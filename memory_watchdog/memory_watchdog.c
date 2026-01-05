#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/hashtable.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ChatGPT");
MODULE_DESCRIPTION("Kernel module to monitor memory growth of user processes");

// 可配置参数
static int check_interval = 120;  // 默认120秒
module_param(check_interval, int, 0644);
MODULE_PARM_DESC(check_interval, "Check interval in seconds (default: 120)");

static int growth_threshold = 10240; // 默认10MB in KB
module_param(growth_threshold, int, 0644);
MODULE_PARM_DESC(growth_threshold, "Memory growth threshold in KB (default: 10240)");

static int monitor_pid = -1;
module_param(monitor_pid, int, 0644);
MODULE_PARM_DESC(monitor_pid, "If set, only monitor this PID (default: -1 for all)");

static char *whitelist = "bash,systemd,sshd,kthreadd";
module_param(whitelist, charp, 0644);
MODULE_PARM_DESC(whitelist, "Comma-separated list of processes to ignore (default: bash,systemd,sshd,kthreadd)");

// 白名单相关
#define MAX_WHITELIST_ENTRIES 32
#define MAX_COMM_LEN 16
static char whitelist_entries[MAX_WHITELIST_ENTRIES][MAX_COMM_LEN];
static int whitelist_count = 0;

static struct task_struct *watchdog_thread;
static struct proc_dir_entry *proc_entry;

// 统计信息
static atomic_t total_monitored = ATOMIC_INIT(0);
static atomic_t total_alerts = ATOMIC_INIT(0);
static atomic_t current_processes = ATOMIC_INIT(0);

struct proc_mem_info {
    pid_t pid;
    unsigned long last_rss_kb;
    int growth_count;
    char comm[TASK_COMM_LEN];  // 保存进程名
    unsigned long first_seen;  // 首次发现时间
    unsigned long last_check;  // 最后检查时间
    unsigned long max_rss_kb;  // 历史最大RSS
    int alert_count;           // 告警次数
    struct hlist_node hnode;
};

DEFINE_HASHTABLE(proc_table, 8); // 256 buckets

// proc文件系统接口
static int memwatch_proc_show(struct seq_file *m, void *v)
{
    struct proc_mem_info *info;
    int bkt;
    int count = 0;

    seq_printf(m, "Memory Watchdog Status\n");
    seq_printf(m, "======================\n");
    seq_printf(m, "Check Interval: %d seconds\n", check_interval);
    seq_printf(m, "Growth Threshold: %d KB\n", growth_threshold);
    seq_printf(m, "Monitor PID: %d\n", monitor_pid);
    seq_printf(m, "Whitelist: %s\n", whitelist ? whitelist : "none");
    seq_printf(m, "Total Monitored: %d\n", atomic_read(&total_monitored));
    seq_printf(m, "Total Alerts: %d\n", atomic_read(&total_alerts));
    seq_printf(m, "Current Processes: %d\n", atomic_read(&current_processes));
    seq_printf(m, "\nCurrently Monitored Processes:\n");
    seq_printf(m, "%-6s %-16s %-10s %-10s %-10s %-6s %-12s\n", 
               "PID", "COMM", "RSS(KB)", "MAX(KB)", "GROWTH", "ALERTS", "UPTIME(s)");
    seq_printf(m, "%-6s %-16s %-10s %-10s %-10s %-6s %-12s\n", 
               "------", "----------------", "----------", "----------", "----------", "------", "------------");

    hash_for_each(proc_table, bkt, info, hnode) {
        unsigned long uptime = (jiffies - info->first_seen) / HZ;
        seq_printf(m, "%-6d %-16s %-10lu %-10lu %-10d %-6d %-12lu\n",
                   info->pid, info->comm, info->last_rss_kb, info->max_rss_kb,
                   info->growth_count, info->alert_count, uptime);
        count++;
    }

    seq_printf(m, "\nTotal entries: %d\n", count);
    return 0;
}

static int memwatch_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, memwatch_proc_show, NULL);
}

static const struct file_operations memwatch_proc_fops = {
    .owner = THIS_MODULE,
    .open = memwatch_proc_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

// 解析白名单字符串
static void parse_whitelist(void)
{
    char *token, *string, *tofree;
    
    whitelist_count = 0;
    if (!whitelist || strlen(whitelist) == 0)
        return;
    
    tofree = string = kstrdup(whitelist, GFP_KERNEL);
    if (!string) {
        printk(KERN_ERR "memory_watchdog: failed to allocate memory for whitelist parsing\n");
        return;
    }
    
    while ((token = strsep(&string, ",")) != NULL && whitelist_count < MAX_WHITELIST_ENTRIES) {
        // 移除前后空格
        while (*token == ' ') token++;
        if (strlen(token) > 0 && strlen(token) < MAX_COMM_LEN) {
            strncpy(whitelist_entries[whitelist_count], token, MAX_COMM_LEN - 1);
            whitelist_entries[whitelist_count][MAX_COMM_LEN - 1] = '\0';
            whitelist_count++;
        }
    }
    
    kfree(tofree);
    
    printk(KERN_INFO "memory_watchdog: loaded %d whitelist entries\n", whitelist_count);
}

// 检查进程是否在白名单中
static bool is_whitelisted(const char *comm)
{
    int i;
    for (i = 0; i < whitelist_count; i++) {
        if (strcmp(comm, whitelist_entries[i]) == 0) {
            return true;
        }
    }
    return false;
}

// 清理已退出的进程条目
static void cleanup_dead_processes(void)
{
    struct proc_mem_info *info;
    struct hlist_node *tmp;
    struct task_struct *task;
    int bkt;
    bool found;
    int cleaned_count = 0;

    hash_for_each_safe(proc_table, bkt, tmp, info, hnode) {
        found = false;
        
        // 检查PID是否仍然存在
        rcu_read_lock();
        for_each_process(task) {
            if (task->pid == info->pid) {
                found = true;
                break;
            }
        }
        rcu_read_unlock();
        
        if (!found) {
            printk(KERN_INFO "memory_watchdog: [CLEANUP] Process '%s' (PID: %d) exited, alerts: %d\n", 
                   info->comm, info->pid, info->alert_count);
            hash_del(&info->hnode);
            kfree(info);
            cleaned_count++;
            atomic_dec(&current_processes);
        }
    }
    
    if (cleaned_count > 0) {
        printk(KERN_INFO "memory_watchdog: cleaned up %d dead process entries\n", cleaned_count);
    }
}

static int monitor_fn(void *data)
{
    struct task_struct *task;
    struct proc_mem_info *info;
    unsigned long rss_kb;
    unsigned long check_interval_jiffies;
    struct audit_buffer *ab = NULL;
    bool found;

    printk(KERN_INFO "memory_watchdog: monitoring started with interval=%ds, threshold=%dKB\n", 
           check_interval, growth_threshold);

    while (!kthread_should_stop()) {
        // 定期清理已退出的进程
        cleanup_dead_processes();

        rcu_read_lock();
        for_each_process(task) {
            if (!task->mm)
                continue;

            // 如果指定了monitor_pid，只监控该PID
            if (monitor_pid > 0 && task->pid != monitor_pid)
                continue;

            // 检查是否在白名单中
            if (is_whitelisted(task->comm))
                continue;

            rss_kb = get_mm_rss(task->mm) * (PAGE_SIZE / 1024);

            // 搜索现有条目
            found = false;
            hash_for_each_possible(proc_table, info, hnode, task->pid) {
                if (info->pid == task->pid) {
                    found = true;
                    
                    // 更新进程名（以防进程名发生变化）
                    strncpy(info->comm, task->comm, TASK_COMM_LEN);
                    info->comm[TASK_COMM_LEN - 1] = '\0';
                    info->last_check = jiffies;
                    
                    // 更新最大RSS记录
                    if (rss_kb > info->max_rss_kb) {
                        info->max_rss_kb = rss_kb;
                    }
                    
                    if (rss_kb > info->last_rss_kb + growth_threshold) {
                        info->growth_count++;
                        if (info->growth_count >= 2) {
                            unsigned long growth_kb = rss_kb - info->last_rss_kb;
                            info->alert_count++;
                            atomic_inc(&total_alerts);
                            
                            printk(KERN_WARNING "memory_watchdog: [ALERT #%d] Process '%s' (PID: %d, PPID: %d) memory growing rapidly!\n",
                                   info->alert_count, task->comm, task->pid, 
                                   task->real_parent ? task->real_parent->pid : 0);
                            printk(KERN_WARNING "  Current RSS: %lu KB, Previous RSS: %lu KB, Growth: +%lu KB, Max RSS: %lu KB\n",
                                   rss_kb, info->last_rss_kb, growth_kb, info->max_rss_kb);
                            printk(KERN_WARNING "  Process uptime: %lu seconds\n", 
                                   (jiffies - info->first_seen) / HZ);
                            
                            // 审计日志 - 包含更详细信息
                            ab = audit_log_start(NULL, GFP_ATOMIC, AUDIT_USER);
                            if (ab) {
                                audit_log_format(ab, "memory_watchdog: [ALERT #%d] process '%s' (PID:%d PPID:%d) memory growth: %lu->%lu KB (+%lu KB) max:%lu KB",
                                       info->alert_count, task->comm, task->pid, 
                                       task->real_parent ? task->real_parent->pid : 0,
                                       info->last_rss_kb, rss_kb, growth_kb, info->max_rss_kb);
                                audit_log_end(ab);
                            }
                            
                            info->growth_count = 0; // 重置计数
                        }
                    } else {
                        info->growth_count = 0; // 重置计数
                    }
                    info->last_rss_kb = rss_kb;
                    break;
                }
            }

            if (!found) {
                // 新PID，添加到哈希表
                info = kmalloc(sizeof(*info), GFP_ATOMIC);
                if (!info)
                    continue;
                info->pid = task->pid;
                info->last_rss_kb = rss_kb;
                info->max_rss_kb = rss_kb;
                info->growth_count = 0;
                info->alert_count = 0;
                info->first_seen = jiffies;
                info->last_check = jiffies;
                
                // 保存进程名
                strncpy(info->comm, task->comm, TASK_COMM_LEN);
                info->comm[TASK_COMM_LEN - 1] = '\0';
                
                hash_add(proc_table, &info->hnode, task->pid);
                atomic_inc(&total_monitored);
                atomic_inc(&current_processes);
                
                printk(KERN_INFO "memory_watchdog: [NEW] Started monitoring process '%s' (PID: %d, PPID: %d) with initial RSS: %lu KB\n",
                       info->comm, info->pid, 
                       task->real_parent ? task->real_parent->pid : 0, rss_kb);
            }
        }
        rcu_read_unlock();

        // 使用参数化的检查间隔
        check_interval_jiffies = check_interval * HZ;
        schedule_timeout_interruptible(check_interval_jiffies);
    }
    
    return 0;
}

static int __init memory_watchdog_init(void)
{
    // 参数验证
    if (check_interval <= 0) {
        printk(KERN_ERR "memory_watchdog: invalid check_interval %d, using default 120\n", check_interval);
        check_interval = 120;
    }
    
    if (growth_threshold <= 0) {
        printk(KERN_ERR "memory_watchdog: invalid growth_threshold %d, using default 10240\n", growth_threshold);
        growth_threshold = 10240;
    }

    printk(KERN_INFO "memory_watchdog: module loaded with parameters:\n");
    printk(KERN_INFO "  check_interval: %d seconds\n", check_interval);
    printk(KERN_INFO "  growth_threshold: %d KB\n", growth_threshold);
    printk(KERN_INFO "  monitor_pid: %d\n", monitor_pid);
    printk(KERN_INFO "  whitelist: %s\n", whitelist ? whitelist : "none");

    hash_init(proc_table);
    
    // 解析白名单
    parse_whitelist();

    // 创建proc文件系统接口
    proc_entry = proc_create("memory_watchdog", 0444, NULL, &memwatch_proc_fops);
    if (!proc_entry) {
        printk(KERN_ERR "memory_watchdog: failed to create /proc/memory_watchdog\n");
        return -ENOMEM;
    }

    watchdog_thread = kthread_run(monitor_fn, NULL, "mem_watchdog");
    if (IS_ERR(watchdog_thread)) {
        printk(KERN_ERR "memory_watchdog: failed to create thread\n");
        proc_remove(proc_entry);
        return PTR_ERR(watchdog_thread);
    }

    printk(KERN_INFO "memory_watchdog: monitoring started successfully\n");
    printk(KERN_INFO "memory_watchdog: view status with 'cat /proc/memory_watchdog'\n");

    return 0;
}

static void __exit memory_watchdog_exit(void)
{
    struct proc_mem_info *info;
    struct hlist_node *tmp;
    int bkt;
    int total_entries = 0;
    int total_alerts_count = 0;

    if (watchdog_thread)
        kthread_stop(watchdog_thread);

    // 移除proc文件系统接口
    if (proc_entry)
        proc_remove(proc_entry);

    // 释放哈希表条目并显示统计信息
    hash_for_each_safe(proc_table, bkt, tmp, info, hnode) {
        printk(KERN_DEBUG "memory_watchdog: [FINAL] Process '%s' (PID: %d) - Alerts: %d, Max RSS: %lu KB, Uptime: %lu seconds\n", 
               info->comm, info->pid, info->alert_count, info->max_rss_kb,
               (jiffies - info->first_seen) / HZ);
        total_alerts_count += info->alert_count;
        hash_del(&info->hnode);
        kfree(info);
        total_entries++;
    }

    printk(KERN_INFO "memory_watchdog: module unloaded\n");
    printk(KERN_INFO "  Final statistics:\n");
    printk(KERN_INFO "  - Total processes monitored: %d\n", atomic_read(&total_monitored));
    printk(KERN_INFO "  - Total alerts generated: %d\n", atomic_read(&total_alerts));
    printk(KERN_INFO "  - Process entries cleaned up: %d\n", total_entries);
}

module_init(memory_watchdog_init);
module_exit(memory_watchdog_exit);
