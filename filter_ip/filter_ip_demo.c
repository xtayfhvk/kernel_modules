#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/ratelimit.h>
#include <linux/percpu.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/inet.h>




MODULE_LICENSE("GPL");
MODULE_AUTHOR("demo");
MODULE_DESCRIPTION("Advanced netfilter demo for CentOS 7 (3.10)");
MODULE_VERSION("2.0");

/* ===== 参数（默认） ===== */
static int d = 0;                  /* 0:统计 1:DROP */
static char t[4] = "tcp";          /* tcp / udp */
static char l[4] = "all";          /* in / out / all */
static __be32 filter_ip = 0;       /* 0.0.0.0 = all */
static struct kobject *filter_kobj;


module_param(d, int, 0644);

/* ===== per-cpu 统计 ===== */
DEFINE_PER_CPU(unsigned long, pkt_cnt);
DEFINE_PER_CPU(unsigned long, syn_cnt);
DEFINE_PER_CPU(unsigned long, retrans_cnt);

/* ===== printk 限频 ===== */
static DEFINE_RATELIMIT_STATE(rs, 5 * HZ, 10);


/* ===== d ===== */
static ssize_t d_show(struct kobject *kobj,
                      struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", d);
}

static ssize_t d_store(struct kobject *kobj,
                       struct kobj_attribute *attr,
                       const char *buf, size_t count)
{
    sscanf(buf, "%d", &d);
    return count;
}

static struct kobj_attribute d_attr =
    __ATTR(d, 0664, d_show, d_store);
	
/* ===== t   ===== */	
static ssize_t t_show(struct kobject *kobj,
                      struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%s\n", t);
}

static ssize_t t_store(struct kobject *kobj,
                       struct kobj_attribute *attr,
                       const char *buf, size_t count)
{
    sscanf(buf, "%3s", t);
    return count;
}

static struct kobj_attribute t_attr =
    __ATTR(t, 0664, t_show, t_store);
	
	
/* =====  l  ===== */	
static ssize_t l_show(struct kobject *kobj,
                      struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%s\n", l);
}

static ssize_t l_store(struct kobject *kobj,
                       struct kobj_attribute *attr,
                       const char *buf, size_t count)
{
    sscanf(buf, "%3s", l);
    return count;
}

static struct kobj_attribute l_attr =
    __ATTR(l, 0664, l_show, l_store);
	
	
	
/* =====  ip  ===== */
static ssize_t ip_show(struct kobject *kobj,
                       struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%pI4\n", &filter_ip);
}

static ssize_t ip_store(struct kobject *kobj,
                        struct kobj_attribute *attr,
                        const char *buf, size_t count)
{
    filter_ip = in_aton(buf);
    return count;
}

static struct kobj_attribute ip_attr =
    __ATTR(ip, 0664, ip_show, ip_store);	
	

/* =====  stat  ===== */
static ssize_t stats_show(struct kobject *kobj,
                          struct kobj_attribute *attr, char *buf)
{
    int cpu;
    unsigned long total = 0, syn = 0, retrans = 0;

    for_each_possible_cpu(cpu) {
        total   += per_cpu(pkt_cnt, cpu);
        syn     += per_cpu(syn_cnt, cpu);
        retrans += per_cpu(retrans_cnt, cpu);
    }

    return sprintf(buf,
        "total=%lu syn=%lu retrans=%lu\n",
        total, syn, retrans);
}

static struct kobj_attribute stats_attr =
    __ATTR(stats, 0444, stats_show, NULL);

	
	
/* ===== hook 函数 ===== */
static unsigned int hook_func(unsigned int hooknum,
                              struct sk_buff *skb,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    /* IP 过滤（源 IP） */
    if (filter_ip && iph->saddr != filter_ip)
        return NF_ACCEPT;

    /* 协议过滤 */
    if (!strcmp(t, "tcp") && iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    if (!strcmp(t, "udp") && iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    /* TCP 统计 */
    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        if (tcph->syn && !tcph->ack)
            this_cpu_inc(syn_cnt);
    }

    /* DROP 模式 */
    if (d == 1) {
        if (__ratelimit(&rs))
            printk(KERN_INFO "filter_demo DROP %pI4\n", &iph->saddr);
        return NF_DROP;
    }

    /* 统计模式 */
    this_cpu_inc(pkt_cnt);

    if (__ratelimit(&rs))
        printk(KERN_INFO "filter_demo STAT %pI4\n", &iph->saddr);

    return NF_ACCEPT;
}

/* ===== hook 定义 ===== */
static struct nf_hook_ops nfho_in = {
    .hook     = hook_func,
    .pf       = PF_INET,
    .hooknum  = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops nfho_out = {
    .hook     = hook_func,
    .pf       = PF_INET,
    .hooknum  = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST,
};

/* ===== proc 接口 ===== */
#define PROC_NAME "filter_demo"
static char proc_buf[128];

static ssize_t proc_read(struct file *file, char __user *buf,
                         size_t count, loff_t *ppos)
{
    int len;

    if (*ppos > 0)
        return 0;

    len = snprintf(proc_buf, sizeof(proc_buf),
                   "d=%d t=%s l=%s ip=%pI4\n",
                   d, t, l, &filter_ip);

    if (copy_to_user(buf, proc_buf, len))
        return -EFAULT;

    *ppos = len;
    return len;
}

static ssize_t proc_write(struct file *file, const char __user *buf,
                          size_t count, loff_t *ppos)
{
    char kbuf[64];

    if (count >= sizeof(kbuf))
        return -EINVAL;

    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;

    kbuf[count] = '\0';

    if (sscanf(kbuf, "d=%d", &d) == 1)
        return count;

    if (sscanf(kbuf, "t=%3s", t) == 1)
        return count;

    if (sscanf(kbuf, "l=%3s", l) == 1)
        return count;

    if (!strncmp(kbuf, "ip=", 3))
        filter_ip = in_aton(kbuf + 3);

    return count;
}

static const struct file_operations proc_fops = {
    .owner  = THIS_MODULE,
    .read   = proc_read,
    .write  = proc_write,
};

/* ===== init / exit ===== */
static int __init demo_init(void)
{


    filter_kobj = kobject_create_and_add("filter_demo", kernel_kobj);
    if (!filter_kobj)
        return -ENOMEM;

    sysfs_create_file(filter_kobj, &d_attr.attr);
    sysfs_create_file(filter_kobj, &t_attr.attr);
    sysfs_create_file(filter_kobj, &l_attr.attr);
    sysfs_create_file(filter_kobj, &ip_attr.attr);
    sysfs_create_file(filter_kobj, &stats_attr.attr);
	
	
	
    proc_create(PROC_NAME, 0666, NULL, &proc_fops);

    if (!strcmp(l, "in") || !strcmp(l, "all"))
        nf_register_hook(&nfho_in);

    if (!strcmp(l, "out") || !strcmp(l, "all"))
        nf_register_hook(&nfho_out);

    printk(KERN_INFO "filter_demo loaded\n");
    return 0;
}

static void __exit demo_exit(void)
{
    int cpu;
    unsigned long total = 0, syn = 0, retrans = 0;
	
	kobject_put(filter_kobj);
	
	
    if (!strcmp(l, "in") || !strcmp(l, "all"))
        nf_unregister_hook(&nfho_in);

    if (!strcmp(l, "out") || !strcmp(l, "all"))
        nf_unregister_hook(&nfho_out);

    remove_proc_entry(PROC_NAME, NULL);

    for_each_possible_cpu(cpu) {
        total   += per_cpu(pkt_cnt, cpu);
        syn     += per_cpu(syn_cnt, cpu);
        retrans += per_cpu(retrans_cnt, cpu);
    }

    printk(KERN_INFO
           "filter_demo unload: total=%lu syn=%lu retrans=%lu\n",
           total, syn, retrans);
}

module_init(demo_init);
module_exit(demo_exit);
