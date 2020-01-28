#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <net/sock.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_fpath.h>

int nfacc_enable = 0;
int nfacc_debug = 0;


static unsigned int pre_routing_hook(void *priv,
			struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	if (nfacc_enable && ip_hdr(skb)->protocol == IPPROTO_ICMP) {
		enum ip_conntrack_info ctinfo;
		struct nf_conn *ct;
		struct nf_conn_fpath * fpath;
		printk(KERN_INFO "pre_routing_hook: %p:%d\n", skb, icmp_hdr(skb)->type);
		if (skb->dev)
			printk(KERN_INFO "   [dev:%s]\n", skb->dev->name);

		ct = nf_ct_get(skb, &ctinfo);
		if (ct) {
			test_bit(IPS_CONFIRMED_BIT, &ct->status);
			printk(KERN_INFO "   c->status=%ld\n", ct->status);
			fpath = nf_conn_fpath_find(ct);
		} else {
			return NF_ACCEPT;
		}

		if (!fpath) {
			if (!nf_ct_is_confirmed(ct)) {
				fpath = nf_ct_fpath_ext_add(ct);
				printk(KERN_INFO "   adding ct ext\n");
			}

			if (fpath)
				fpath->todo = 0;
			else
				printk(KERN_INFO "cannot add fpath extension :(\n");
		} else {
			printk(KERN_INFO "   [%p] fpath->todo = %d", fpath, fpath->todo);
			fpath->todo++;
		}
	}

	return NF_ACCEPT;
}

static unsigned int post_routing_hook(void *priv,
			struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	if (nfacc_enable && ip_hdr(skb)->protocol == IPPROTO_ICMP) {
		enum ip_conntrack_info ctinfo;
		struct nf_conn *ct;
		struct nf_conn_fpath * fpath;
		printk(KERN_INFO "post_routing_hook: %p:%p:%d\n", skb, skb->sk, icmp_hdr(skb)->type);
		if (skb->dev)
			printk(KERN_INFO "   [dev:%s]\n", skb->dev->name);

		ct = nf_ct_get(skb, &ctinfo);
		if (ct) {
			test_bit(IPS_CONFIRMED_BIT, &ct->status);
			printk(KERN_INFO "   c->status=%ld\n", ct->status);
			fpath = nf_conn_fpath_find(ct);
		} else {
			return NF_ACCEPT;
		}

		if (fpath) {
			printk(KERN_INFO "   [%p] fpath->todo = %d", fpath, fpath->todo);
		}
	}
	return NF_ACCEPT;
}

static unsigned int local_out_hook(void *priv,
			struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	if (ip_hdr(skb)->protocol == IPPROTO_ICMP)
		printk(KERN_INFO "local_out_hook: %p:%p:%d\n", skb, skb->sk, icmp_hdr(skb)->type);
	else
		printk(KERN_INFO "local_out_hook -not icmp-: %p:%d\n", skb, ip_hdr(skb)->protocol);
	return NF_ACCEPT;
}

static unsigned int local_in_hook(void *priv,
			struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	if (ip_hdr(skb)->protocol == IPPROTO_ICMP) {
		enum ip_conntrack_info ctinfo;
		struct nf_conn *c;
		printk(KERN_INFO "local_in_hook: %p:%d\n", skb, icmp_hdr(skb)->type);
		c = nf_ct_get(skb, &ctinfo);
		if (c)
			printk(KERN_INFO "   c->status=%ld\n", c->status);
	}
	return NF_ACCEPT;
}


static const struct nf_hook_ops nfacc_ops[] = {
	{
		.hook		= pre_routing_hook,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK + 1,
	},
	{
		.hook		= post_routing_hook,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP_PRI_LAST,
	},
	{
		.hook		= local_out_hook,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP_PRI_FIRST,
	},
	{
		.hook		= local_in_hook,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_LAST,
	},
};


static ssize_t nfacc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos)
{
	int num, c, enable;
	char buf[10];

	if(*ppos > 0 || count > 10)
		return -EFAULT;
	if(copy_from_user(buf, ubuf, count))
		return -EFAULT;

	num = sscanf(buf, "%d", &enable);
	if(num != 1)
		return -EFAULT;

	nfacc_enable = enable;

	c = strlen(buf);
	*ppos = c;

	return c;
}

static ssize_t nfacc_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos)
{
	char buf[50];
	int len=0;

	if(*ppos > 0 || count < 50)
		return 0;

	len += sprintf(buf, "nfacc_enable = %d\n", nfacc_enable);

	if(copy_to_user(ubuf, buf, len))
		return -EFAULT;
	*ppos = len;

	return len;
}

struct proc_dir_entry *proc_nfacc_enable;
static const struct file_operations proc_nfacc_enable_fops = {
 .owner = THIS_MODULE,
 .write = nfacc_write,
 .read  = nfacc_read,
};


static ssize_t nfacc_debug_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos)
{
	int num, c, debug;
	char buf[10];

	if(*ppos > 0 || count > 10)
		return -EFAULT;
	if(copy_from_user(buf, ubuf, count))
		return -EFAULT;

	num = sscanf(buf, "%d", &debug);
	if(num != 1)
		return -EFAULT;

	nfacc_debug = debug;

	c = strlen(buf);
	*ppos = c;

	return c;
}

static ssize_t nfacc_debug_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos)
{
	char buf[50];
	int len=0;

	if(*ppos > 0 || count < 50)
		return 0;

	len += sprintf(buf, "nfacc_debug = %d\n", nfacc_debug);

	if(copy_to_user(ubuf, buf, len))
		return -EFAULT;
	*ppos = len;

	return len;
}

struct proc_dir_entry *proc_nfacc_debug;
static const struct file_operations proc_nfacc_debug_fops = {
 .owner = THIS_MODULE,
 .write = nfacc_debug_write,
 .read  = nfacc_debug_read,
};


static int __init nfacc_init(void)
{
	int err;

	proc_nfacc_enable = proc_create("nfacc_enable", 0, NULL, &proc_nfacc_enable_fops);
	if(proc_nfacc_enable == NULL)
		return -ENOMEM;

	proc_nfacc_debug = proc_create("nfacc_debug", 0, NULL, &proc_nfacc_debug_fops);
	if(proc_nfacc_debug == NULL)
		return -ENOMEM;

	err = nf_register_net_hooks(&init_net, nfacc_ops,
				    ARRAY_SIZE(nfacc_ops));

	if (!err)
		printk("nfacc insmoded");
	else
		printk("nf_register_net_hook: error");
	return err;
}

static void __exit nfacc_fini(void)
{
	proc_remove(proc_nfacc_enable);
	proc_remove(proc_nfacc_debug);

	nf_unregister_net_hooks(&init_net, nfacc_ops,
				ARRAY_SIZE(nfacc_ops));
	printk("nfacc rmmoded");
}


MODULE_DESCRIPTION("Netfilter based packet accelerator");
MODULE_AUTHOR("Mikolaj Kowalik <kowalikmikolaj95@gmail.com>");
MODULE_LICENSE("GPL");

module_init(nfacc_init);
module_exit(nfacc_fini);
