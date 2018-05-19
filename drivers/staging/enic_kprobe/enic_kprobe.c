#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/smp.h>
#include <linux/timex.h>
#include <linux/string.h>
#include <linux/cpufreq.h>

static char func_name[NAME_MAX] = "do_IRQ";
module_param_string(func, func_name, NAME_MAX, S_IRUGO);
MODULE_PARM_DESC(func, "Function to kretprobe; this module will report the"
			" function's execution time");

struct enic_do_irq {
	u64 min;
	ktime_t min_time;
	u64 max;
	ktime_t max_time;
	u64 count;
	u64 usec0to19;
	u64 usec20to49;
	u64 usec50to99;
	u64 usec100to499;
	u64 usec500to999;
	u64 msec1to49;
	u64 msec50to499;
	u64 msec500to999;
	u64 sec1;
	u64 sec2;
	u64 sec3;
	u64 sec4;
	u64 sec5;
	u64 sec6;
	u64 sec7plus;
};

struct enic_do_irq __percpu *do_irq_stats;

#define ENIC_KPROBE_NUM 1

static struct kretprobe enic_kprobe[ENIC_KPROBE_NUM];

/* per-instance private data */
struct doirq_data {
	ktime_t entry_stamp;
};

/* Here we use the entry_hanlder to timestamp function entry */
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct doirq_data *data;

	data = (struct doirq_data *)ri->data;
	data->entry_stamp = ktime_get();
	return 0;
}

/*
 * Return-probe handler: Log the return value and duration. Duration may turn
 * out to be zero consistently, depending upon the granularity of time
 * accounting on the platform.
 */
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned long retval = regs_return_value(regs);
	struct doirq_data *data = (struct doirq_data *)ri->data;
	struct enic_do_irq *d = get_cpu_ptr(do_irq_stats);
	s64 delta, delta_msec, delta_usec, delta_sec;
	ktime_t now, ktime_delta;


	now = ktime_get();
	ktime_delta = ktime_sub(now, data->entry_stamp);
	delta = ktime_to_ns(ktime_delta);
	delta_usec = ktime_to_us(ktime_delta);
	delta_msec = ktime_to_ms(ktime_delta);
	delta_sec = delta_msec / 1000;

	if (delta_sec >= 7) {
		d->sec7plus++;
	} else if (delta_sec == 6) {
		d->sec6++;
	} else if (delta_sec == 5) {
		d->sec5++;
	} else if (delta_sec == 4) {
		d->sec4++;
	} else if (delta_sec == 3) {
		d->sec3++;
	} else if (delta_sec == 2) {
		d->sec2++;
	} else if (delta_sec == 1) {
		d->sec1++;
	} else if (delta_msec >= 500) {
		d->msec500to999++;
	} else if (delta_msec >= 50) {
		d->msec50to499++;
	} else if (delta_msec >= 1) {
		d->msec1to49++;
	} else if (delta_usec >= 500) {
		d->usec500to999++;
	} else if (delta_usec >= 100) {
		d->usec100to499++;
	} else if (delta_usec >= 50) {
		d->usec50to99++;
	} else if (delta_usec >= 20) {
		d->usec20to49++;
	} else {
		d->usec0to19++;
	}

	d->count++;

	if (!d->min)
		d->min = delta;
	if (delta < d->min) {
		d->min = delta;
		d->min_time = now;
	}
	if (delta > d->max) {
		d->max = delta;
		d->max_time = now;
	}

//	pr_info("%s returned %lu and took %lld us to execute\n",
//			func_name, retval, (long long)delta_usec);

	put_cpu_ptr(d);
	return 0;
}

static struct kretprobe my_kretprobe = {
	.handler		= ret_handler,
	.entry_handler		= entry_handler,
	.data_size		= sizeof(struct doirq_data),
	/* Probe up to 20 instances concurrently. */
	.maxactive		= 20,
};

static int doirq_show(struct seq_file *m, void *v)
{
	int *cpu = v;
	struct enic_do_irq *d = per_cpu_ptr(do_irq_stats, *cpu);

	if (!*cpu) {
		seq_printf(m, "Now time: %llu\n", ktime_to_ns(ktime_get()));
		seq_printf(m, "%-3s | %-10s | %-10s | %-20s | %-10s | %-20s | %-10s | %-10s | %-10s | %-10s | %-10s | %-10s | %-10s | %-10s | %-10s | %-10s | %-10s | %-10s | %-10s | %-10s | %-10s\n",
			   "cpu",
			   "count",
			   "min(ns)",
			   "min_t(ns)",
			   "max(ns)",
			   "max_t(ns)",
			   "u0-19",
			   "u20-49",
			   "u50-99",
			   "u100-499",
			   "u500-999",
			   "m1-49",
			   "m50-499",
			   "m500-999",
			   "sec1",
			   "sec2",
			   "sec3",
			   "sec4",
			   "sec5",
			   "sec6",
			   "sec7");
	}
	seq_printf(m, "%-3d | %-10llu | %-10llu | %-20llu | %-10llu | %-20llu | %-10llu | %-10llu | %-10llu | %-10llu | %-10llu | %-10llu | %-10llu | %-10llu | %-10llu | %-10llu | %-10llu| %-10llu | %-10llu | %-10llu | %-10llu\n",
			   *cpu,
			   d->count,
			   d->min,
			   ktime_to_ns(d->min_time),
			   d->max,
			   ktime_to_ns(d->max_time),
			   d->usec0to19,
			   d->usec20to49,
			   d->usec50to99,
			   d->usec100to499,
			   d->usec500to999,
			   d->msec1to49,
			   d->msec50to499,
			   d->msec500to999,
			   d->sec1,
			   d->sec2,
			   d->sec3,
			   d->sec4,
			   d->sec5,
			   d->sec6,
			   d->sec7plus);

	return 0;
}

static void *doirq_start(struct seq_file *m, loff_t *pos)
{
	if ((*pos) < nr_cpu_ids)
		return pos;
	return NULL;
}

static void *doirq_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	return doirq_start(m, pos);
}

static void doirq_stop(struct seq_file *m, void *v)
{
}

const struct seq_operations doirq_op = {
	.start	= doirq_start,
	.next	= doirq_next,
	.stop	= doirq_stop,
	.show	= doirq_show,
};

static int doirq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &doirq_op);
}

static const struct file_operations proc_enic_doirq_operations = {
	.open		= doirq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init enic_kprobe_init(void)
{
	int ret = 0;

	do_irq_stats = alloc_percpu(struct enic_do_irq);
	if (!do_irq_stats)
		return -ENOMEM;

	my_kretprobe.kp.symbol_name = func_name;
	ret = register_kretprobe(&my_kretprobe);
	if (ret < 0) {
		pr_err("register_kretprobe failed, returned %d\n", ret);
		goto free_do_irq_stats;
	}
	pr_info("Planted return probe at %s: %p\n",
			my_kretprobe.kp.symbol_name, my_kretprobe.kp.addr);

	proc_create("enic_doirq", 0, NULL, &proc_enic_doirq_operations);
	return 0;

free_do_irq_stats:
	free_percpu(do_irq_stats);

	return ret;
}

static void __exit enic_kprobe_exit(void)
{
	remove_proc_entry("enic_doirq", NULL);
	unregister_kretprobe(&my_kretprobe);
	pr_info("kretprobe at %p unregistered\n", my_kretprobe.kp.addr);

	/* nmissed > 0 suggests that maxactive was set too low. */
	pr_info("Missed probing %d instances of %s\n",
		my_kretprobe.nmissed, my_kretprobe.kp.symbol_name);
}

module_init(enic_kprobe_init)
module_exit(enic_kprobe_exit)
MODULE_LICENSE("GPL");
