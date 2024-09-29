#include <linux/tskinfo.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/pid.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/memory.h>
#include <linux/rcupdate.h>
#include <linux/x86_dependent.h>
#include <linux/sched.h>
#include <linux/sched/task.h>

void get_tskinfo_with_task_struct(struct task_struct*, struct tskinfo *, int);
void get_tskinfo_with_task_struct(struct task_struct *task_st, struct tskinfo * tskinfo_buf, int level_value){
	// printk(KERN_INFO "Access for task_st %p is %d", task_st, access_ok(task_st, sizeof(struct task_struct)));
	
	// pid and tgid
	tskinfo_buf->pid = task_st->pid;
    tskinfo_buf->tgid = task_st->tgid;

	// parent_pid
	pid_t task_parent_pid = task_st->real_parent->pid;
	tskinfo_buf->parent_pid = task_parent_pid;

	// level, get from michael
	tskinfo_buf->level = level_value;	

	// comm[16], name of program executed
	strscpy(tskinfo_buf->comm, task_st->comm, 16);

	// userpc, pc/ip when task returns to user mode
	struct pt_regs *regs = task_pt_regs(task_st);
	tskinfo_buf->userpc = regs->ip;

	// pc/ip when task is run by schedule()
	unsigned long kernelpc_value = get_kernelpc(task_st);
	tskinfo_buf->kernelpc = kernelpc_value;
}

SYSCALL_DEFINE3(ptree, struct tskinfo __user *, buf, int * __user, nr, int, root_pid) {
	// from https://tuxthink.blogspot.com/2012/07/module-to-find-task-from-its-pid.html
	if (buf == NULL || nr == NULL) return -EINVAL;
	if (!access_ok((void *) nr, sizeof(int))) return -EFAULT;
	pid_t pid_0 = root_pid;
	int nr_tmp = 0;
	if (copy_from_user(&nr_tmp, nr, sizeof(nr_tmp))) return -EFAULT;
	if (nr <= 0) {
		return -EINVAL;
	}
	if (!access_ok((void *) buf, sizeof( struct tskinfo ) * nr_tmp) ) return -EFAULT;
	//printk(KERN_INFO "Current nr is %d\n", nr_tmp);
	struct task_struct **queue = kmalloc(nr_tmp * sizeof(struct task_struct *), GFP_KERNEL);
	struct tskinfo **out_arr = kmalloc(nr_tmp * sizeof(struct tskinfo), GFP_KERNEL);
	for(int k = 0; k < nr_tmp; k++){
		out_arr[k] = kmalloc(sizeof(struct tskinfo), GFP_KERNEL);
	}
	int *queue_skip = kmalloc(nr_tmp * sizeof(int), GFP_KERNEL);
	for (int i = 0; i < nr_tmp; i++) {
		queue[i] = NULL;
	}
	int *prc_height = kmalloc(nr_tmp * sizeof(int), GFP_KERNEL);
	int cur_loc = 0;
	int queue_back = 0;
	int queue_skip_ctr = 0;
	int queue_skip_ctr_back = 0;
	prc_height[0] = 0;
	struct task_struct *task_st = NULL;
	rcu_read_lock();
	if (pid_0 == 0) {
		task_st = &init_task;
	} else {
		struct pid *pid_st = find_get_pid(pid_0);
		if (pid_st == NULL) {
			return -EINVAL;
		}

		task_st = pid_task(pid_st, PIDTYPE_PID);
		task_st = task_st -> group_leader;
		// from https://chengyihe.wordpress.com/2015/12/29/kernel-thread-and-thread-group/

	}
	queue[cur_loc] = task_st;
	cur_loc += 1;
	int n_thread = 0;
	struct task_struct *thd = NULL;
	for_each_thread(task_st, thd){
		if (n_thread >= 1 && cur_loc < nr_tmp) {
			queue[cur_loc] = thd;
			prc_height[cur_loc] = prc_height[queue_back];
			cur_loc += 1;
		}
		n_thread += 1;
	}
	queue_skip[queue_skip_ctr] = n_thread;
	queue_skip_ctr += 1;
	struct list_head *l = NULL;
	struct task_struct *st_2 = NULL;
	int block_lp = 0;
	
	while (!block_lp) {
		list_for_each(l, &task_st -> children) {
			if (cur_loc < nr_tmp) {
				printk(KERN_INFO "Iterating for %d at height %d", cur_loc, prc_height[queue_back] + 1);
				st_2 = list_entry(l, struct task_struct, sibling);
				queue[cur_loc] = st_2;
				prc_height[cur_loc] = prc_height[queue_back] + 1;
				cur_loc += 1;
				n_thread = 0;
				for_each_thread(st_2, thd){
					int stat_thd = access_ok((void *) thd, sizeof(struct task_struct));
					if (n_thread >= 1 && cur_loc < nr_tmp && !stat_thd) {
						printk(KERN_INFO "found thread %p at %d with height %d\n", thd, cur_loc, prc_height[queue_back] + 1);
						queue[cur_loc] = thd;
						prc_height[cur_loc] = prc_height[queue_back] + 1;
						cur_loc += 1;
					} else if (cur_loc >= nr_tmp) {
						block_lp = 1;
					} else if (stat_thd) {
						n_thread -= 1;
					}
					n_thread += 1;
				}
				queue_skip[queue_skip_ctr] = n_thread;
				queue_skip_ctr += 1;
			} else {
				block_lp = 1;
			}
		}
		// printk(KERN_INFO "Skipping %d threads from location %d", queue_skip[queue_skip_ctr_back], queue_back - queue_skip[queue_skip_ctr_back]);
		queue_back += queue_skip[queue_skip_ctr_back];
		queue_skip_ctr_back += 1;
		if (queue_back == cur_loc) break;
		task_st = queue[queue_back];
		l = NULL;
		thd = NULL;
	}
	for (int i = 0; i < cur_loc; i++) {
		// get_tskinfo_with_task_struct(queue[i], out_arr[i], prc_height[i]);
		// pid and tgid
		out_arr[i]->pid = queue[i]->pid;
		out_arr[i]->tgid = queue[i]->tgid;

		// parent_pid
		pid_t task_parent_pid = queue[i]->real_parent->pid;
		out_arr[i]->parent_pid = task_parent_pid;

		// level, get from michael
		out_arr[i]->level = prc_height[i];	

		// comm[16], name of program executed
		strscpy(out_arr[i]->comm, queue[i]->comm, 16);

		// userpc, pc/ip when task returns to user mode
		struct pt_regs *regs = task_pt_regs(queue[i]);
		out_arr[i]->userpc = regs->ip;

		// pc/ip when task is run by schedule()
		unsigned long kernelpc_value = get_kernelpc(queue[i]);
		out_arr[i]->kernelpc = kernelpc_value;
	}
	rcu_read_unlock();
        int stat = copy_to_user(nr, &cur_loc, sizeof(int));
        if (stat) return -EFAULT;
	for (int j = 0; j < cur_loc; j++) {
		int stat_2 = copy_to_user(buf + j, out_arr[j], sizeof(struct tskinfo));
		if (stat_2) return -EFAULT;
	}
	for (int l = 0; l < nr_tmp; l++){
		kfree( (void *) out_arr[l]);
	}
	kfree((void *) out_arr);
	kfree((void *) prc_height);
	kfree((void *) queue);
	kfree((void *) queue_skip);
	printk(KERN_INFO "Ending PTREE\n");
	return 0;
}
