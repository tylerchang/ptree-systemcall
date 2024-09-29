
#include <asm/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <asm/ptrace.h>
#include <asm/switch_to.h>

unsigned long get_kernelpc(struct task_struct*);

unsigned long get_kernelpc(struct task_struct *task){
	printk(KERN_INFO "Hello we are in arch dependent get_kernelpc() function");
	struct thread_struct thread_struct_of_task = task->thread;
	struct inactive_task_frame* frame = (struct inactive_task_frame*)(thread_struct_of_task.sp);
	unsigned long kernelpc = frame->ret_addr;

   	return kernelpc;


}