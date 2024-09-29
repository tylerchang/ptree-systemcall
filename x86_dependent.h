#ifndef _LINUX_PTREE_H
#define _LINUX_PTREE_H
#include <linux/sched.h>

unsigned long get_kernelpc(struct task_struct *task);

#endif /* _LINUX_PTREE_H */