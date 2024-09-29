#include <linux/types.h>

struct tskinfo {
    pid_t pid;              /* process id */
    pid_t tgid;             /* thread group id */
    pid_t parent_pid;       /* process id of parent */
    int level;              /* level of this process in the subtree */
    char comm[16];          /* name of program executed */
    unsigned long userpc;   /* pc/ip when task returns to user mode */
    unsigned long kernelpc; /* pc/ip when task is run by schedule() */
};

