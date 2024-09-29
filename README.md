# Process Tree Custom System Call Implementation for x86 Linux

This is a custom implementation of a system call in the Linux kernel, called "ptree" / defined as system call #462, which takes in a process ID and returns a tree of all the threads associated with that process, all of the process's children and their threads, and all of their corresponding children/thread ... until the certain number of processes traversed reaches a number set by the user.
