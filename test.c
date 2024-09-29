#include <syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <linux/tskinfo.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

int main(int argc, char **argv) {
	pid_t root_p = 0;
	if (argc > 1 && argv[1]){
		printf("Calculating value input\n");
		for (int x = 0; x < strlen(argv[1]); x++){
			root_p *= 10;
			root_p += argv[1][x] - '0';
		}
	}

	int x;
	int nr = 10;
	struct tskinfo *t = (struct tskinfo *) malloc(nr * sizeof(struct tskinfo));
	if (t == NULL) {
		perror("malloc");
		return -1;
	}
	while (1) {
		int nr_start = nr;
		if ((x = syscall(462, t, &nr, root_p)) != 0){
			perror("syscall");
		}
		if (nr != nr_start) break;
		nr *= 2;
		free(t);
		t = (struct tskinfo *) malloc(nr * sizeof(struct tskinfo));
		if (t == NULL){
			perror("malloc");
			return -1;
		}
	}
	for (int i = 0; i < nr; i++){
		printf("%s,%d,%d,%d,%p,%p,%d\n", t[i].comm, t[i].pid, t[i].tgid,
    	t[i].parent_pid, (void *) t[i].userpc, (void *) t[i].kernelpc, t[i].level);

	}
	free(t);
}
