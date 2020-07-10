# Information Leakage in OpenBSD and FreeBSD

### Overview
The BSD msgctl and semctl syscalls return kernel pointers and uninitialized
kernel memory to the user, leaking potentially sensitive information.

Tested Versions: FreeBSD 12.1, FreeBSD 11.2, OpenBSD 6.6, OpenBSD 6.4
Affected Versions: FreeBSD 2.0+, OpenBSD 1.1+

### Exercising
```
# FreeBSD only
$ clang msgctl.c -o msgctl
$ ./msgctl
msqid_ds.msg_first = 0xfffff8000382d800
msqid_ds.msg_last = 0xfffff8000382d820

# FreeBSD and OpenBSD
$ clang semctl.c -o semctl
$ ./semctl
0: sem 0x120000
sem_perm.cuid = 1000
sem_perm.cgid = 1000
sem_perm.uid = 1000
sem_perm.gid = 1000
sem_perm.mode = 438
sem_perm.seq = 18
leaked pad1 = 00 00 00 00        <----- Leaked uninitialized kernel memory
sem_perm.key = 0
sem_base = 0xffff8000007afe50    <----- Kernel Pointer
sem_nsems = 1
leaked pad2 = 41 00 00 2B 00 00  <----- Leaked uninitialized kernel memory
sem_otime = 0
sem_ctime = 1588478538
```

### Details
Within the System V IPC subsystems, the BSD kernel supports the ability to
create message queues and semaphores that can be used across separate processes.
These messages and semaphores are managed by the kernel in `sys/kern/sysv_msg.c`
and `sys/kern/sysv_sem.c` respectively. In order to gather information on the
message queues and semaphores, the kernel provides the `IPC_STAT` command for
the msgctl and semctl syscalls. Within the kernel msgctl and semctl syscalls, a
kernel struct containing the message queue or semaphore information is directly
copied from the kernel to userland memory. As a result, several kernel pointers
and uninitialized bytes are leaked to userland. These information leak bugs have
existed in the BSD kernels for as long as the IPC message and semaphore
subsystem has existed.

The msgctl syscall returns a `msqid_ds` struct that contains the message queue
information. Within the
[`msqid_ds` struct](https://github.com/freebsd/freebsd/blob/dc28a074e/sys/sys/msg.h#L90),
the `__msg_first` and `__msg_last` kernel pointers point to the first and last
message within a queue. On FreeBSD, the [entire struct is copied to the user's
passed in
buffer](https://github.com/freebsd/freebsd/blob/dc28a074e/sys/kern/sysv_msg.c#L494),
and thus, these two kernel pointers are leaked to the user. On the other
hand, OpenBSD does not leak kernel pointer values. While the [OpenBSD `msqid_ds`
struct](https://github.com/openbsd/src/blob/155713db747/sys/sys/msg.h#L35) also
contains the `msg_first` and `msg_last` pointers and the [entire struct is 
copied to userland](https://github.com/openbsd/src/blob/155713db747/sys/kern/sysv_msg.c#L177),
these fields are not used, and thus the value copied in them to userland is
always zero. 

Similarly, the
[FreeBSD](https://github.com/freebsd/freebsd/blob/dc28a074e/sys/sys/sem.h#L49)
and [OpenBSD](https://github.com/openbsd/src/blob/155713db747/sys/sys/sem.h#L53)
`semid_ds` struct is returned from the semctl syscall while containing a kernel
pointer. The `IPC_STAT` command in semctl [copies
the](https://github.com/freebsd/freebsd/blob/dc28a074e/sys/kern/sysv_sem.c#L684)
[entire `semid_ds` struct](https://github.com/openbsd/src/blob/155713db747/sys/kern/sysv_sem.c#L302)
to userland without first zeroizing the `sem_base` pointer, thus leaking its
value to userland. Additionally, the `semid_ds` [struct is not properly
initialized](https://github.com/openbsd/src/blob/155713db747/sys/kern/sysv_sem.c#L471),
such that the padding bytes within the struct are not set. Thus, the 10 bytes of
padding in this struct the can be used to leak additional kernel memory.

### Timeline
2020.07.08 - Reported bug to FreeBSD (secteam@FreeBSD.org) and OpenBSD (deraadt@openbsd.org)
2020.07.08 - Theo provides feedback and patches the bug[1]
2020.07.08 - FreeBSD security team responds acknowledging the report
2020.07.09 - Errata issued for OpenBSD[2]
2020.07.10 - Public release

[1] https://github.com/openbsd/src/commit/464b9e490f2a1ac3e43c1dd16ffd344d9bbc61e0
[2] https://www.openbsd.org/errata67.html
