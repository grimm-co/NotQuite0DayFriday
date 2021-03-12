
///////////////////////////////////////////////////////////////////////////////
// Struct definitions /////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

struct module;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned short umode_t;
typedef uint32_t __bitwise__ itt_t;
typedef u64 sector_t;

struct iscsi_transport {
	struct module *owner;
	char *name;
	unsigned int caps;

	void *(*create_session) (void *ep,
					uint16_t cmds_max, uint16_t qdepth,
					uint32_t sn);
	void (*destroy_session) (void *session);
	struct iscsi_cls_conn *(*create_conn) (void *sess,
				uint32_t cid);
	int (*bind_conn) (void *session,
			  struct iscsi_cls_conn *cls_conn,
			  uint64_t transport_eph, int is_leading);
	int (*start_conn) (struct iscsi_cls_conn *conn);
	void (*stop_conn) (struct iscsi_cls_conn *conn, int flag);
	void (*destroy_conn) (struct iscsi_cls_conn *conn);
	int (*set_param) (struct iscsi_cls_conn *conn, enum iscsi_param param,
			  char *buf, int buflen);
	int (*get_ep_param) (void *ep, enum iscsi_param param,
			     char *buf);
	int (*get_conn_param) (struct iscsi_cls_conn *conn,
			       enum iscsi_param param, char *buf);
	int (*get_session_param) (void *session,
				  enum iscsi_param param, char *buf);
	int (*get_host_param) (void *shost,
				enum iscsi_host_param param, char *buf);
	int (*set_host_param) (void *shost,
			       enum iscsi_host_param param, char *buf,
			       int buflen);
	int (*send_pdu) (struct iscsi_cls_conn *conn, void *hdr,
			 char *data, uint32_t data_size);
	void (*get_stats) (struct iscsi_cls_conn *conn,
			   struct iscsi_stats *stats);

	int (*init_task) (void *task);
	int (*xmit_task) (void *task);
	void (*cleanup_task) (void *task);

	int (*alloc_pdu) (void *task, uint8_t opcode);
	int (*xmit_pdu) (void *task);
	int (*init_pdu) (void *task, unsigned int offset,
			 unsigned int count);
	void (*parse_pdu_itt) (void *conn, itt_t itt,
			       int *index, int *age);

	void (*session_recovery_timedout) (void *session);
	void *(*ep_connect) (void *shost,
					      struct sockaddr *dst_addr,
					      int non_blocking);
	int (*ep_poll) (void *ep, int timeout_ms);
	void (*ep_disconnect) (void *ep);
	int (*tgt_dscvr) (void *shost, enum iscsi_tgt_dscvr type,
			  uint32_t enable, struct sockaddr *dst_addr);
	int (*set_path) (void *shost, struct iscsi_path *params);
	int (*set_iface_param) (void *shost, void *data,
				uint32_t len);
	int (*get_iface_param) (void *iface,
				enum iscsi_param_type param_type,
				int param, char *buf);
	umode_t (*attr_is_visible)(int param_type, int param);
	int (*bsg_request)(void *job);
	int (*send_ping) (void *shost, uint32_t iface_num,
			  uint32_t iface_type, uint32_t payload_size,
			  uint32_t pid, struct sockaddr *dst_addr);
	int (*get_chap) (void *shost, uint16_t chap_tbl_idx,
			 uint32_t *num_entries, char *buf);
	int (*delete_chap) (void *shost, uint16_t chap_tbl_idx);
	int (*set_chap) (void *shost, void *data, int len);
	int (*get_flashnode_param) (void *fnode_sess,
				    int param, char *buf);
	int (*set_flashnode_param) (void *fnode_sess,
				    void *fnode_conn,
				    void *data, int len);
	int (*new_flashnode) (void *shost, const char *buf,
			      int len);
	int (*del_flashnode) (void *fnode_sess);
	int (*login_flashnode) (void *fnode_sess,
				void *fnode_conn);
	int (*logout_flashnode) (void *fnode_sess,
				 void *fnode_conn);
	int (*logout_flashnode_sid) (void *cls_sess);
	int (*get_host_stats) (void *shost, char *buf, int len);
	u8 (*check_protection)(void *task, sector_t *sector);
};

struct kernel_param_ops {
	unsigned int flags;
	/* Returns 0, or -errno.  arg is in kp->arg. */
	int (*set)(const char *val, void *kp);
	/* Returns length written or -errno.  Buffer is 4k (ie. be short!) */
	int (*get)(char *buffer, void *kp);
	/* Optional function to free kp->arg when module unloaded. */
	void (*free)(void *arg);
};

struct kparam_array
{
	unsigned int max;
	unsigned int elemsize;
	unsigned int *num;
	const struct kernel_param_ops *ops;
	void *elem;
};

struct seq_buf {
	char *buffer;
	size_t size;
	size_t len;
	loff_t readpos;
};


///////////////////////////////////////////////////////////////////////////////
// Globals ////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

#define TRANSPORT_STRUCT_OFFSET (offsetof(struct iscsi_transport, xmit_pdu))

#define MSG_SIZE            8192
#define MSG_HEADER_SIZE 0x30         //size of the header added to the kernel's UDP messages struct
#define	SPRAY0_BUF_LEN0     (2048+1) //Smallest size still in the 4096 region

#define	NUM_CONNECTIONS 75
#define	BASE_PORT 3000

extern unsigned char buf_padding[SPRAY0_BUF_LEN0];

///////////////////////////////////////////////////////////////////////////////
// Functions //////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

uint64_t get_uint64_from_file(const char * filename, int is_hex);
int read_file(const char * filename, char * buffer, size_t length);
uint64_t get_tcp_transport_handle();
uint64_t get_iser_transport_handle();
int iscsi_get_file(int hostno);
void read_response(int sock_fd, struct nlmsghdr * nlh);
void read_response_error(int sock_fd, struct nlmsghdr * nlh, int exit_on_error);
void send_netlink_msg(int sock_fd, struct nlmsghdr * nlh);
void send_netlink_msg_sized(int sock_fd, struct nlmsghdr * nlh, int size);
int init_server(struct sockaddr_in *si, int port);
int init_client(struct sockaddr_in *si, int port);
int client_sendmsg(int sock, struct sockaddr_in *si, char *buf, size_t len);
int bind_cpu();
int setup_iscsi(int load_only, uint32_t *hostnop, uint32_t *sidp, int *sock_fdp, uint64_t *handlep);
int setup_overflow(uint32_t hostno, int sock_fd, uint64_t handle);
int init_msgq();
int msgq_send(int msgq_fd, char *buf, size_t len);
int msgq_recv(int msgq_fd);

#define SLEEP_FOREVER() while(1) { sleep(60); }
