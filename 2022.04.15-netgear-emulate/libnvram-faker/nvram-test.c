#include "nvram-faker.h"
#include <stdio.h>

int main(int argc, char ** argv) {
	if(argc < 2) {
		printf("Usage: nvram-test key\n");
		return 1;
	}
  printf("key = %s, value = %s\n", argv[1], nvram_get(argv[1]));
  return 0;
}
