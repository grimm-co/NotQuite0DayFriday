#pragma once

#include <stdint.h>

enum SYMBOLS_OFFSETS
{
	//Symbols:

	//These symbol addresses can be obtained by running the commands listed in the
	//comments before them on the desired kernel. See the utilities/get_symbols.sh
	//for an automated generation script.

	// grep param_array_free /boot/System.map-*
	enum_PARAM_ARRAY_FREE,
#define PARAM_ARRAY_FREE  get_symbol_offset(enum_PARAM_ARRAY_FREE)
	// grep '\<memcpy\>' /boot/System.map-*
	enum_MEMCPY,
#define MEMCPY  get_symbol_offset(enum_MEMCPY)
	// grep run_cmd /boot/System.map-*
	enum_RUN_CMD,
#define RUN_CMD  get_symbol_offset(enum_RUN_CMD)
	// grep '\<netlink_sock_destruct$' /boot/System.map-*
	enum_NETLINK_SOCK_DESTRUCT,
#define NETLINK_SOCK_DESTRUCT  get_symbol_offset(enum_NETLINK_SOCK_DESTRUCT)
	// grep '\<modules\>' /boot/System.map-*
	enum_MODULE_LIST_HEAD,
#define MODULE_LIST_HEAD  get_symbol_offset(enum_MODULE_LIST_HEAD)
	// grep module_kset /boot/System.map-`uname -r`
	enum_MODULE_KSET,
#define MODULE_KSET  get_symbol_offset(enum_MODULE_KSET)
	// grep '\<seq_buf_putmem\>' /boot/System.map-`uname -r`
	enum_SEQ_BUF_PUTMEM,
#define SEQ_BUF_PUTMEM  get_symbol_offset(enum_SEQ_BUF_PUTMEM)
	// grep '\<seq_buf_to_user\>' /boot/System.map-`uname -r`
	enum_SEQ_BUF_TO_USER,
#define SEQ_BUF_TO_USER  get_symbol_offset(enum_SEQ_BUF_TO_USER)

	// The difference between the transport struct's owner module field and the
	// transport struct. Add the offset to the gnu.linkonce.this_module section
	// and the offset to the __this_module symobl, and subtract the offset of
	// the iscsi_iser_transport symbol. For example:
	// objdump -h ib_iser.ko  | grep gnu.linkonce.this_module | cut -d\  -f 4
	// 00000380
	// nm ib_iser.ko |grep __this_module
	// 0000000000000000 D __this_module
	// nm ib_iser.ko |grep iscsi_iser_transport
	// 0000000000000040 d iscsi_iser_transport
	// Value = 0x380 + 0x0 - 0x40 = 0x340
	enum_MODULE_INFO_DIFF,
#define MODULE_INFO_DIFF  get_symbol_offset(enum_MODULE_INFO_DIFF)
	//The offset in the kernel's struct module, where the status field is
	//Determine the "ptype /o struct module" command while debugging the kernel
	enum_MODULE_STATUS_OFFSET,
#define MODULE_STATUS_OFFSET  get_symbol_offset(enum_MODULE_STATUS_OFFSET)
	//The offset in the kernel's struct module, where the list->next field is
	//Determine the "ptype /o struct module" command while debugging the kernel
	enum_MODULE_LIST_OFFSET,
#define MODULE_LIST_OFFSET  get_symbol_offset(enum_MODULE_LIST_OFFSET)
	//The offset in the kernel's struct module, where the mkobj->kobj->entry->next
	//field is Determine the "ptype /o struct module" command while debugging the
	//kernel
	enum_MODULE_KOBJ_LIST_OFFSET,
#define MODULE_KOBJ_LIST_OFFSET  get_symbol_offset(enum_MODULE_KOBJ_LIST_OFFSET)
	//The offset in the kernel's struct module, where the refcnt field is
	//Determine the "ptype /o struct module" command while debugging the kernel
	enum_MODULE_REFCNT_OFFSET,
#define MODULE_REFCNT_OFFSET  get_symbol_offset(enum_MODULE_REFCNT_OFFSET)

	MAX_SYMBOLS_OFFSETS
};

//Get Symbol or Offset for the current kernel
uint64_t get_symbol_offset(enum SYMBOLS_OFFSETS);

//Set the kernel base
uint64_t set_kernel_base(uint64_t kernel_base, uint64_t kernel_slide);
