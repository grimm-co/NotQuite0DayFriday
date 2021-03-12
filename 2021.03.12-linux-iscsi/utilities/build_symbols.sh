#!/bin/bash
SYSTEM_MAP=$1
STRUCT_NAME=$2
UNAME_OUT=$3

if [ "$SYSTEM_MAP" = "" ]; then
	SYSTEM_MAP="/boot/System.map-`uname -r`"
fi
if [ "$UNAME_OUT" = "" ]; then
	UNAME_OUT=$(uname -r)
fi

PARAM_ARRAY_FREE=$(grep param_array_free $SYSTEM_MAP | cut -d\  -f 1)
MEMCPY=$(grep '\<memcpy\>' $SYSTEM_MAP | cut -d\  -f 1)
RUN_CMD=$(grep run_cmd $SYSTEM_MAP | cut -d\  -f 1)
NETLINK_SOCK_DESTRUCT=$(grep '\<netlink_sock_destruct$' $SYSTEM_MAP | cut -d\  -f 1)
MODULE_LIST_HEAD=$(grep '\<modules\>' $SYSTEM_MAP | cut -d\  -f 1)
MODULE_KSET=$(grep module_kset $SYSTEM_MAP | cut -d\  -f 1)
SEQ_BUF_PUTMEM=$(grep '\<seq_buf_putmem\>' $SYSTEM_MAP | cut -d\  -f 1)
SEQ_BUF_TO_USER=$(grep '\<seq_buf_to_user\>' $SYSTEM_MAP | cut -d\  -f 1)

if [ "$STRUCT_NAME" = "" ]; then
	if [ -f /etc/redhat-release ]; then
		RHEL_VERSION=$(grep -o '[0-9\.]*' /etc/redhat-release | sed 's/\./_/g')
		KERNEL_VERSION=$(uname -r | sed 's/.x86_64//g' | sed 's/[.-]/_/g')
		STRUCT_NAME="rhel_${RHEL_VERSION}_kernel_${KERNEL_VERSION}_symbols"
	elif [ "$(which lsb_release)" != "" -a "$(lsb_release -a 2>/dev/null |grep Ubuntu)" != "" ]; then
		UBUNTU_VERSION=$(lsb_release -a 2>/dev/null | grep Description | grep -o '[0-9.]*' | sed 's/\./_/g')
		KERNEL_VERSION=$(uname -r | sed 's/[.-]/_/g')
		STRUCT_NAME="ubuntu_${UBUNTU_VERSION}_kernel_${KERNEL_VERSION}_symbols"
	else
		echo "Unknown distribution"
		exit
	fi
fi

STRUCT_NAME2="other"
echo
echo "struct symbol_offset $STRUCT_NAME2[] = {"
echo "  { .is_address = 1, .value = 0x${PARAM_ARRAY_FREE}UL }, //PARAM_ARRAY_FREE"
echo "  { .is_address = 1, .value = 0x${MEMCPY}UL }, //MEMCPY"
echo "  { .is_address = 1, .value = 0x${RUN_CMD}UL }, //RUN_CMD"
echo "  { .is_address = 1, .value = 0x${NETLINK_SOCK_DESTRUCT}UL }, //NETLINK_SOCK_DESTRUCT"
echo "  { .is_address = 1, .value = 0x${MODULE_LIST_HEAD}UL }, //MODULE_LIST_HEAD"
echo "  { .is_address = 1, .value = 0x${MODULE_KSET}UL }, //MODULE_KSET"
echo "  { .is_address = 1, .value = 0x${SEQ_BUF_PUTMEM}UL }, //SEQ_BUF_PUTMEM"
echo "  { .is_address = 1, .value = 0x${SEQ_BUF_TO_USER}UL }, //SEQ_BUF_TO_USER"
echo "  //TODO double check these offsets"
echo "  { .is_address = 0, .value = 0x340,               }, //MODULE_INFO_DIFF"
echo "  { .is_address = 0, .value = 0x0,                 }, //MODULE_STATUS_OFFSET"
echo "  { .is_address = 0, .value = 0x8,                 }, //MODULE_LIST_OFFSET"
echo "  { .is_address = 0, .value = 0x58,                }, //MODULE_KOBJ_LIST_OFFSET"
echo "  { .is_address = 0, .value = 0x328,               }, //MODULE_REFCNT_OFFSET"
echo "};"
echo "//###"
echo "  { .symbols = $STRUCT_NAME2,"
echo "  .count = ARRAY_SIZE($STRUCT_NAME2),"
echo "  .uname = \"${UNAME_OUT}\" },"
echo
