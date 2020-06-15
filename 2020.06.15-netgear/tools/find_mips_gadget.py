# This IDAPython script defines the functions find_system_gadget, which locates
# a call to system with an argument on the stack in a MIPS executable.

import sys
import os

import idaapi
import idc

MAX_PREVIOUS_SEARCH = 10

def call_xrefs(function_name):
	function_address = LocByName(function_name)
	for addr in XrefsTo(function_address):
		mnem = GetMnem(addr.frm)

		# We only care about the calls
		if mnem not in ['jalr', 'jr']:
			continue

		yield addr.frm

def print_gadget(fd, start, end, stack_size):
	fd.write("Found gadget (address 0x{:x} buffer $sp+0x{:x})\n".format(start, stack_size))
	for address in range(start, end+4, 4):
		fd.write("0x{:x}: {}\n".format(address, GetDisasm(address)))
	fd.write("\n")

def find_gadget(symbol_name, filename = None):

	stack_write_inst = "addiu   $a0, $sp,"

	required = [
		[stack_write_inst],
		["la      $t9,", "lw      $t9,"],
	]

	disallowed_starts = [
		# No calls/branches in our
		"jalr", "jr", "b",

		# Writing to memory could crash, let's skip it.
		# It might be worthwhile to exclude sp here.
		"lw", "lh", "lb",
		"sw", "sh", "sb",
	]

	bad_register_writes = [
		"a0", "t9",
	]

	fd = sys.stdout
	if filename != None:
		fd = open(filename, 'w')

	for symbol_call in call_xrefs(symbol_name):
		mnem = GetMnem(symbol_call)

		found_insts = {}
		stack_size = None
		first_address = symbol_call
		for x in range(4, -MAX_PREVIOUS_SEARCH * 4, -4):
			if x == 0:
				continue
			inst_address = symbol_call+x
			if x < 0:
				first_address = inst_address

			disasm = GetDisasm(inst_address)
			for required_inst in required:
				if any([x in disasm for x in required_inst]):
					found_insts[inst_address] = required_inst
					if stack_size == None and disasm.startswith(stack_write_inst):
						stack_size = GetOperandValue(inst_address, 2)
					break

			if inst_address not in found_insts:
				if any([disasm.startswith(x) for x in disallowed_starts]):
					break

				if GetOpnd(inst_address, 0) in bad_register_writes:
					break

			if len(required) == len(found_insts):
				print_gadget(fd, first_address, symbol_call+4, stack_size)
				break

	if filename != None:
		fd.close()

def find_system_gadget(filename = None):
	find_gadget("system", filename)

idaapi.autoWait()

find_system_gadget(os.environ.get("OUTPUT_GADGET_NAME"))
if os.environ.get("OUTPUT_GADGET_NAME") != None:
	idc.Exit(0)

