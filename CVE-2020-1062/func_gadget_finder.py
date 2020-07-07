"""
IE 11 has a protection that , on top of CFG, restricts you to only calling indirect functions
which have similar type signature as the intended function. This is done because in 'thiscall' convention the callee
is responsible for stack cleanup
Specifically there is a stack pointer save before the actual indirect call and compare after the call which ensures
that you can only call functions with the same number of arguments as intended.

This particular script attempts to find functions with the following criteria -
a) Function's RVA is listed in the CFG table/is a valid indirect call location
b) has 2 arguments , i.e have a retn 0x8 instruction at the end of the function
c) there is a memory write in a memory location which is referenced as a double/triple/quadruple pointer either directly or indirectly
   via the 'this' pointer (ecx/rcx)
   essentially any writes of the form  *(*(this+ index) )
d) any other function which satisfies only c) above but its is called from a function that satisfies a) AND b)

note: This script currently doesn't rely on BN's analyzer to recognize CFG table. There is some uncertainty which
has been reported as an issue here-
https://github.com/Vector35/binaryninja-api/issues/1542

"""
import sys
br = BinaryReader(bv)


def get_reg_value_at_address(func, reg, address):
    bbl = func.get_basic_block_at(address)
    bbl_address = bbl.start
    latest_ecx_val = 0
    for each_ins in func.mlil.ssa_form.instructions:
        if each_ins.address < bbl.start:
            continue
        if each_ins.address == address:
            return latest_ecx_val
        if each_ins.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
            if reg in str(each_ins.dest):
                try:
                    latest_ecx_val = each_ins.vars_read[0]
                except BaseException:
                    # vars_read doesnt exist/cant be parsed, bailout
                    return 0


def is_thiscall(each_func):
    mlil = each_func.mlil_instructions
    ecx_source = 0
    ecx_dest = 0
    for mlil_ins in mlil:
        if mlil_ins.operation == MediumLevelILOperation.MLIL_SET_VAR:
            if mlil_ins.src.value.reg == 'ecx':
                if ecx_dest == 1:
                    return 0
                else:
                    return 1
            if mlil_ins.dest == 'ecx':
                ecx_dest = 1
    return 0


def func_gadget_find(each_func, recurse=0, ptr_level=0,
                     sink1=[], sink2=[], sink3=[], sink4=[], sink5=[]):

    found = 0
    # set limit to recursive callee scanning
    if recurse > 1:
        return
    i = 0
    while(1):
        memory_uses = each_func.mlil.ssa_form.get_ssa_memory_uses(i)
        if (memory_uses == []):
            break
        hit = 0
        for each_use in memory_uses:
            fail = 0
            # VAR_SSA
            if each_use.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
                if len(each_use.vars_read) == 0:
                    continue
                if len(each_use.vars_written) == 0:
                    continue
                vars_read = each_use.vars_read[0]
                vars_written = each_use.vars_written[0]
                try:
                    read_ins = each_func.mlil.get_ssa_var_definition(
                        each_use.vars_read[0])
                except BaseException:
                    pass  # we catch this below
                # If memory is being read from ecx or another register that
                # tracked ecx
                try:
                    if str(read_ins.src) == 'ecx':
                        sink1.append(vars_written)
                except BaseException:
                    pass
                try:
                    if 'ecx' in str(read_ins.src.value):
                        sink1.append(vars_written)
                except BaseException:
                    pass
                try:
                    if 'ecx' in str(vars_read.var):
                        sink1.append(vars_written)
                except BaseException:
                    fail = 1
                if fail == 1:
                    continue  # both .var and .src are None, cant anlyze this operation
                for sinks in sink1:
                    if vars_read == sinks:
                        sink2.append(vars_written)
                for sinks in sink2:
                    if vars_read == sinks:
                        sink3.append(vars_written)
                for sinks in sink3:
                    if vars_read == sinks:
                        sink4.append(vars_written)
                for sinks in sink4:
                    if vars_read == sinks:
                        sink5.append(vars_written)
            # CALL_SSA
            if each_use.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                latest_ecx_val = get_reg_value_at_address(
                    each_func, 'ecx', each_use.address)
                if latest_ecx_val == 0:
                    continue  # this callee isnt taking arg(this) in via 'ecx'
                ptr_level_callee = 0
                if sink2 != []:
                    for sinks in sink2:
                        if latest_ecx_val == sinks:
                            ptr_level_callee = 1
                if sink3 != []:
                    for sinks in sink3:
                        if latest_ecx_val == sinks:
                            ptr_level_callee = 2
                if sink4 != []:
                    for sinks in sink4:
                        if latest_ecx_val == sinks:
                            ptr_level_callee = 3
                if sink5 != []:
                    for sinks in sink5:
                        if latest_ecx_val == sinks:
                            ptr_level_callee = 4
                if ptr_level_callee == 0:
                    continue
                # bv.get_function_at expects a regular funciton type, not mlil
                # function
                if each_use.dest.value.value is None:
                    continue  # indirect calls cannot be resolved yet
                if bv.get_function_at(each_use.dest.value.value) is None:
                    continue  # in case of imported funcs in external lib
                if is_thiscall(bv.get_function_at(
                        each_use.dest.value.value)) == 0:
                    continue  # not a thiscall
                found_return = func_gadget_find(
                    bv.get_function_at(
                        each_use.dest.value.value),
                    recurse + 1,
                    ptr_level_callee)
                if found_return != 0 and found_return is not None:
                    print(
                        "[*] Function %s @ %s has a callee %s @ %s which seems useful" %
                        (each_func.symbol.full_name, hex(
                            each_func.start), bv.get_function_at(
                            each_use.dest.value.value).symbol.full_name, hex(
                            bv.get_function_at(
                                each_use.dest.value.value).start)))
            # STORE_SSA
            if each_use.operation == MediumLevelILOperation.MLIL_STORE_SSA:
                if len(each_use.dest.ssa_form.vars_read) == 0:
                    continue
                # note: for MLIL_STORE_SSA vars_written is an empty []
                vars_written = each_use.dest.ssa_form.vars_read[0]
                if ptr_level == 1:
                    for sinks in sink2:
                        if vars_written == sinks:
                            print(
                                "[*] Found a write via @ %s vars_written:%s sinks:%s a double de-reference of this/ecx!\n %s ,%s \n" %
                                (each_use, vars_written, sinks, each_func.symbol.full_name, hex(
                                    each_func.start)))
                            found += 1
                            break
                elif ptr_level == 2 or ptr_level == 3 or ptr_level == 4:
                    for sinks in sink1:
                        if vars_written == sinks:
                            print(
                                "[*] Found a write via @ %s vars_written:%s sinks:%s a double de-reference of this/ecx!\n %s ,%s \n" %
                                (each_use, vars_written, sinks, each_func.symbol.full_name, hex(
                                    each_func.start)))
                            found += 1
                            break
                elif ptr_level == 0:
                    for sinks in sink3:
                        if vars_written == sinks:
                            print(
                                "[*] Found a write via @ %s vars_written:%s sinks:%s a double de-reference of this/ecx!\n %s ,%s \n" %
                                (each_use, vars_written, sinks, each_func.symbol.full_name, hex(
                                    each_func.start)))
                            found += 1
                            break
                    for sinks in sink4:
                        if vars_written == sinks:
                            print(
                                "[*] Found a write via @ %s vars_written:%s sinks:%s a triple de-reference of this/ecx!\n %s ,%s \n" %
                                (each_use, vars_written, sinks, each_func.symbol.full_name, hex(
                                    each_func.start)))
                            found += 1
                            break
                    for sinks in sink5:
                        if vars_written == sinks:
                            print(
                                "[*] Found a write via @ %s vars_written:%s sinks:%s a quadruple de-reference of this/ecx!\n %s ,%s \n" %
                                (each_use, vars_written, sinks, each_func.symbol.full_name, hex(
                                    each_func.start)))
                            found += 1
                            break
        i = i + 1
    return found


def parse_data_view(structure, address):
    PE = StructuredDataView(bv, structure, address)
    return PE


def byte_swap(i):
    i = str(i).replace(" ", "")
    temp = int(i, 16)
    return struct.unpack("<I", struct.pack(">I", temp))[0]


# Check if BN was able to parse CFG headers successfully?
data_keys = list(bv.data_vars.keys())
data_vals = list(bv.data_vars.values())
lcte_index = 0
cfg_index = 0
header_index = 0
for index in range(0, len(data_vals)):
    if "Guard_Control_Flow_Function_Table" in str(data_vals[index]):
        cfg_index = index
    if "Load_Configuration_Directory_Table" in str(data_vals[index]):
        lcte_index = index
    if "PE32_Optional_Header" in str(data_vals[index]):
        header_index = index

if cfg_index != 0 and lcte_index != 0:
    GuardCFFunctionTable_virtualAddress = data_keys[cfg_index]
    lcte_virtualAddress = data_keys[lcte_index]
    lcte = parse_data_view(
        "Load_Configuration_Directory_Table",
        lcte_virtualAddress)
    br.offset = lcte.guardCFFunctionCount.address
    if "uint64_t" in str(lcte.guardCFFunctionCount.type):
        GuardCFFunctionTable_size = br.read64le()
    elif "uint32_t" in str(lcte.guardCFFunctionCount.type):
        GuardCFFunctionTable_size = br.read32le()
elif header_index != 0:
    pe32_header_address = data_vals[header_index]
    pe32_header = parse_data_view(
        "PE32_Optional_Header",
        pe32_header_address.address)
    loadConfigTableEntry = pe32_header.loadConfigTableEntry.address
    lcte = parse_data_view(
        "PE_Data_Directory_Entry",
        loadConfigTableEntry)  # hardcoded for now
    lcte_virtualAddress = byte_swap(lcte.virtualAddress)  # RVA
    lcte_size = byte_swap(lcte.size)
    lcte_virtualAddress = lcte_virtualAddress + bv.start
    GuardCFFunctionTable_offset = bv.types["SIZE_T"].width * 4  # 16/32
    GuardCFFunctionTable = parse_data_view(
        "PE_Data_Directory_Entry",
        (lcte_virtualAddress + lcte_size + GuardCFFunctionTable_offset))
    GuardCFFunctionTable_virtualAddress = byte_swap(
        GuardCFFunctionTable.virtualAddress)  # RVA
    GuardCFFunctionTable_size = byte_swap(GuardCFFunctionTable.size)
else:
    print("Couldnt Find PE32 header, exiting!")
    sys.exit()

br.offset = GuardCFFunctionTable_virtualAddress

# Find all functions within the CFG Table
CFG_funcs = []
for i in range(0, GuardCFFunctionTable_size):
    CFG_RVA = br.read32le()
    CFG_byte = br.read8()
    func_address = bv.get_function_at(bv.start + CFG_RVA)
    # if BN failed to identify a function there, create one
    if func_address is None:
        bv.create_user_function(bv.start + CFG_RVA)
    CFG_funcs.append(bv.get_function_at(bv.start + CFG_RVA))

if GuardCFFunctionTable_size == len(CFG_funcs):
    print("[*] Found %s CFG Valid Functions" % (len(CFG_funcs)))
else:
    print("[*] Number of functions within the CFG Table dont match Function count within the CFG headers")

retn_func_count = 0
for each_func in CFG_funcs:
    # for each_func in bv.functions:
    # Filter those functions with "retn 0x8" instructions
    if each_func.stack_adjustment.value == 8:
        retn_func_count += 1
        found = func_gadget_find(each_func)  # check the function for gadgets

print(
    "[*] Found %s functions with the return instruction criteria" %
     (retn_func_count))
