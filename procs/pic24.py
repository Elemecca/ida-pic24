import idaapi as ida


asm_xc16 = {
    'name': 'Microchip XC16',

    'flag': (
        0
        | ida.ASH_HEXF3  # hex 'numbers':     0x000E
        | ida.ASD_DECF0  # decimal 'numbers': 14
        | ida.ASO_OCTF1  # octal 'numbers':   016
        | ida.ASB_BINF5  # binary 'numbers':  0b0110
        | ida.AS_ASCIIC  # strings accept C-style escapes
    ),

    'origin': '.org',
    'end': '.end',

    'cmnt': ';',
    'ascsep': '"',  # string literal delimiter
    'accsep': "'",  # char literal delimite
    'esccodes': '\'"',

    'a_ascii': '.ascii',
    'a_byte': '.byte',
    'a_word': '.word',
    'a_float': '.float',
    'a_double': '.double',
    'a_align': '.align',

    # FIXME: check these
    'a_bss': '.space %s',
    'a_seg': 'seg',
    'a_public': '.def',
    'a_weak': '',
    'a_extrn': '.ref',
    'a_comdef': '',

    'a_curip': '.',

    'lbrace': '(',
    'rbrace': ')',
    'a_mod': '%',
    'a_band': '&',
    'a_bor': '|',
    'a_xor': '^',
    'a_bnot': '~',
    'a_shl': '<<',
    'a_shr': '>>',
}


class Enum(object):
    def __init__(self, items):
        for idx, item in enumerate(items):
            setattr(self, item, idx)


registers = [
    # common registers
    'W0',
    'W1',
    'W2',
    'W3',
    'W4',
    'W5',
    'W6',
    'W7',
    'W8',
    'W9',
    'W10',
    'W11',
    'W12',
    'W13',
    'W14',
    'W15',
    'SPLIM',
    'PC',
    'RCOUNT',
    'CORCON',
    'STATUS',

    # dsPIC registers
    'ACCA',
    'ACCB',
    'DCOUNT',
    'DOSTART',
    'DOEND',

    # segment registers
    'TBLPAG',
    'PSVPAG',  # PIC24F / dsPIC3xF
    'DSRPAG',  # PIC24E / dsPIC3xE
    'DSWPAG',  # PIC24E / dsPIC3xE
    'CS',  # virtual CS to make IDA happy
    'DS',  # virtual DS to make IDA happy
]


ireg = Enum(registers)


def insn_get_next_word(insn):
    res = ida.get_wide_word(insn.ea + insn.size)
    insn.size += 2
    return res


IP_DOTB = 0x01
OPS1_WREG = 0x1

AUX_SZ_BYTE = 0x01


class Instruction(object):
    def __index__(self):
        return self.index

    def __int__(self):
        return self.index

    def decode(self, insn, code):
        insn.itype = self.index
        self._decode(insn, code)


class I_mov_lw(Instruction):
    """MOV #lit16, Wnd"""
    name = 'mov'
    mask = 0xF00000
    code = 0x200000
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        # 0010 kkkk kkkk kkkk kkkk dddd

        insn.Op1.type = ida.o_imm
        insn.Op1.value = (code & 0x0FFFF0) >> 4
        insn.Op1.dtyp = ida.dt_word

        insn.Op2.type = ida.o_reg
        insn.Op2.reg = ireg.W0 + (code & 0x00000F)
        insn.Op2.dtyp = ida.dt_word


class I_mov_ww(Instruction):
    """MOV{.B} Ws, Wd"""
    name = 'mov'
    mask = 0xF80000
    code = 0x780000
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        # 0111 1www wBhh hddd dggg ssss

        insn.Op1.type = ida.o_phrase
        insn.Op1.phrase = (code & 0x00000F)  # s
        insn.Op1.specflag4 = (code & 0x000070) >> 4   # g
        insn.Op1.specflag3 = (code & 0x078000) >> 15  # w
        insn.Op1.dtyp = ida.dt_word

        insn.Op2.type = ida.o_phrase
        insn.Op2.phrase = (code & 0x000780) >> 7  # d
        insn.Op2.specflag4 = (code & 0x003800) >> 11  # h
        insn.Op1.specflag3 = (code & 0x078000) >> 15  # w
        insn.Op1.dtyp = ida.dt_word

        if code & 0x004000:  # B
            insn.Op1.dtyp = ida.dt_byte
            insn.Op2.dtyp = ida.dt_byte
            insn.auxpref |= AUX_SZ_BYTE


class I_mov_fw(Instruction):
    """MOV f, Wnd"""
    name = 'mov'
    mask = 0xF80000
    code = 0x800000
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        # 1000 0fff ffff ffff ffff dddd

        insn.Op1.type = ida.o_mem
        insn.Op1.addr = ida.map_data_ea(insn, (code & 0x07FFF0) << 1)
        insn.Op1.dtyp = ida.dt_word

        insn.Op2.type = ida.o_reg
        insn.Op2.reg = ireg.W0 + (code & 0x00000F)
        insn.Op2.dtyp = ida.dt_word


class I_mov_wf(Instruction):
    """MOV Wns, f"""
    name = 'mov'
    mask = 0xF80000
    code = 0x880000
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        # 1000 1fff ffff ffff ffff ssss

        insn.Op1.type = ida.o_reg
        insn.Op1.reg = ireg.W0 + (code & 0x00000F)
        insn.Op1.dtyp = ida.dt_word

        insn.Op2.type = ida.o_mem
        insn.Op2.addr = ida.map_data_ea(insn, (code & 0x07FFF0) << 1)
        insn.Op2.dtyp = ida.dt_word


class I_mov_pw(Instruction):
    """MOV{.B} [Ws + Slit10], Wnd"""
    name = 'mov'
    mask = 0xF80000
    code = 0x900000
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        # 1001 0kkk kBkk kddd dkkk ssss

        insn.Op1.type = ida.o_displ
        insn.Op1.phrase = ireg.W0 + (code & 0x00000F)
        insn.Op1.addr = (
            ((code & 0x038000) >> 11)
            + ((code & 0x003800) >> 8)
            + ((code & 0x000070) >> 4)
        ) * (-2 if code & 0x040000 else 2)
        insn.Op1.dtyp = ida.dt_word

        insn.Op2.type = ida.o_reg
        insn.Op2.reg = ireg.W0 + ((code & 0x000780) >> 7)
        insn.Op2.dtyp = ida.dt_word

        if code & 0x004000:  # B
            insn.Op1.addr //= 2
            insn.Op1.dtyp = ida.dt_byte
            insn.Op2.dtyp = ida.dt_byte
            insn.auxpref |= AUX_SZ_BYTE


class I_mov_wp(Instruction):
    """MOV{.B} Wns, [Wd + Slit10]"""
    name = 'mov'
    mask = 0xF80000
    code = 0x980000
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        # 1001 1kkk kBkk kddd dkkk ssss

        insn.Op1.type = ida.o_reg
        insn.Op1.reg = ireg.W0 + (code & 0x00000F)
        insn.Op1.dtyp = ida.dt_word

        insn.Op2.type = ida.o_displ
        insn.Op1.phrase = ireg.W0 + ((code & 0x000780) >> 7)
        insn.Op1.addr = (
            ((code & 0x038000) >> 11)
            + ((code & 0x003800) >> 8)
            + ((code & 0x000070) >> 4)
        ) * (-2 if code & 0x040000 else 2)
        insn.Op1.dtyp = ida.dt_word

        if code & 0x004000:  # B
            insn.Op2.addr //= 2
            insn.Op1.dtyp = ida.dt_byte
            insn.Op2.dtyp = ida.dt_byte
            insn.auxpref |= AUX_SZ_BYTE


class I_mov_lbw(Instruction):
    """MOV.B #lit8, Wnd"""
    name = 'mov'
    mask = 0xFFF000
    code = 0xB3C000
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        # 1011 0011 1100 kkkk kkkk dddd

        insn.Op1.type = ida.o_imm
        insn.Op1.value = (code & 0x000FF0) >> 4
        insn.Op1.dtyp = ida.dt_byte

        insn.Op2.type = ida.o_reg
        insn.Op2.reg = ireg.W0 + (code & 0x00000F)
        insn.Op2.dtyp = ida.dt_byte


class I_mov_wrf(Instruction):
    """MOV{.B} WREG, f"""
    name = 'mov'
    mask = 0xFF8000
    code = 0xB78000
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        # 1011 0111 1B1f ffff ffff ffff

        insn.Op1.type = ida.o_reg
        insn.Op1.reg = ireg.W0
        insn.Op1.specflag1 = OPS1_WREG
        insn.Op1.dtyp = ida.dt_word

        insn.Op2.type = ida.o_mem
        insn.Op2.addr = ida.map_data_ea(insn, code & 0x001FFF)
        insn.Op2.dtyp = ida.dt_word

        if code & 0x004000:  # B
            insn.Op1.dtyp = ida.dt_byte
            insn.Op2.dtyp = ida.dt_byte
            insn.auxpref |= AUX_SZ_BYTE


class I_mov_f(Instruction):
    """MOV{.B} f"""
    name = 'mov'
    mask = 0xFFA000
    code = 0xBF8000
    feat = ida.CF_CHG1

    def _decode(self, insn, code):
        # 1011 1111 1B0f ffff ffff ffff

        insn.Op1.type = ida.o_mem
        insn.Op1.addr = ida.map_data_ea(insn, code & 0x001FFF)
        insn.Op1.dtyp = ida.dt_word

        if code & 0x004000:  # B
            insn.Op1.dtyp = ida.dt_byte
            insn.auxpref |= AUX_SZ_BYTE


class I_mov_fwr(Instruction):
    """MOV{.B} f, WREG"""
    name = 'mov'
    mask = 0xFFA000
    code = 0xBFA000
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        # 1011 1111 1B1f ffff ffff ffff

        insn.Op1.type = ida.o_mem
        insn.Op1.addr = ida.map_data_ea(insn, code & 0x001FFF)
        insn.Op1.dtyp = ida.dt_word

        insn.Op2.type = ida.o_reg
        insn.Op2.reg = ireg.W0
        insn.Op2.specflag1 = OPS1_WREG

        if code & 0x004000:  # B
            insn.Op1.dtyp = ida.dt_byte
            insn.Op2.dtyp = ida.dt_byte
            insn.auxpref |= AUX_SZ_BYTE


class Matcher(object):
    def __init__(self):
        self.instructions = []

    def add(self, instruction):
        self.instructions.append(instruction)

    def decode(self, insn, code):
        for inst in self.instructions:
            if code & inst.mask == inst.code:
                return inst.decode(insn, code)


instructions = [
    # invalid instruction
    # must be index 0 so uninitialized insn_t uses it
    {'name': '', 'feature': 0},
]

decode_map = list([Matcher() for idx in range(0, 256)])
for idx, itype in enumerate(Instruction.__subclasses__(), 1):
    setattr(itype, 'index', idx)

    inst = itype()
    instructions.append({
        'name': inst.name,
        'feature': inst.feat,
    })

    # this assumes that the mask is a strict prefix
    op_mask = (inst.mask >> 16) & 0xFF
    op_code = (inst.code >> 16) & 0xFF
    op_high = (op_code | ~op_mask) & 0xFF
    for op in range(op_code, op_high + 1):
        decode_map[op].add(inst)


class PIC24Processor(ida.processor_t):
    id = 0x8000 + 24

    flag = (
        ida.PR_USE32   # use 32-bit (as opposed to 16-bit) addresses
        | ida.PRN_HEX  # show numbers in hex by default
        | ida.PR_NO_SEGMOVE  # we don't support move_segm()
        | ida.PR_WORD_INS
        | ida.PR_SEGTRANS
    )

    # number of bits in a byte
    # where "byte" means the smallest addressable unit of memory
    cnbits = 16  # in code segments
    dnbits = 8   # in data segments

    psnames = ['pic24']
    plnames = ['Microchip PIC24']

    assembler = asm_xc16

    reg_names = registers

    #segreg_size = 1
    #reg_first_sreg = _ireg.TBLPAG
    segreg_size = 0
    reg_first_sreg = ireg.CS
    reg_last_sreg = ireg.DS
    reg_code_sreg = ireg.CS
    reg_data_sreg = ireg.DS

    instruc = instructions
    instruc_start = 0
    instruc_end = len(instruc) + 1

    def notify_ana(self, insn):
        code = insn_get_next_word(insn)
        decode_map[(code >> 16) & 0xFF].decode(insn, code)
        return insn.size if insn.itype != 0 else 0

    def notify_emu(self, insn):
        feat = insn.get_canon_feature()

        if not feat & ida.CF_STOP:
            ida.add_cref(insn.ea, insn.ea + insn.size, ida.fl_F)

        return 1

    def out_mnem(self, ctx):
        postfix = ""

        if ctx.insn.auxpref & AUX_SZ_BYTE:
            postfix = '.b'

        ctx.out_mnem(8, postfix)
        return 1

    def notify_out_operand(self, ctx, op):
        if op.type == ida.o_reg:
            ctx.out_register(self.reg_names[op.reg])

        elif op.type == ida.o_imm:
            ctx.out_symbol('#')
            ctx.out_value(op, ida.OOFW_IMM)

        elif op.type == ida.o_mem:
            ctx.out_value(op, ida.OOF_ADDR | ida.OOFW_24)

        elif op.type == ida.o_displ:
            ctx.out_symbol('[')
            ctx.out_register(self.reg_names[op.reg])
            ctx.out_symbol('+')
            ctx.out_value(op, ida.OOF_ADDR | ida.OOF_SIGNED)
            ctx.out_symbol(']')

        elif op.type == ida.o_phrase:
            mode = op.specflag4
            if mode != 0:
                ctx.out_symbol('[')

            if mode == 4:
                ctx.out_symbol('-')
                ctx.out_symbol('-')
            elif mode == 5:
                ctx.out_symbol('+')
                ctx.out_symbol('+')

            ctx.out_register(self.reg_names[op.reg])

            if mode == 2:
                ctx.out_symbol('-')
                ctx.out_symbol('-')
            elif mode == 3:
                ctx.out_symbol('+')
                ctx.out_symbol('+')
            elif mode in [6, 7]:
                ctx.out_symbol('+')
                ctx.out_register(self.reg_names[op.specflag3])

            if mode != 0:
                ctx.out_symbol(']')

        return True

    def notify_out_insn(self, ctx):
        ctx.out_mnemonic()

        if ctx.insn.ops[0].type != ida.o_void:
            ctx.out_one_operand(0)

        for idx in range(1, ida.UA_MAXOP):
            if ctx.insn.ops[idx].type == ida.o_void:
                break
            ctx.out_symbol(',')
            ctx.out_char(' ')
            ctx.out_one_operand(idx)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()


def PROCESSOR_ENTRY():
    return PIC24Processor()
