import idaapi


class Enum(object):
    def __init__(self, items):
        for idx, value in enumerate(items):
            setattr(self, value, idx)


asm_xc16 = {
    'name': 'Microchip XC16',

    'flag': (
        0
        | idaapi.ASH_HEXF3  # hex 'numbers':     0x000E
        | idaapi.ASD_DECF0  # decimal 'numbers': 14
        | idaapi.ASO_OCTF1  # octal 'numbers':   016
        | idaapi.ASB_BINF5  # binary 'numbers':  0b0110
        | idaapi.AS_ASCIIC  # strings accept C-style escapes
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


IP_DOTB = 0x01
OPS1_WREG = 0x1

AUX_SZ_BYTE = 0x01

def insn_get_next_word(insn):
    res = idaapi.get_wide_word(insn.ea + insn.size)
    insn.size += 2
    return res


class PIC24Processor(idaapi.processor_t):
    id = 0x8000 + 24

    flag = (
        idaapi.PR_USE32   # use 32-bit (as opposed to 16-bit) addresses
        | idaapi.PRN_HEX  # show numbers in hex by default
        | idaapi.PR_NO_SEGMOVE  # we don't support move_segm()
    )

    # number of bits in a byte
    # where "byte" means the smallest addressable unit of memory
    cnbits = 16  # in code segments
    dnbits = 8   # in data segments

    psnames = ['pic24']
    plnames = ['Microchip PIC24']

    assembler = asm_xc16

    reg_names = [
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

    _ireg = Enum(reg_names)

    #segreg_size = 1
    #reg_first_sreg = _ireg.TBLPAG
    segreg_size = 0
    reg_first_sreg = _ireg.CS
    reg_last_sreg = _ireg.DS
    reg_code_sreg = _ireg.CS
    reg_data_sreg = _ireg.DS

    instruc = [
        {'name': '', '_type': 'null', 'feature': 0},

        # move instructions
        {
            'name': 'exch', '_type': 'exch',
            'feature': idaapi.CF_USE1 | idaapi.CF_CHG1 | idaapi.CF_USE2 | idaapi.CF_CHG2,
            'cmt': '(exch Wns, Wnd) swap Wns and Wnd',
        }, {
            'name': 'mov', '_type': 'movf',
            'feature': idaapi.CF_USE1 | idaapi.CF_CHG1,
            'cmt': '(mov[.b] f) move f to f',
        }, {
            'name': 'mov', '_type': 'movfwr',
            'feature': idaapi.CF_USE1 | idaapi.CF_CHG2,
            'cmt': '(mov[.b] f, WREG) move f to W0',
        }, {
            'name': 'mov', '_type': 'movwrf',
            'feature': idaapi.CF_USE1 | idaapi.CF_CHG2,
            'cmt': '(mov[.b] WREG, f) move WREG to f',
        }, {
            'name': 'mov', '_type': 'movfw',
            'feature': idaapi.CF_USE1 | idaapi.CF_CHG2,
            'cmt': '(mov f, Wnd) move f to Wnd',
        }, {
            'name': 'mov', '_type': 'movwf',
            'feature': idaapi.CF_USE1 | idaapi.CF_CHG2,
            'cmt': '(mov Wns, f) move Wns to f',
        }, {
            'name': 'mov.b', '_type': 'movlbw',
            'feature': idaapi.CF_USE1 | idaapi.CF_CHG2,
            'cmt': '(mov.b #lit8, Wnd) move 8-bit literal to Wnd',
        }, {
            'name': 'mov', '_type': 'movlw',
            'feature': idaapi.CF_USE1 | idaapi.CF_CHG2,
            'cmt': '(mov #lit16, Wnd) move 16-bit literal to Wnd',
        }, {
            'name': 'mov', '_type': 'movpw',
            'feature': idaapi.CF_USE1 | idaapi.CF_CHG2,
            'cmt': '(mov [Ws+Slit10], Wnd) move [Ws + signed 10-bit offset] to Wnd',
        }, {
            'name': 'mov', '_type': 'movwp',
            'feature': idaapi.CF_USE1 | idaapi.CF_CHG2,
            'cmt': '(mov Wns, [Wd+Slit10]) move Wns to [Wd + signed 10-bit offset]',
        }, {
            'name': 'mov', '_type': 'movww',
            'feature': idaapi.CF_USE1 | idaapi.CF_CHG2,
            'cmt': '(mov Wso, Wdo) move Wso to Wdo',
        }, {
            'name': 'mov.d', '_type': 'movd',
            'feature': idaapi.CF_USE1 | idaapi.CF_CHG2,
            'cmt': '(mov.d Ws, Wnd) move double Ws to Wnd:Wnd+1',
        },
    ]

    _itype = Enum([ins['_type'] for ins in instruc])

    instruc_start = 0
    instruc_end = len(instruc) + 1


    def __init__(self):
        idaapi.processor_t.__init__(self)

    def notify_init(self, idp_file):
        return 1

    def _decode_mov(self, insn, code):
        # MOV #lit16, Wnd
        # 0010 kkkk kkkk kkkk kkkk dddd
        if code & 0xF00000 == 0x200000:
            insn.itype = self._itype.movlw

            insn.Op1.type = idaapi.o_imm
            insn.Op1.value = (code & 0x0FFFF0) >> 4
            insn.Op1.dtyp = idaapi.dt_word

            insn.Op2.type = idaapi.o_reg
            insn.Op2.reg = self._ireg.W0 + (code & 0x00000F)
            insn.Op2.dtyp = idaapi.dt_word

        # MOV{.B} Ws, Wd
        # 0111 1www wBhh hddd dggg ssss
        elif code & 0xF80000 == 0x780000:
            insn.itype = self._itype.movww

            insn.Op1.type = idaapi.o_phrase
            insn.Op1.phrase = (code & 0x00000F)  # s
            insn.Op1.specflag4 = (code & 0x000070) >> 4   # g
            insn.Op1.specflag3 = (code & 0x078000) >> 15  # w
            insn.Op1.dtyp = idaapi.dt_word

            insn.Op2.type = idaapi.o_phrase
            insn.Op2.phrase = (code & 0x000780) >> 7  # d
            insn.Op2.specflag4 = (code & 0x003800) >> 11  # h
            insn.Op1.specflag3 = (code & 0x078000) >> 15  # w
            insn.Op1.dtyp = idaapi.dt_word

            if code & 0x004000:  # B
                insn.Op1.dtyp = idaapi.dt_byte
                insn.Op2.dtyp = idaapi.dt_byte
                insn.auxpref |= AUX_SZ_BYTE

        # MOV f, Wnd
        # 1000 0fff ffff ffff ffff dddd
        elif code & 0xF80000 == 0x800000:
            insn.itype = self._itype.movfw

            insn.Op1.type = idaapi.o_mem
            insn.Op1.addr = idaapi.map_data_ea(insn, (code & 0x07FFF0) << 1)
            insn.Op1.dtyp = idaapi.dt_word

            insn.Op2.type = idaapi.o_reg
            insn.Op2.reg = self._ireg.W0 + (code & 0x00000F)
            insn.Op2.dtyp = idaapi.dt_word

        # MOV Wns, f
        # 1000 1fff ffff ffff ffff ssss
        elif code & 0xF80000 == 0x880000:
            insn.itype = self._itype.movwf

            insn.Op1.type = idaapi.o_reg
            insn.Op1.reg = self._ireg.W0 + (code & 0x00000F)
            insn.Op1.dtyp = idaapi.dt_word

            insn.Op2.type = idaapi.o_mem
            insn.Op2.addr = idaapi.map_data_ea(insn, (code & 0x07FFF0) << 1)
            insn.Op2.dtyp = idaapi.dt_word

        # MOV{.B} [Ws + Slit10], Wnd
        # 1001 0kkk kBkk kddd dkkk ssss
        elif code & 0xF80000 == 0x900000:
            insn.itype = self._itype.movpw

            insn.Op1.type = idaapi.o_displ
            insn.Op1.phrase = self._ireg.W0 + (code & 0x00000F)
            insn.Op1.addr = (
                ((code & 0x038000) >> 11)
                + ((code & 0x003800) >> 8)
                + ((code & 0x000070) >> 4)
            ) * (-2 if code & 0x040000 else 2)
            insn.Op1.dtyp = idaapi.dt_word

            insn.Op2.type = idaapi.o_reg
            insn.Op2.reg = self._ireg.W0 + ((code & 0x000780) >> 7)
            insn.Op2.dtyp = idaapi.dt_word

            if code & 0x004000:  # B
                insn.Op1.addr //= 2
                insn.Op1.dtyp = idaapi.dt_byte
                insn.Op2.dtyp = idaapi.dt_byte
                insn.auxpref |= AUX_SZ_BYTE

        # MOV{.B} Wns, [Wd + Slit10]
        # 1001 1kkk kBkk kddd dkkk ssss
        elif code & 0xF80000 == 0x980000:
            insn.itype = self._itype.movwp

            insn.Op1.type = idaapi.o_reg
            insn.Op1.reg = self._ireg.W0 + (code & 0x00000F)
            insn.Op1.dtyp = idaapi.dt_word

            insn.Op2.type = idaapi.o_displ
            insn.Op1.phrase = self._ireg.W0 + ((code & 0x000780) >> 7)
            insn.Op1.addr = (
                ((code & 0x038000) >> 11)
                + ((code & 0x003800) >> 8)
                + ((code & 0x000070) >> 4)
            ) * (-2 if code & 0x040000 else 2)
            insn.Op1.dtyp = idaapi.dt_word

            if code & 0x004000:  # B
                insn.Op2.addr //= 2
                insn.Op1.dtyp = idaapi.dt_byte
                insn.Op2.dtyp = idaapi.dt_byte
                insn.auxpref |= AUX_SZ_BYTE

        # MOV.B #lit8, Wnd
        # 1011 0011 1100 kkkk kkkk dddd
        elif code & 0xFFF000 == 0xB3C000:
            insn.itype = self._itype.movlbw

            insn.Op1.type = idaapi.o_imm
            insn.Op1.value = (code & 0x000FF0) >> 4
            insn.Op1.dtyp = idaapi.dt_byte

            insn.Op2.type = idaapi.o_reg
            insn.Op2.reg = self._ireg.W0 + (code & 0x00000F)
            insn.Op2.dtyp = idaapi.dt_byte

        # MOV{.B} WREG, f
        # 1011 0111 1B1f ffff ffff ffff
        elif code & 0xFF8000 == 0xB78000:
            insn.itype = self._itype.movwrf

            insn.Op1.type = idaapi.o_reg
            insn.Op1.reg = self._ireg.W0
            insn.Op1.specflag1 = OPS1_WREG
            insn.Op1.dtyp = idaapi.dt_word

            insn.Op2.type = idaapi.o_mem
            insn.Op2.addr = idaapi.map_data_ea(insn, code & 0x001FFF)
            insn.Op2.dtyp = idaapi.dt_word

            if code & 0x004000:  # B
                insn.Op1.dtyp = idaapi.dt_byte
                insn.Op2.dtyp = idaapi.dt_byte
                insn.auxpref |= AUX_SZ_BYTE

        # MOV{.B} f {,WREG}
        # 1011 1111 1BDf ffff ffff ffff
        elif code & 0xFF8000 == 0xBF8000:
            insn.itype = self._itype.movf

            insn.Op1.type = idaapi.o_mem
            insn.Op1.addr = idaapi.map_data_ea(insn, code & 0x001FFF)
            insn.Op1.dtyp = idaapi.dt_word

            if code & 0x004000:  # B
                insn.Op1.dtyp = idaapi.dt_byte
                insn.auxpref |= AUX_SZ_BYTE

            if code & 0x002000:  # D
                insn.itype = self._itype.movfwr
                insn.Op2.type = idaapi.o_reg
                insn.Op2.reg = self._ireg.W0
                insn.Op2.specflag1 = OPS1_WREG
                insn.Op2.dtyp = insn.Op1.dtyp

        else:
            self._decode_unknown(insn, code)

    def _decode_unknown(self, insn, code):
        insn.itype = self._itype.null

    def notify_ana(self, insn):
        code = insn_get_next_word(insn)
        high = code >> 20 & 0xF
        low = code >> 16 & 0xF

        if high == 0x2:
            self._decode_mov(insn, code)
        elif high == 0x7:
            if low & 0x8:
                self._decode_mov(insn, code)
            else:
                # TODO
                self._decode_unknown(insn, code)
        elif high == 0x8:
            self._decode_mov(insn, code)
        elif high == 0x9:
            self._decode_mov(insn, code)
        elif high == 0xB:
            # TODO
            if low == 0x3:
                if code & 0x008000:
                    self._decode_mov(insn, code)
                else:
                    # TODO
                    self._decode_unknown(insn, code)
            elif low == 0x7:
                if code & 0x008000:
                    self._decode_mov(insn, code)
                else:
                    # TODO
                    self._decode_unknown(insn, code)
            elif low == 0xF:
                self._decode_mov(insn, code)

        else:
            self._decode_unknown(insn, code)

        return insn.size #if insn.itype != self._itype.null else 0

    def notify_emu(self, insn):
        #idaapi.add_cref(insn.ea, insn.ea + insn.size, idaapi.fl_F)
        return 1

    def out_mnem(self, ctx):
        postfix = ""

        if ctx.insn.auxpref & AUX_SZ_BYTE:
            postfix = '.b'

        ctx.out_mnem(8, postfix)
        return 1

    def notify_out_operand(self, ctx, op):
        if op.type == idaapi.o_reg:
            ctx.out_register(self.reg_names[op.reg])

        elif op.type == idaapi.o_imm:
            ctx.out_symbol('#')
            ctx.out_value(op, idaapi.OOFW_IMM)

        elif op.type == idaapi.o_mem:
            ctx.out_value(op, idaapi.OOF_ADDR | idaapi.OOFW_24)

        elif op.type == idaapi.o_displ:
            ctx.out_symbol('[')
            ctx.out_register(self.reg_names[op.reg])
            ctx.out_symbol('+')
            ctx.out_value(op, idaapi.OOF_ADDR | idaapi.OOF_SIGNED)
            ctx.out_symbol(']')

        elif op.type == idaapi.o_phrase:
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

        if ctx.insn.ops[0].type != idaapi.o_void:
            ctx.out_one_operand(0)

        for idx in range(1, idaapi.UA_MAXOP):
            if ctx.insn.ops[idx].type == idaapi.o_void:
                break
            ctx.out_symbol(',')
            ctx.out_char(' ')
            ctx.out_one_operand(idx)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()


def PROCESSOR_ENTRY():
    return PIC24Processor()
