# Copyright 2018 Sam Hanes.
# This file is part of IDA-PIC24.
#
# IDA-PIC24 is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# IDA-PIC24 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the
# GNU Lesser General Public License along with IDA-PIC24.
# If not, see <https://www.gnu.org/licenses/>.


import idaapi as ida


###############################################################################
# Assembler Definitions                                                    {{{1
###############################################################################


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


###############################################################################
# Registers & Conditions                                                   {{{1
###############################################################################


class Enum(object):
    def __init__(self, items):
        for idx, item in enumerate(items):
            if item is not None:
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
    'A',  # ACCA
    'B',  # ACCB
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


conditions = [
    # branch conditions at 0x300000
    'OV',
    'C',
    'Z',
    'N',
    'LE',
    'LT',
    'LEU',
    None,
    'NOV',
    'NC',
    'NZ',
    'NN',
    'GT',
    'GE',
    'GTU',
    None,

    # branch conditions at 0x060000
    'OA',
    'OB',
    'SA',
    'SB',
]


icond = Enum(conditions)


###############################################################################
# Flags & Decoding Helpers                                                 {{{1
###############################################################################


def insn_get_next_word(insn):
    res = ida.get_wide_word(insn.ea + insn.size)
    insn.size += 2
    return res


o_cond = ida.o_idpspec0

IP_DOTB = 0x01
OPS1_WREG = 0x1

AUX_SZ_BYTE = 0x01


def mask_A_15(code):
    return (code & 0x008000) != 0


def mask_B_10(code):
    return (code & 0x000400) != 0


def mask_B_14(code):
    return (code & 0x004000) != 0


def mask_b_0(code):
    return ((code & 0x00E000) >> 12) | (code & 0x000001)


def mask_b_12(code):
    return (code & 0x00F000) >> 12


def mask_d_0(code):
    return code & 0x00000F


def mask_d_7(code):
    return (code & 0x000780) >> 7


def mask_f12_1(code):
    return (code & 0x001FFE) >> 1


def mask_f13_0(code):
    return code & 0x001FFF


def mask_f15_4(code):
    return (code & 0x07FFF0) >> 3


def mask_g_4(code):
    return (code & 0x000070) >> 4


def mask_h_11(code):
    return (code & 0x003800) >> 11


def mask_k4_0(code):
    return code & 0x00000F


def mask_k5_0(code):
    return code & 0x00001F


def mask_k8_0(code):
    return ((code & 0x00038) >> 2) | (code & 0x00001F)


def mask_k8_4(code):
    return (code & 0x000FF0) >> 4


def mask_k10_4(code):
    return (code & 0x003FF0) >> 4


def mask_k16_4(code):
    return (code & 0x0FFFF0) >> 4


def mask_lit23(code, data):
    return (code & 0x00FFFE) | ((data & 0x0000EF) << 16)


def mask_p_4(code):
    return (code & 0x000070) >> 4


def mask_q_11(code):
    return (code & 0x003800) >> 11


def mask_s_0(code):
    return code & 0x00000F


def mask_slit4_7(code):
    return (
        ((code & 0x000380) >> 7)
        * (-1 if (code & 0x000400) else 1)
    )


def mask_slit10_4(code):
    return (
        (
            ((code & 0x038000) >> 11)
            + ((code & 0x003800) >> 8)
            + ((code & 0x000070) >> 4)
        ) * (-2 if code & 0x040000 else 2)
    )


def mask_slit16_0(code):
    return (
        (code & 0x007FFF)
        * (-1 if (code & 0x008000) else 1)
    )


def mask_w_11(code):
    return (code & 0x007800) >> 11


def mask_w_15(code):
    return (code & 0x078000) >> 15


def set_op_imm(insn, op, value):
    insn.ops[op].type = ida.o_imm
    insn.ops[op].value = value
    insn.ops[op].dtyp = ida.dt_word


def set_op_reg(insn, op, reg):
    insn.ops[op].type = ida.o_reg
    insn.ops[op].reg = reg
    insn.ops[op].dtyp = ida.dt_word


def set_op_wreg(insn, op):
    insn.ops[op].type = ida.o_reg
    insn.ops[op].reg = ireg.W0
    insn.ops[op].specflag1 = OPS1_WREG
    insn.ops[op].dtyp = ida.dt_word


def set_op_mem(insn, op, addr):
    insn.ops[op].type = ida.o_mem
    insn.ops[op].addr = ida.map_data_ea(insn, addr)
    insn.ops[op].dtyp = ida.dt_word


def set_op_displ(insn, op, reg, displ):
    insn.ops[op].type = ida.o_displ
    insn.ops[op].reg = ireg.W0 + reg
    insn.ops[op].addr = displ
    insn.ops[op].dtyp = ida.dt_word


def set_op_phrase(insn, op, reg, mode, offset_reg):
    insn.ops[op].type = ida.o_phrase
    insn.ops[op].phrase = reg
    insn.ops[op].specflag3 = offset_reg
    insn.ops[op].specflag4 = mode
    insn.ops[op].dtyp = ida.dt_word


def set_op_near(insn, op, addr):
    insn.ops[op].type = ida.o_near
    insn.ops[op].addr = addr
    ida.map_code_ea(insn, insn.ops[op])


def set_op_cond(insn, op, cond):
    insn.ops[op].type = o_cond
    insn.ops[op].reg = cond


def set_op_near_rel(insn, op, offset):
    set_op_near(insn, op, insn.ea + insn.size + offset * 2)


def set_insn_byte(insn):
    for op in insn.ops:
        if op.type == ida.o_null:
            break
        if op.dtyp == ida.dt_word:
            op.dtyp = ida.dt_byte

    insn.auxpref |= AUX_SZ_BYTE


###############################################################################
# Instructions                                                             {{{1
###############################################################################


#######################################
# Abstract Instruction Classes     {{{2


class Instruction(object):
    feat = 0

    def __index__(self):
        return self.index

    def __int__(self):
        return self.index

    def decode(self, insn, code):
        insn.itype = self.index
        self._decode(insn, code)

    def _decode(self, insn, code):
        pass


class Instruction_f_wr_B(Instruction):
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        set_op_mem(insn, 0, mask_f13_0(code))
        set_op_wreg(insn, 1)
        if mask_B_14(code):
            set_insn_byte(insn)


class Instruction_f_B(Instruction):
    feat = ida.CF_CHG1

    def _decode(self, insn, code):
        set_op_mem(insn, 0, mask_f13_0(code))
        if mask_B_14(code):
            set_insn_byte(insn)


class Instruction_wr_B(Instruction):
    feat = ida.CF_CHG1

    def _decode(self, insn, code):
        set_op_wreg(insn, 0)
        if mask_B_14(code):
            set_insn_byte(insn)


class Instruction_wp_B(Instruction):
    feat = ida.CF_CHG1

    def _decode(self, insn, code):
        set_op_phrase(insn, 0, mask_d_7(code), mask_q_11(code), 0)
        if mask_B_14(code):
            set_insn_byte(insn)


class Instruction_l10_w_B(Instruction):
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        set_op_imm(insn, 0, mask_k10_4(code))
        set_op_reg(insn, 1, ireg.W0 + mask_d_0(code))
        if mask_B_14(code):
            set_insn_byte(insn)


class Instruction_w_l5_B(Instruction):
    feat = ida.CF_USE1 | ida.CF_USE2

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_w_11(code))
        set_op_imm(insn, 1, mask_k5_0(code))
        if mask_B_10(code):
            set_insn_byte(insn)


class Instruction_w_l8_B(Instruction):
    feat = ida.CF_USE1 | ida.CF_USE2

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_w_11(code))
        set_op_imm(insn, 0, mask_k8_0(code))
        if mask_B_10(code):
            set_insn_byte(insn)


class Instruction_w_wp_B(Instruction):
    feat = ida.CF_USE1 | ida.CF_USE2

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_w_11(code))
        set_op_phrase(insn, 1, mask_s_0(code), mask_p_4(code), 0)
        if mask_B_10(code):
            set_insn_byte(insn)


class Instruction_w_l5_wp_B(Instruction):
    feat = ida.CF_USE1 | ida.CF_USE2 | ida.CF_CHG3

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_w_15(code))
        set_op_imm(insn, 1, mask_k5_0(code))
        set_op_phrase(insn, 2, mask_d_7(code), mask_q_11(code), 0)
        if mask_B_14(code):
            set_insn_byte(insn)


class Instruction_w_wp_wp_B(Instruction):
    feat = ida.CF_USE1 | ida.CF_USE2 | ida.CF_CHG3

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_w_15(code))
        set_op_phrase(insn, 1, mask_s_0(code), mask_p_4(code), 0)
        set_op_phrase(insn, 2, mask_d_7(code), mask_q_11(code), 0)
        if mask_B_14(code):
            set_insn_byte(insn)


class Instruction_wp_wp_B(Instruction):
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        set_op_phrase(
            insn, 0,
            mask_s_0(code),
            mask_g_4(code),
            mask_w_15(code)
        )
        set_op_phrase(
            insn, 1,
            mask_d_7(code),
            mask_h_11(code),
            mask_w_15(code)
        )
        if mask_B_14(code):
            set_insn_byte(insn)


class Instruction_f_b_B(Instruction):
    feat = ida.CF_USE1 | ida.CF_CHG1

    def _decode(self, insn, code):
        set_op_mem(insn, 0, mask_f12_1(code))
        set_op_imm(insn, 1, mask_b_0(code))
        if insn.ops[1].value > 7:
            set_insn_byte(insn)


class Instruction_wp_b(Instruction):
    feat = ida.CF_USE1 | ida.CF_CHG1

    def _decode(self, insn, code):
        set_op_phrase(insn, 0, mask_s_0(code), mask_p_4(code), 0)
        set_op_imm(insn, 1, mask_b_12(code))


class Instruction_wp_b_B(Instruction):
    feat = ida.CF_USE1 | ida.CF_CHG1

    def _decode(self, insn, code):
        set_op_phrase(insn, 0, mask_s_0(code), mask_p_4(code), 0)
        set_op_imm(insn, 1, mask_b_12(code))
        if mask_B_10(code):
            set_insn_byte(insn)


class Instruction_wp_w(Instruction):
    feat = ida.CF_USE1 | ida.CF_CHG1 | ida.CF_USE2

    def _decode(self, insn, code):
        set_op_phrase(insn, 0, mask_s_0(code), mask_p_4(code), 0)
        set_op_reg(insn, 1, ireg.W0 + mask_w_11(code))


#######################################
# ADD                              {{{2


class I_add_f_wr(Instruction_f_wr_B):
    """ADD{.B} f, WREG"""
    name = 'add'
    mask = 0xFFA000
    code = 0xB40000


class I_add_f(Instruction_f_B):
    """ADD{.B} f"""
    name = 'add'
    mask = 0xFFA000
    code = 0xB44000


class I_add_l10_w(Instruction_l10_w_B):
    """ADD{.B} #lit10, Wn"""
    name = 'add'
    mask = 0xFF8000
    code = 0xB00000


class I_add_w_l5_wp(Instruction_w_l5_wp_B):
    """ADD{.B} Wb, #lit5, [Wd]"""
    name = 'add'
    mask = 0xF80060
    code = 0x400060


class I_add_w_wp_wp(Instruction_w_wp_wp_B):
    """ADD{.B} Wb [Ws], [Wd]"""
    name = 'add'
    mask = 0xF80000
    code = 0x400000


class I_add_a(Instruction):
    """ADD Acc"""
    name = 'add'
    mask = 0xFF7FFF
    code = 0xCB0000
    feat = ida.CF_CHG1

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.A if mask_A_15(code) else ireg.B)


class I_add_wp_a(Instruction):
    """ADD [Ws], Acc"""
    name = 'add'
    mask = 0xFF0700
    code = 0xC90000
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        set_op_phrase(
            insn, 0,
            mask_s_0(code),
            mask_g_4(code),
            mask_w_11(code)
        )
        set_op_reg(insn, 1, ireg.A if mask_A_15(code) else ireg.B)


class I_add_wp_sl4_a(Instruction):
    """ADD [Ws], {#Slit4,} Acc"""
    name = 'add'
    mask = 0xFF0000
    code = 0xC90000
    feat = ida.CF_USE1 | ida.CF_USE2 | ida.CF_CHG3

    def _decode(self, insn, code):
        set_op_phrase(
            insn, 0,
            mask_s_0(code),
            mask_g_4(code),
            mask_w_11(code)
        )
        set_op_imm(insn, 1, mask_slit4_7(code))
        set_op_reg(insn, 2, ireg.A if mask_A_15(code) else ireg.B)


class I_addc_f_wr(Instruction_f_wr_B):
    """ADDC{.B} f, WREG"""
    name = 'addc'
    mask = 0xFFA000
    code = 0xB48000


class I_addc_f(Instruction_f_B):
    """ADDC{.B} f"""
    name = 'addc'
    mask = 0xFFA000
    code = 0xB4A000


class I_addc_l10_w(Instruction_l10_w_B):
    """ADDC{.B} #lit10, Wn"""
    name = 'addc'
    mask = 0xFF8000
    code = 0xB08000


class I_addc_w_l5_wp(Instruction_w_l5_wp_B):
    """ADDC{.B} Wb, #lit5, [Wd]"""
    name = 'addc'
    mask = 0xF80060
    code = 0x480060


class I_addc_w_wp_wp(Instruction_w_wp_wp_B):
    """ADDC{.B} Wb, [Ws], [Wd]"""
    name = 'addc'
    mask = 0xF80000
    code = 0x480000


#######################################
# AND                              {{{2


class I_and_f_wr(Instruction_f_wr_B):
    """AND{.B} f, WREG"""
    name = 'and'
    mask = 0xFFA000
    code = 0xB60000


class I_and_f(Instruction_f_B):
    """AND{.B} f"""
    name = 'and'
    mask = 0xFFA000
    code = 0xB62000


class I_and_l10_w(Instruction_l10_w_B):
    """AND{.B} #lit10, Wn"""
    name = 'and'
    mask = 0xFF8000
    code = 0xB20000


class I_and_w_l5_wp(Instruction_w_l5_wp_B):
    """AND{.B} Wb, #lit5, [Wd]"""
    name = 'and'
    mask = 0xF80060
    code = 0x600060


class I_and_w_wp_wp(Instruction_w_wp_wp_B):
    """AND{.B} Wb, [Ws], [Wd]"""
    name = 'and'
    mask = 0xF80000
    code = 0x600000


#######################################
# ASR                              {{{2


class I_asr_f_wr(Instruction_f_wr_B):
    """ASR{.B} f, WREG"""
    name = 'asr'
    mask = 0xFFA000
    code = 0xD58000


class I_asr_f(Instruction_f_B):
    """ASR{.B} f"""
    name = 'asr'
    mask = 0xFFA000
    code = 0xD5A000


class I_asr_wp_wp(Instruction_wp_wp_B):
    """ASR{.B} [Ws], [Wd]"""
    name = 'asr'
    mask = 0xFF8000
    code = 0xD18000


class I_asr_w_l4_w(Instruction):
    """ASR Wb, #lit4, Wnd"""
    name = 'asr'
    mask = 0xFF8070
    code = 0xDE8040
    feat = ida.CF_USE1 | ida.CF_USE2 | ida.CF_CHG3

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_w_11(code))
        set_op_imm(insn, 1, mask_k4_0(code))
        set_op_reg(insn, 2, ireg.W0 + mask_d_7(code))


class I_asr_w_w_w(Instruction):
    """ASR Wb, Wns, Wnd"""
    name = 'asr'
    mask = 0xFF8070
    code = 0xDE8000
    feat = ida.CF_USE1 | ida.CF_USE2 | ida.CF_CHG3

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_w_11(code))
        set_op_reg(insn, 1, ireg.W0 + mask_s_0(code))
        set_op_reg(insn, 2, ireg.W0 + mask_d_7(code))


#######################################
# BCLR                             {{{2


class I_bclr_f_b(Instruction_f_b_B):
    """BCLR{.B} f, #bit4"""
    name = 'bclr'
    mask = 0xFF0000
    code = 0xA90000


class I_bclr_wp_b(Instruction_wp_b_B):
    """BCLR{.B} Ws, #bit4"""
    name = 'bclr'
    mask = 0xFF0B80
    code = 0xA10000


#######################################
# BRA                              {{{2


class I_bra_slit16(Instruction):
    """BRA Expr"""
    name = 'bra'
    mask = 0xFF0000
    code = 0x370000
    feat = ida.CF_USE1 | ida.CF_STOP

    def _decode(self, insn, code):
        set_op_near_rel(insn, 0, mask_slit16_0(code))


class I_bra_w(Instruction):
    """BRA Wn"""
    name = 'bra'
    mask = 0xFFFFF0
    code = 0x016000
    feat = ida.CF_USE1 | ida.CF_STOP | ida.CF_JUMP

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))


class I_bra_w_E(Instruction):
    """BRA Wn"""
    name = 'bra'
    mask = 0xFFFFF0
    code = 0x010600
    feat = ida.CF_USE1 | ida.CF_STOP | ida.CF_JUMP

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))


class I_bra_c_slit16(Instruction):
    """BRA Cond, Expr"""
    name = 'bra'
    mask = 0xF00000
    code = 0x300000
    feat = ida.CF_USE2

    def _decode(self, insn, code):
        set_op_cond(insn, 0, icond.OV + ((code & 0x0F0000) >> 16))
        set_op_near_rel(insn, 1, mask_slit16_0(code))


class I_bra_c_slit16_DSP(Instruction):
    """BRA Cond, Expr"""
    name = 'bra'
    mask = 0xFC0000
    code = 0x0C0000
    feat = ida.CF_USE2

    def _decode(self, insn, code):
        set_op_cond(insn, 0, icond.OA + ((code & 0x030000) >> 16))
        set_op_near_rel(insn, 1, mask_slit16_0(code))


#######################################
# BSET                             {{{2


class I_bset_f_b(Instruction_f_b_B):
    """BSET{.B} f, #bit4"""
    name = 'bset'
    mask = 0xFF0000
    code = 0xA80000


class I_bset_wp_b(Instruction_wp_b_B):
    """BSET{.B} Ws, #bit4"""
    name = 'bset'
    mask = 0xFF0B80
    code = 0xA00000


#######################################
# BSW                              {{{2


class I_bswc_wp_w(Instruction_wp_w):
    """BSW.C [Ws], Wb"""
    name = 'bsw.c'
    mask = 0xFF8780
    code = 0xAD0000


class I_bswz_wp_w(Instruction_wp_w):
    """BSW.Z [Ws], Wb"""
    name = 'bsw.z'
    mask = 0xFF8780
    code = 0xAD8000


#######################################
# BTG                              {{{2


class I_btg_f_b(Instruction_f_b_B):
    """BTG{.B} f, #bit4"""
    name = 'btg'
    mask = 0xFF0000
    code = 0xAA0000


class I_btg_wp_b(Instruction_wp_b_B):
    """BTG{.B} Ws, #bit4"""
    name = 'btg'
    mask = 0xFF0B80
    code = 0xA20000


#######################################
# BTSC                             {{{2


class I_btsc_f_b(Instruction_f_b_B):
    """BTSC{.B} f, #bit4"""
    name = 'btsc'
    mask = 0xFF0000
    code = 0xAF0000


class I_btsc_wp_b(Instruction_wp_b):
    """BTSC Ws, #bit4"""
    name = 'btsc'
    mask = 0xFF0F80
    code = 0xA70000


#######################################
# BTSS                             {{{2


class I_btss_f_b(Instruction_f_b_B):
    """BTSS{.B} f, #bit4"""
    name = 'btss'
    mask = 0xFF0000
    code = 0xAE0000


class I_btss_wp_b(Instruction_wp_b):
    """BTSS Ws, #bit4"""
    name = 'btss'
    mask = 0xFF0F80
    code = 0xA60000


#######################################
# BTST                             {{{2


class I_btst_f_b(Instruction_f_b_B):
    """BTST{.B} f, #bit4"""
    name = 'btst'
    mask = 0xFF0000
    code = 0xAB0000
    feat = ida.CF_USE1


class I_btstc_wp_b(Instruction_wp_b):
    """BTST.C Ws, #bit4"""
    name = 'btst.c'
    mask = 0xFF0780
    code = 0xA30000
    feat = ida.CF_USE1


class I_btstz_wp_b(Instruction_wp_b):
    """BTST.Z Ws, #bit4"""
    name = 'btst.z'
    mask = 0xFF0780
    code = 0xA30800
    feat = ida.CF_USE1


class I_btstc_wp_w(Instruction_wp_w):
    """BTST.C Ws, Wb"""
    name = 'btst.c'
    mask = 0xFF8780
    code = 0xA50000
    feat = ida.CF_USE1 | ida.CF_USE2


class I_btstz_wp_w(Instruction_wp_w):
    """BTST.Z Ws, Wb"""
    name = 'btst.z'
    mask = 0xFF8780
    code = 0xA58000
    feat = ida.CF_USE1 | ida.CF_USE2


#######################################
# BTSTS                            {{{2


class I_btsts_f_b(Instruction_f_b_B):
    """BTSTS{.B} f, #bit4"""
    name = 'btsts'
    mask = 0xFF0000
    code = 0xAC0000


class I_btstsc_wp_b(Instruction_wp_b):
    """BTSTS.C Ws, #bit4"""
    name = 'btsts.c'
    mask = 0xFF0F80
    code = 0xA40000


class I_btstsz_wp_b(Instruction_wp_b):
    """BTSTS.Z Ws, #bit4"""
    name = 'btsts.z'
    mask = 0xFF0F80
    code = 0xA40800


#######################################
# CALL                             {{{2


class I_call_l23(Instruction):
    """CALL Expr"""
    name = 'call'
    mask = 0xFF0000
    code = 0x020000
    feat = ida.CF_USE1 | ida.CF_CALL

    def _decode(self, insn, code):
        data = insn_get_next_word(insn)
        set_op_near(insn, 0, mask_lit23(code, data))


class I_call_w(Instruction):
    """CALL Wn"""
    name = 'call'
    mask = 0xFFFFF0
    code = 0x010000
    feat = ida.CF_USE1 | ida.CF_CALL | ida.CF_JUMP

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))


class I_calll_w(Instruction):
    """CALL.L Wn"""
    name = 'call.l'
    mask = 0xFF87F0
    code = 0x018000
    feat = ida.CF_USE1 | ida.CF_CALL | ida.CF_JUMP

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))


#######################################
# CLR                              {{{2


class I_clr_wr(Instruction_wr_B):
    """CLR{.B} WREG"""
    name = 'clr'
    mask = 0xFFA000
    code = 0xEF0000


class I_clr_f(Instruction_f_B):
    """CLR{.B} f"""
    name = 'clr'
    mask = 0xFFA000
    code = 0xEF2000


class I_clr_wp(Instruction_wp_B):
    """CLR{.B} Wd"""
    name = 'clr'
    mask = 0xFF807F
    code = 0xEB0000


# TODO: missing dsPIC opcode
# CLR Acc {,[Wx],Wxd} {,[Wy],Wyd} {,AWB}
# DS70157F page 186


#######################################
# CLRWDT                           {{{2


class I_clrwdt(Instruction):
    """CLRWDT"""
    name = 'clrwdt'
    mask = 0xFFFFFF
    code = 0xFE6000


#######################################
# COM                              {{{2


class I_com_f_wr(Instruction_f_wr_B):
    """COM{.B} f"""
    name = 'com'
    mask = 0xFFA000
    code = 0xEE8000


class I_com_f(Instruction_f_B):
    """COM{.B} f"""
    name = 'com'
    mask = 0xFFA000
    code = 0xEEA000


class I_com_wp_wp(Instruction_wp_wp_B):
    """COM{.B} [Ws], [Wd]"""
    name = 'com'
    mask = 0xFF8000
    code = 0xEA8000


#######################################
# CP                               {{{2


class I_cp_f(Instruction_f_B):
    """CP{.B} f"""
    name = 'cp'
    mask = 0xFFA000
    code = 0xE30000
    feat = ida.CF_USE1


class I_cp_w_l5(Instruction_w_l5_B):
    """CP{.B} f"""
    name = 'cp'
    mask = 0xFF83E0
    code = 0xE10060
    feat = ida.CF_USE1


class I_cp_w_l8(Instruction_w_l8_B):
    """CP{.B} f"""
    name = 'cp'
    mask = 0xFF8060
    code = 0xE10060
    feat = ida.CF_USE1


class I_cp_w_wp(Instruction_w_wp_B):
    """CP{.B} Wb, [Ws]"""
    name = 'cp'
    mask = 0xFF8380
    code = 0xE10000
    feat = ida.CF_USE1 | ida.CF_USE2


#######################################
# CP0                              {{{2


class I_cp0_f(Instruction_f_B):
    """CP0{.B} f"""
    name = 'cp0'
    mask = 0xFFA000
    code = 0xE20000
    feat = ida.CF_USE1


class I_cp0_wp(Instruction_wp_B):
    """CP0{.B} [Ws]"""
    name = 'cp0'
    mask = 0xFFFB80
    code = 0xE00000
    feat = ida.CF_USE1


#######################################
# CPB                              {{{2


class I_cpb_f(Instruction_f_B):
    """CPB{.B} f"""
    name = 'cpb'
    mask = 0xFFA000
    code = 0xE38000
    feat = ida.CF_USE1


class I_cpb_w_l5(Instruction_w_l5_B):
    """CPB{.B} Wb, #lit5"""
    name = 'cpb'
    mask = 0xFF83E0
    code = 0xE18060
    feat = ida.CF_USE1


class I_cpb_w_l8(Instruction_w_l8_B):
    """CPB{.B} Wb, #lit8"""
    name = 'cpb'
    mask = 0xFF8060
    code = 0xE18060
    feat = ida.CF_USE1


class I_cpb_w_wp(Instruction_w_wp_B):
    """CPB{.B} Wb, [Ws]"""
    name = 'cpb'
    mask = 0xFF8380
    code = 0xE18000
    feat = ida.CF_USE1 | ida.CF_USE2


#######################################
# GOTO                             {{{2


class I_goto_l23(Instruction):
    """GOTO Expr"""
    name = 'goto'
    mask = 0xFF0000
    code = 0x040000
    feat = ida.CF_USE1 | ida.CF_STOP

    def _decode(self, insn, code):
        data = insn_get_next_word(insn)
        set_op_near(insn, 0, mask_lit23(code, data))


class I_goto_w(Instruction):
    """GOTO Wn"""
    name = 'goto'
    mask = 0xFFFFF0
    code = 0x014000
    feat = ida.CF_USE1 | ida.CF_STOP | ida.CF_JUMP

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))


class I_goto_w_E(Instruction):
    """GOTO Wn"""
    name = 'goto'
    mask = 0xFFFFF0
    code = 0x010400
    feat = ida.CF_USE1 | ida.CF_STOP | ida.CF_JUMP

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))


class I_gotol_w(Instruction):
    """GOTO.L Wn"""
    name = 'goto.l'
    mask = 0xFF87F0
    code = 0x018400
    feat = ida.CF_USE1 | ida.CF_STOP | ida.CF_JUMP

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))


#######################################
# MOV                              {{{2


class I_mov_f_wr(Instruction_f_wr_B):
    """MOV{.B} f, WREG"""
    name = 'mov'
    mask = 0xFFA000
    code = 0xBF8000


class I_mov_f(Instruction_f_B):
    """MOV{.B} f"""
    name = 'mov'
    mask = 0xFFA000
    code = 0xBFA000


class I_mov_wr_f(Instruction):
    """MOV{.B} WREG, f"""
    name = 'mov'
    mask = 0xFF8000
    code = 0xB78000
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        set_op_wreg(insn, 0)
        set_op_mem(insn, 1, mask_f13_0(code))
        if mask_B_14(code):
            set_insn_byte(insn)


class I_mov_f_w(Instruction):
    """MOV f, Wnd"""
    name = 'mov'
    mask = 0xF80000
    code = 0x800000
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        set_op_mem(insn, 0, mask_f15_4(code))
        set_op_reg(insn, 1, ireg.W0 + mask_d_0(code))


class I_mov_w_f(Instruction):
    """MOV Wns, f"""
    name = 'mov'
    mask = 0xF80000
    code = 0x880000
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))
        set_op_mem(insn, 1, mask_f15_4(code))


class I_mov_l8_w(Instruction):
    """MOV.B #lit8, Wnd"""
    name = 'mov'
    mask = 0xFFF000
    code = 0xB3C000
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        set_op_imm(insn, 0, mask_k8_4(code))
        set_op_reg(insn, 1, ireg.W0 + mask_d_0(code))
        set_insn_byte(insn)


class I_mov_l16_w(Instruction):
    """MOV #lit16, Wnd"""
    name = 'mov'
    mask = 0xF00000
    code = 0x200000
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        set_op_imm(insn, 0, mask_k16_4(code))
        set_op_reg(insn, 1, ireg.W0 + mask_d_0(code))


class I_mov_wso_w(Instruction):
    """MOV{.B} [Ws + Slit10], Wnd"""
    name = 'mov'
    mask = 0xF80000
    code = 0x900000
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        set_op_displ(insn, 0, mask_s_0(code), mask_slit10_4(code))
        set_op_reg(insn, 1, ireg.W0 + mask_d_7(code))
        if mask_B_14(code):
            set_insn_byte(insn)
            insn.ops[0].addr //= 2


class I_mov_w_wso(Instruction):
    """MOV{.B} Wns, [Wd + Slit10]"""
    name = 'mov'
    mask = 0xF80000
    code = 0x980000
    feat = ida.CF_USE1 | ida.CF_CHG2

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))
        set_op_displ(insn, 1, mask_d_7(code), mask_slit10_4(code))
        if mask_B_14(code):
            set_insn_byte(insn)
            insn.Op2.addr //= 2


class I_mov_wp_wp(Instruction_wp_wp_B):
    """MOV{.B} Ws, Wd"""
    name = 'mov'
    mask = 0xF80000
    code = 0x780000


#######################################
# NOP                              {{{2


class I_nop(Instruction):
    """NOP"""
    name = 'nop'
    mask = 0xFF0000
    code = 0x000000


class I_nopr(Instruction):
    """NOPR"""
    name = 'nopr'
    mask = 0xFF0000
    code = 0xFF0000


#######################################
# RCALL                            {{{2


class I_rcall_slit16(Instruction):
    """RCALL Expr"""
    name = 'rcall'
    mask = 0xFF0000
    code = 0x070000
    feat = ida.CF_USE1 | ida.CF_CALL

    def _decode(self, insn, code):
        set_op_near_rel(insn, 0, mask_slit16_0(code))


class I_rcall_w(Instruction):
    """RCALL Wn"""
    name = 'rcall'
    mask = 0xFFFFF0
    code = 0x014000
    feat = ida.CF_USE1 | ida.CF_CALL | ida.CF_JUMP

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))


class I_rcall_w_E(Instruction):
    """RCALL Wn"""
    name = 'rcall'
    mask = 0xFFFFF0
    code = 0x010400
    feat = ida.CF_USE1 | ida.CF_CALL | ida.CF_JUMP

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))


#######################################
# Decode Map                       {{{2


class InstructionMatcher(object):
    def __init__(self):
        self.instructions = []

    def add(self, instruction):
        self.instructions.append(instruction)

    def decode(self, insn, code):
        for inst in self.instructions:
            if code & inst.mask == inst.code:
                return inst.decode(insn, code)


instructions = []
decode_map = list([InstructionMatcher() for idx in range(0, 256)])


def build_decode_map(parent):
    children = parent.__subclasses__()
    if children:
        for child in children:
            build_decode_map(child)
    else:
        inst = parent()
        instructions.append(inst)

        # this assumes that the mask is a strict prefix
        op_mask = (inst.mask >> 16) & 0xFF
        op_code = (inst.code >> 16) & 0xFF
        op_high = (op_code | ~op_mask) & 0xFF
        for op in range(op_code, op_high + 1):
            decode_map[op].add(inst)


build_decode_map(Instruction)


ida_instructions = [
    # invalid instruction
    # must be index 0 so uninitialized insn_t uses it
    {'name': '', 'feature': 0},
]

for idx, itype in enumerate(instructions, 1):
    setattr(itype, 'index', idx)

    ida_instructions.append({
        'name': itype.name,
        'feature': itype.feat,
    })


###############################################################################
# Processor Class                                                          {{{1
###############################################################################


class PIC24Processor(ida.processor_t):
    id = 0x8000 + 24

    flag = (
        ida.PR_USE32   # use 32-bit (as opposed to 16-bit) addresses
        | ida.PRN_HEX  # show numbers in hex by default
        | ida.PR_NO_SEGMOVE  # we don't support move_segm()
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

    segreg_size = 1
    reg_first_sreg = ireg.TBLPAG
    reg_last_sreg = ireg.DS
    reg_code_sreg = ireg.CS
    reg_data_sreg = ireg.DS

    instruc = ida_instructions
    instruc_start = 0
    instruc_end = len(instruc) + 1

    def notify_ana(self, insn):
        code = insn_get_next_word(insn)
        decode_map[(code >> 16) & 0xFF].decode(insn, code)
        return insn.size if insn.itype != 0 else 0

    def _emu_operand(self, insn, op, is_write):
        feat = insn.get_canon_feature()
        dref_flag = ida.dr_W if is_write else ida.dr_R

        if op.type == ida.o_mem:
            # create data xrefs
            insn.create_op_data(op.addr, op)
            insn.add_dref(op.addr, op.offb, dref_flag)

        elif op.type == ida.o_near:
            # create code xrefs
            insn.add_cref(
                op.addr, op.offb,
                (ida.fl_CN if (feat & ida.CF_CALL) else ida.fl_JN)
            )

    def notify_emu(self, insn):
        feat = insn.get_canon_feature()

        for idx in range(0, ida.UA_MAXOP):
            op = insn.ops[idx]
            if op.type == ida.o_void:
                break
            if (feat & getattr(ida, 'CF_USE' + str(idx + 1))) != 0:
                self._emu_operand(insn, op, False)
            if (feat & getattr(ida, 'CF_CHG' + str(idx + 1))) != 0:
                self._emu_operand(insn, op, True)

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

        elif op.type in [ida.o_mem, ida.o_near]:
            if not ctx.out_name_expr(op, op.addr):
                ctx.out_tagon(ida.COLOR_ERROR)
                ctx.out_value(op, ida.OOF_ADDR)
                ctx.out_tagoff(ida.COLOR_ERROR)
                ida.remember_problem(ida.PR_NONAME, ctx.insn.ea)

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

        elif op.type == o_cond:
            ctx.out_register(conditions[op.reg])

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
