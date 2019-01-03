# vim:ft=python:sts=4:sw=4:et:fdm=marker:
#
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


from collections import namedtuple
import re
import sys

import idaapi


###############################################################################
# Assembler Definitions                                                    {{{1
###############################################################################


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
# SFR Configuration                                                        {{{1
###############################################################################


class ReMatcher(object):
    def __init__(self, string):
        self.string = string
        self.match = None

    def __call__(self, pattern):
        self.match = pattern.match(self.string)
        return self.match

    def __getattr__(self, name):
        return getattr(self.match, name)


class Config(object):
    RE_IGNORE = re.compile(r'^\s+|^\s*;')
    RE_DEFAULT = re.compile(r'^ \.default \s+ (\S+)', re.I | re.X)
    RE_DEVICE = re.compile(r'^ \. (\S+)', re.X)
    RE_PORT = re.compile(
        r'''^   ([^\s.]+)
            \s+ (0x[0-9a-f]+|[0-9]+)
        ''',
        re.I | re.X,
    )
    RE_BIT = re.compile(
        r'''^   ([^\s.]+)
            \.  ([^\s.]+)
            \s+ (0x[0-9a-f]+|[0-9]+)
        ''',
        re.I | re.X,
    )
    RE_AREA = re.compile(
        r'''^   area
            \s+ (\S+)
            \s+ (\S+)
            \s+ (0x[0-9a-f]+|[0-9]+)
            :   (0x[0-9a-f]+|[0-9]+)
            \s+ (.*) $
        ''',
        re.I | re.X,
    )

    Port = namedtuple('Port', [
        'name',
        'addr',
        'bits_by_name',
        'bits_by_addr',
    ])

    Device = namedtuple('Device', [
        'name',
        'areas',
    ])

    Area = namedtuple('Area', [
        'cls',
        'name',
        'start',
        'end',
        'desc',
    ])

    _ports_by_name = {}
    _ports_by_addr = {}
    _devices = {}
    _default = None

    def read(self, stream):
        device = None
        for line in stream:
            match = ReMatcher(line)

            if match(self.RE_IGNORE):
                pass

            elif not device and match(self.RE_DEFAULT):
                if self._default is not None:
                    raise Exception('duplicate .default')

                self._default = match.group(1)

            elif match(self.RE_DEVICE):
                device = self.Device(
                    name=match.group(1),
                    areas=[],
                )
                self._devices[device.name] = device

            elif not device and match(self.RE_PORT):
                port = self.Port(
                    name=match.group(1),
                    addr=int(match.group(2), 0),
                    bits_by_name={},
                    bits_by_addr={},
                )
                self._ports_by_name[port.name] = port
                self._ports_by_addr[port.addr] = port

            elif not device and match(self.RE_BIT):
                port_name, name, addr = match.groups()
                if port_name not in self._ports_by_name:
                    raise Exception('found bit for undeclared port')

                addr = int(addr, 0)
                port = self._ports_by_name[port_name]
                port.bits_by_name[name] = addr
                port.bits_by_addr[addr] = name

            elif device and match(self.RE_AREA):
                name = match.group(2)
                device.areas.append(self.Area(
                    cls=match.group(1),
                    name=name,
                    start=int(match.group(3), 0),
                    end=int(match.group(4), 0),
                    desc=match.group(5),
                ))

            else:
                raise Exception('invalid config line')

        if self._default is None:
            raise Exception('.default is required')
        elif self._default not in self._devices:
            raise Exception('unsupported value for .default')

    def select_device(self, device=None):
        if device is None:
            self._device = self._devices[self._default]
        elif device in self.devices:
            self._device = self._devices[device]
        else:
            raise Exception('unsupported device name')

    def find_port(self, addr):
        if addr in self._ports_by_addr:
            return self._ports_by_addr[addr]
        return None

    def find_port_name(self, addr):
        if addr in self._ports_by_addr:
            return self._ports_by_addr[addr].name
        return None

    def find_bit_name(self, addr, bit):
        if addr not in self._ports_by_addr:
            return None

        port = self._ports_by_addr[addr]
        if bit not in port.bits_by_addr:
            return None

        return port.bits_by_addr[bit]

    @property
    def areas(self):
        return self._device.areas

    @property
    def ports(self):
        return self._ports_by_addr.values()


###############################################################################
# Flags & Decoding Helpers                                                 {{{1
###############################################################################


def insn_get_next_word(insn):
    res = idaapi.get_wide_word(insn.ea + insn.size)
    insn.size += 2
    return res


o_cond = idaapi.o_idpspec0

OPS1_WREG = 0x1

AUX_SZ_BYTE = 0x01
AUX_SZ_DWORD = 0x02


def mask_A_15(code):
    return (code & 0x008000) != 0


def mask_B_10(code):
    return (code & 0x000400) != 0


def mask_B_14(code):
    return (code & 0x004000) != 0


def mask_b_0(code):
    return ((code & 0x00E000) >> 13) | ((code & 0x000001) << 3)


def mask_b_12(code):
    return (code & 0x00F000) >> 12


def mask_d_0(code):
    return code & 0x00000F


def mask_d_7(code):
    return (code & 0x000780) >> 7


def mask_f12_1(code):
    return code & 0x001FFE


def mask_f13_0(code):
    return code & 0x001FFF


def mask_f15_4(code):
    return (code & 0x07FFF0) >> 3


def mask_f16_0(code):
    return code & 0x00FFFF


def mask_g_4(code):
    return (code & 0x000070) >> 4


def mask_h_11(code):
    return (code & 0x003800) >> 11


def mask_k1_0(code):
    return code & 0x000001


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


def mask_k14_0(code):
    return code & 0x003FFF


def mask_k16_4(code):
    return (code & 0x0FFFF0) >> 4


def mask_lit14(code):
    return code & 0x003FFF


def mask_lit23(code, data):
    return (code & 0x00FFFE) | ((data & 0x0000EF) << 16)


def mask_p_4(code):
    return (code & 0x000070) >> 4


def mask_q_11(code):
    return (code & 0x003800) >> 11


def mask_s_0(code):
    return code & 0x00000F


def mask_slit4_7(code):
    value = ((code & 0x000780) >> 7)
    if value > 0x07:
        value -= 0x10
    return value


def mask_slit10_4(code):
    value = (
        ((code & 0x078000) >> 9)
        + ((code & 0x003800) >> 8)
        + ((code & 0x000070) >> 4)
    )
    if value > 0x01FF:
        value -= 0x0400
    return value


def mask_slit16_0(code):
    value = code & 0x00FFFF
    if value > 0x7FFF:
        value -= 0x010000
    return value


def mask_v_7(code):
    return (code & 0x000780) >> 7


def mask_w_0(code):
    return code & 0x00000F


def mask_w_11(code):
    return (code & 0x007800) >> 11


def mask_w_15(code):
    return (code & 0x078000) >> 15


def mask_W_6(code):
    return (code & 0x000040) != 0


def set_op_imm(insn, op, value):
    insn.ops[op].type = idaapi.o_imm
    insn.ops[op].value = value
    insn.ops[op].dtyp = idaapi.dt_word


def set_op_reg(insn, op, reg):
    insn.ops[op].type = idaapi.o_reg
    insn.ops[op].reg = reg
    insn.ops[op].dtyp = idaapi.dt_word


def set_op_wreg(insn, op):
    insn.ops[op].type = idaapi.o_reg
    insn.ops[op].reg = ireg.W0
    insn.ops[op].specflag1 = OPS1_WREG
    insn.ops[op].dtyp = idaapi.dt_word


def set_op_mem(insn, op, addr):
    insn.ops[op].type = idaapi.o_mem
    insn.ops[op].addr = addr
    insn.ops[op].dtyp = idaapi.dt_word


def set_op_displ(insn, op, reg, displ):
    insn.ops[op].type = idaapi.o_displ
    insn.ops[op].reg = ireg.W0 + reg
    insn.ops[op].addr = displ
    insn.ops[op].dtyp = idaapi.dt_word


def set_op_phrase(insn, op, reg, mode, offset_reg):
    insn.ops[op].type = idaapi.o_phrase
    insn.ops[op].phrase = reg
    insn.ops[op].specflag3 = offset_reg
    insn.ops[op].specflag4 = mode
    insn.ops[op].dtyp = idaapi.dt_word


def set_op_near(insn, op, addr):
    insn.ops[op].type = idaapi.o_near
    insn.ops[op].addr = addr


def set_op_cond(insn, op, cond):
    insn.ops[op].type = o_cond
    insn.ops[op].reg = cond


def set_op_near_rel(insn, op, offset):
    set_op_near(insn, op, insn.ea + insn.size + offset * 2)


def set_insn_byte(insn):
    for op in insn.ops:
        if op.type == idaapi.o_void:
            break
        if op.dtyp == idaapi.dt_word:
            op.dtyp = idaapi.dt_byte

    insn.auxpref |= AUX_SZ_BYTE


###############################################################################
# Instructions                                                             {{{1
###############################################################################


#######################################
# Abstract Instruction Classes     {{{2


class Instruction(object):
    feat = 0
    is_bit = False

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
    feat = idaapi.CF_USE1 | idaapi.CF_CHG2

    def _decode(self, insn, code):
        set_op_mem(insn, 0, mask_f13_0(code))
        set_op_wreg(insn, 1)
        if mask_B_14(code):
            set_insn_byte(insn)


class Instruction_f_B(Instruction):
    feat = idaapi.CF_CHG1

    def _decode(self, insn, code):
        set_op_mem(insn, 0, mask_f13_0(code))
        if mask_B_14(code):
            set_insn_byte(insn)


class Instruction_wr_B(Instruction):
    feat = idaapi.CF_CHG1

    def _decode(self, insn, code):
        set_op_wreg(insn, 0)
        if mask_B_14(code):
            set_insn_byte(insn)


class Instruction_wp_B(Instruction):
    feat = idaapi.CF_CHG1

    def _decode(self, insn, code):
        set_op_phrase(insn, 0, mask_d_7(code), mask_q_11(code), 0)
        if mask_B_14(code):
            set_insn_byte(insn)


class Instruction_l10_w_B(Instruction):
    feat = idaapi.CF_USE1 | idaapi.CF_CHG2

    def _decode(self, insn, code):
        set_op_imm(insn, 0, mask_k10_4(code))
        set_op_reg(insn, 1, ireg.W0 + mask_d_0(code))
        if mask_B_14(code):
            set_insn_byte(insn)


class Instruction_w_l5_B(Instruction):
    feat = idaapi.CF_USE1 | idaapi.CF_USE2

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_w_11(code))
        set_op_imm(insn, 1, mask_k5_0(code))
        if mask_B_10(code):
            set_insn_byte(insn)


class Instruction_w_l8_B(Instruction):
    feat = idaapi.CF_USE1 | idaapi.CF_USE2

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_w_11(code))
        set_op_imm(insn, 0, mask_k8_0(code))
        if mask_B_10(code):
            set_insn_byte(insn)


class Instruction_w_wp_B(Instruction):
    feat = idaapi.CF_USE1 | idaapi.CF_USE2

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_w_11(code))
        set_op_phrase(insn, 1, mask_s_0(code), mask_p_4(code), 0)
        if mask_B_10(code):
            set_insn_byte(insn)


class Instruction_w_wp_w(Instruction):
    feat = idaapi.CF_USE1 | idaapi.CF_USE2 | idaapi.CF_CHG3

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_w_11(code))
        set_op_phrase(insn, 1, mask_s_0(code), mask_p_4(code), 0)
        set_op_reg(insn, 2, ireg.W0 + mask_d_7(code))


class Instruction_w_l5_wp_B(Instruction):
    feat = idaapi.CF_USE1 | idaapi.CF_USE2 | idaapi.CF_CHG3

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_w_15(code))
        set_op_imm(insn, 1, mask_k5_0(code))
        set_op_phrase(insn, 2, mask_d_7(code), mask_q_11(code), 0)
        if mask_B_14(code):
            set_insn_byte(insn)


class Instruction_w_l5_w(Instruction):
    feat = idaapi.CF_USE1 | idaapi.CF_USE2 | idaapi.CF_CHG3

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_w_11(code))
        set_op_imm(insn, 1, mask_k5_0(code))
        set_op_reg(insn, 2, ireg.W0 + mask_d_7(code))


class Instruction_w_l4_w(Instruction):
    feat = idaapi.CF_USE1 | idaapi.CF_CHG3

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_w_11(code))
        set_op_imm(insn, 1, mask_k4_0(code))
        set_op_reg(insn, 2, ireg.W0 + mask_d_7(code))


class Instruction_w_w_w(Instruction):
    feat = idaapi.CF_USE1 | idaapi.CF_USE2 | idaapi.CF_CHG3

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_w_11(code))
        set_op_reg(insn, 1, ireg.W0 + mask_s_0(code))
        set_op_reg(insn, 2, ireg.W0 + mask_d_7(code))


class Instruction_w_wp_wp_B(Instruction):
    feat = idaapi.CF_USE1 | idaapi.CF_USE2 | idaapi.CF_CHG3

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_w_15(code))
        set_op_phrase(insn, 1, mask_s_0(code), mask_p_4(code), 0)
        set_op_phrase(insn, 2, mask_d_7(code), mask_q_11(code), 0)
        if mask_B_14(code):
            set_insn_byte(insn)


class Instruction_wp_wp_B(Instruction):
    feat = idaapi.CF_USE1 | idaapi.CF_CHG2

    def _decode(self, insn, code):
        set_op_phrase(insn, 0, mask_s_0(code), mask_p_4(code), 0)
        set_op_phrase(insn, 1, mask_d_7(code), mask_q_11(code), 0)
        if mask_B_14(code):
            set_insn_byte(insn)


class Instruction_wpo_wpo_B(Instruction):
    feat = idaapi.CF_USE1 | idaapi.CF_CHG2

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
    feat = idaapi.CF_USE1 | idaapi.CF_CHG1

    def _decode(self, insn, code):
        set_op_mem(insn, 0, mask_f12_1(code))
        set_op_imm(insn, 1, mask_b_0(code))
        if insn.ops[1].value < 8:
            set_insn_byte(insn)


class Instruction_wp_b(Instruction):
    feat = idaapi.CF_USE1 | idaapi.CF_CHG1

    def _decode(self, insn, code):
        set_op_phrase(insn, 0, mask_s_0(code), mask_p_4(code), 0)
        set_op_imm(insn, 1, mask_b_12(code))


class Instruction_wp_b_B(Instruction):
    feat = idaapi.CF_USE1 | idaapi.CF_CHG1

    def _decode(self, insn, code):
        set_op_phrase(insn, 0, mask_s_0(code), mask_p_4(code), 0)
        set_op_imm(insn, 1, mask_b_12(code))
        if mask_B_10(code):
            set_insn_byte(insn)


class Instruction_wp_w(Instruction):
    feat = idaapi.CF_USE1 | idaapi.CF_CHG1 | idaapi.CF_USE2

    def _decode(self, insn, code):
        set_op_phrase(insn, 0, mask_s_0(code), mask_p_4(code), 0)
        set_op_reg(insn, 1, ireg.W0 + mask_w_11(code))


class Instruction_w_w_B(Instruction):
    feat = idaapi.CF_USE1 | idaapi.CF_USE2

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_w_11(code))
        set_op_reg(insn, 1, ireg.W0 + mask_w_0(code))
        if mask_B_10(code):
            set_insn_byte(insn)


class Instruction_w_w_W(Instruction):
    feat = idaapi.CF_USE1 | idaapi.CF_USE2

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_v_7(code))
        set_op_reg(insn, 1, ireg.W0 + mask_s_0(code))
        if mask_W_6(code):
            insn.ops[0].dtype = idaapi.dt_dword
            insn.auxpref |= AUX_SZ_DWORD


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
    feat = idaapi.CF_CHG1

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.A if mask_A_15(code) else ireg.B)


class I_add_wp_a(Instruction):
    """ADD [Ws], Acc"""
    name = 'add'
    mask = 0xFF0700
    code = 0xC90000
    feat = idaapi.CF_USE1 | idaapi.CF_CHG2

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
    feat = idaapi.CF_USE1 | idaapi.CF_USE2 | idaapi.CF_CHG3

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
    feat = idaapi.CF_USE1 | idaapi.CF_USE2 | idaapi.CF_CHG3

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_w_11(code))
        set_op_imm(insn, 1, mask_k4_0(code))
        set_op_reg(insn, 2, ireg.W0 + mask_d_7(code))


class I_asr_w_w_w(Instruction):
    """ASR Wb, Wns, Wnd"""
    name = 'asr'
    mask = 0xFF8070
    code = 0xDE8000
    feat = idaapi.CF_USE1 | idaapi.CF_USE2 | idaapi.CF_CHG3

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
    is_bit = True


class I_bclr_wp_b(Instruction_wp_b_B):
    """BCLR{.B} Ws, #bit4"""
    name = 'bclr'
    mask = 0xFF0B80
    code = 0xA10000
    is_bit = True


#######################################
# BRA                              {{{2


class I_bra_slit16(Instruction):
    """BRA Expr"""
    name = 'bra'
    mask = 0xFF0000
    code = 0x370000
    feat = idaapi.CF_USE1 | idaapi.CF_STOP

    def _decode(self, insn, code):
        set_op_near_rel(insn, 0, mask_slit16_0(code))


class I_bra_w(Instruction):
    """BRA Wn"""
    name = 'bra'
    mask = 0xFFFFF0
    code = 0x016000
    feat = idaapi.CF_USE1 | idaapi.CF_STOP | idaapi.CF_JUMP

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))


class I_bra_w_E(Instruction):
    """BRA Wn"""
    name = 'bra'
    mask = 0xFFFFF0
    code = 0x010600
    feat = idaapi.CF_USE1 | idaapi.CF_STOP | idaapi.CF_JUMP

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))


class I_bra_c_slit16(Instruction):
    """BRA Cond, Expr"""
    name = 'bra'
    mask = 0xF00000
    code = 0x300000
    feat = idaapi.CF_USE2

    def _decode(self, insn, code):
        set_op_cond(insn, 0, icond.OV + ((code & 0x0F0000) >> 16))
        set_op_near_rel(insn, 1, mask_slit16_0(code))


class I_bra_c_slit16_DSP(Instruction):
    """BRA Cond, Expr"""
    name = 'bra'
    mask = 0xFC0000
    code = 0x0C0000
    feat = idaapi.CF_USE2

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
    is_bit = True


class I_bset_wp_b(Instruction_wp_b_B):
    """BSET{.B} Ws, #bit4"""
    name = 'bset'
    mask = 0xFF0B80
    code = 0xA00000
    is_bit = True


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
    is_bit = True


class I_btg_wp_b(Instruction_wp_b_B):
    """BTG{.B} Ws, #bit4"""
    name = 'btg'
    mask = 0xFF0B80
    code = 0xA20000
    is_bit = True


#######################################
# BTSC                             {{{2


class I_btsc_f_b(Instruction_f_b_B):
    """BTSC{.B} f, #bit4"""
    name = 'btsc'
    mask = 0xFF0000
    code = 0xAF0000
    is_bit = True


class I_btsc_wp_b(Instruction_wp_b):
    """BTSC Ws, #bit4"""
    name = 'btsc'
    mask = 0xFF0F80
    code = 0xA70000
    is_bit = True


#######################################
# BTSS                             {{{2


class I_btss_f_b(Instruction_f_b_B):
    """BTSS{.B} f, #bit4"""
    name = 'btss'
    mask = 0xFF0000
    code = 0xAE0000
    is_bit = True


class I_btss_wp_b(Instruction_wp_b):
    """BTSS Ws, #bit4"""
    name = 'btss'
    mask = 0xFF0F80
    code = 0xA60000
    is_bit = True


#######################################
# BTST                             {{{2


class I_btst_f_b(Instruction_f_b_B):
    """BTST{.B} f, #bit4"""
    name = 'btst'
    mask = 0xFF0000
    code = 0xAB0000
    feat = idaapi.CF_USE1
    is_bit = True


class I_btstc_wp_b(Instruction_wp_b):
    """BTST.C Ws, #bit4"""
    name = 'btst.c'
    mask = 0xFF0780
    code = 0xA30000
    feat = idaapi.CF_USE1
    is_bit = True


class I_btstz_wp_b(Instruction_wp_b):
    """BTST.Z Ws, #bit4"""
    name = 'btst.z'
    mask = 0xFF0780
    code = 0xA30800
    feat = idaapi.CF_USE1
    is_bit = True


class I_btstc_wp_w(Instruction_wp_w):
    """BTST.C Ws, Wb"""
    name = 'btst.c'
    mask = 0xFF8780
    code = 0xA50000
    feat = idaapi.CF_USE1 | idaapi.CF_USE2


class I_btstz_wp_w(Instruction_wp_w):
    """BTST.Z Ws, Wb"""
    name = 'btst.z'
    mask = 0xFF8780
    code = 0xA58000
    feat = idaapi.CF_USE1 | idaapi.CF_USE2


#######################################
# BTSTS                            {{{2


class I_btsts_f_b(Instruction_f_b_B):
    """BTSTS{.B} f, #bit4"""
    name = 'btsts'
    mask = 0xFF0000
    code = 0xAC0000
    is_bit = True


class I_btstsc_wp_b(Instruction_wp_b):
    """BTSTS.C Ws, #bit4"""
    name = 'btsts.c'
    mask = 0xFF0F80
    code = 0xA40000
    is_bit = True


class I_btstsz_wp_b(Instruction_wp_b):
    """BTSTS.Z Ws, #bit4"""
    name = 'btsts.z'
    mask = 0xFF0F80
    code = 0xA40800
    is_bit = True


#######################################
# CALL                             {{{2


class I_call_l23(Instruction):
    """CALL Expr"""
    name = 'call'
    mask = 0xFF0000
    code = 0x020000
    feat = idaapi.CF_USE1 | idaapi.CF_CALL

    def _decode(self, insn, code):
        data = insn_get_next_word(insn)
        set_op_near(insn, 0, mask_lit23(code, data))


class I_call_w(Instruction):
    """CALL Wn"""
    name = 'call'
    mask = 0xFFFFF0
    code = 0x010000
    feat = idaapi.CF_USE1 | idaapi.CF_CALL | idaapi.CF_JUMP

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))


class I_calll_w(Instruction):
    """CALL.L Wn"""
    name = 'call.l'
    mask = 0xFF87F0
    code = 0x018000
    feat = idaapi.CF_USE1 | idaapi.CF_CALL | idaapi.CF_JUMP

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
    feat = idaapi.CF_USE1


class I_cp_w_l5(Instruction_w_l5_B):
    """CP{.B} f"""
    name = 'cp'
    mask = 0xFF83E0
    code = 0xE10060
    feat = idaapi.CF_USE1


class I_cp_w_l8(Instruction_w_l8_B):
    """CP{.B} f"""
    name = 'cp'
    mask = 0xFF8060
    code = 0xE10060
    feat = idaapi.CF_USE1


class I_cp_w_wp(Instruction_w_wp_B):
    """CP{.B} Wb, [Ws]"""
    name = 'cp'
    mask = 0xFF8380
    code = 0xE10000
    feat = idaapi.CF_USE1 | idaapi.CF_USE2


#######################################
# CP0                              {{{2


class I_cp0_f(Instruction_f_B):
    """CP0{.B} f"""
    name = 'cp0'
    mask = 0xFFA000
    code = 0xE20000
    feat = idaapi.CF_USE1


class I_cp0_wp(Instruction_wp_B):
    """CP0{.B} [Ws]"""
    name = 'cp0'
    mask = 0xFFFB80
    code = 0xE00000
    feat = idaapi.CF_USE1


#######################################
# CPB                              {{{2


class I_cpb_f(Instruction_f_B):
    """CPB{.B} f"""
    name = 'cpb'
    mask = 0xFFA000
    code = 0xE38000
    feat = idaapi.CF_USE1


class I_cpb_w_l5(Instruction_w_l5_B):
    """CPB{.B} Wb, #lit5"""
    name = 'cpb'
    mask = 0xFF83E0
    code = 0xE18060
    feat = idaapi.CF_USE1


class I_cpb_w_l8(Instruction_w_l8_B):
    """CPB{.B} Wb, #lit8"""
    name = 'cpb'
    mask = 0xFF8060
    code = 0xE18060
    feat = idaapi.CF_USE1


class I_cpb_w_wp(Instruction_w_wp_B):
    """CPB{.B} Wb, [Ws]"""
    name = 'cpb'
    mask = 0xFF8380
    code = 0xE18000
    feat = idaapi.CF_USE1 | idaapi.CF_USE2


#######################################
# CPSEQ                            {{{2


class I_cpseq_w_w_B(Instruction_w_w_B):
    """CPSEQ{.B} Wb, Wn"""
    name = 'cpseq'
    mask = 0xFF83F0
    code = 0xE78000
    feat = idaapi.CF_USE1 | idaapi.CF_USE2


#######################################
# CPSGT                            {{{2


class I_cpsgt_w_w_B(Instruction_w_w_B):
    """CPSGT{.B} Wb, Wn"""
    name = 'cpsgt'
    mask = 0xFF83F0
    code = 0xE60000
    feat = idaapi.CF_USE1 | idaapi.CF_USE2


#######################################
# CPSLT                            {{{2


class I_cpslt_w_w_B(Instruction_w_w_B):
    """CPSLT{.B} Wb, Wn"""
    name = 'cpslt'
    mask = 0xFF83F0
    code = 0xE68000
    feat = idaapi.CF_USE1 | idaapi.CF_USE2


#######################################
# CPSNE                            {{{2


class I_cpsne_w_w_B(Instruction_w_w_B):
    """CPSNE{.B} Wb, Wn"""
    name = 'cpsne'
    mask = 0xFF83F0
    code = 0xE70000
    feat = idaapi.CF_USE1 | idaapi.CF_USE2


# DAW.B                            {{{2


class I_dawb(Instruction):
    """DAW.B Wn"""
    name = 'daw'
    mask = 0xFFFFF0
    code = 0xFD4000

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_w_0(code))
        set_insn_byte(insn)


# DEC                              {{{2


class I_dec_f_wr(Instruction_f_wr_B):
    """DEC{.B} f, WREG"""
    name = 'dec'
    mask = 0xFF8000
    code = 0xED0000


class I_dec_wp_wp(Instruction_wp_wp_B):
    """DEC{.B} [Ws], [Wd]"""
    name = 'dec'
    mask = 0xFF8000
    code = 0xE90000


#######################################
# DEC2                             {{{2


class I_dec2_f_wr(Instruction_f_wr_B):
    """DEC2{.B} f, WREG"""
    name = 'dec2'
    mask = 0xFF8000
    code = 0xED8000


class I_dec2_wp_wp(Instruction_wp_wp_B):
    """DEC2{.B} [Ws], [Wd]"""
    name = 'dec2'
    mask = 0xFF8000
    code = 0xE98000


#######################################
# DISI                             {{{2


class I_disi_l14(Instruction):
    """DISI #lit14"""
    name = 'disi'
    mask = 0xFF8000
    code = 0xED8000

    def _decode(self, insn, code):
        set_op_imm(insn, 0, mask_lit14(code))


#######################################
# DIV                              {{{2


class I_divs(Instruction_w_w_W):
    """DIV.S{D} Wm, Wn"""
    name = 'div.s'
    mask = 0xFF8030
    code = 0xD80000


class I_divu(Instruction_w_w_W):
    """DIV.U{D} Wm, Wn"""
    name = 'div.u'
    mask = 0xFF8030
    code = 0xD88000


#######################################
# EXCH                             {{{2


class I_exch(Instruction):
    """EXCH Wns, Wnd"""
    name = 'exch'
    mask = 0xFFF870
    code = 0xFD0000
    feat = idaapi.CF_CHG1 | idaapi.CF_CHG2

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))
        set_op_reg(insn, 0, ireg.W0 + mask_d_7(code))


#######################################
# FF1L                             {{{2


class I_ff1l(Instruction):
    """FF1L [Ws], Wnd"""
    name = 'ff1r'
    mask = 0xFFF800
    code = 0xCF8000
    feat = idaapi.CF_USE1 | idaapi.CF_CHG2

    def _decode(self, insn, code):
        set_op_phrase(insn, 0, mask_s_0(code), mask_p_4(code))
        set_op_reg(insn, 1, ireg.W0 + mask_d_7(code))


#######################################
# FF1R                             {{{2


class I_ff1R(Instruction):
    """FF1R [Ws], Wnd"""
    name = 'ff1r'
    mask = 0xFFF800
    code = 0xCF0000
    feat = idaapi.CF_USE1 | idaapi.CF_CHG2

    def _decode(self, insn, code):
        set_op_phrase(insn, 0, mask_s_0(code), mask_p_4(code), 0)
        set_op_reg(insn, 1, ireg.W0 + mask_d_7(code))


#######################################
# GOTO                             {{{2


class I_goto_l23(Instruction):
    """GOTO Expr"""
    name = 'goto'
    mask = 0xFF0000
    code = 0x040000
    feat = idaapi.CF_USE1 | idaapi.CF_STOP

    def _decode(self, insn, code):
        data = insn_get_next_word(insn)
        set_op_near(insn, 0, mask_lit23(code, data))


class I_goto_w(Instruction):
    """GOTO Wn"""
    name = 'goto'
    mask = 0xFFFFF0
    code = 0x014000
    feat = idaapi.CF_USE1 | idaapi.CF_STOP | idaapi.CF_JUMP

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))


class I_goto_w_E(Instruction):
    """GOTO Wn"""
    name = 'goto'
    mask = 0xFFFFF0
    code = 0x010400
    feat = idaapi.CF_USE1 | idaapi.CF_STOP | idaapi.CF_JUMP

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))


class I_gotol_w(Instruction):
    """GOTO.L Wn"""
    name = 'goto.l'
    mask = 0xFF87F0
    code = 0x018400
    feat = idaapi.CF_USE1 | idaapi.CF_STOP | idaapi.CF_JUMP

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))


#######################################
# INC                              {{{2


class I_inc_f_wr(Instruction_f_wr_B):
    """INC{.B} f, WREG"""
    name = 'inc'
    mask = 0xFF8000
    code = 0xEC0000


class I_inc_wp_wp(Instruction_wp_wp_B):
    """INC{.B} [Ws], [Wd]"""
    name = 'inc'
    mask = 0xFF8000
    code = 0xE80000


#######################################
# INC2                             {{{2


class I_inc2_f_wr(Instruction_f_wr_B):
    """INC2{.B} f, WREG"""
    name = 'inc2'
    mask = 0xFF8000
    code = 0xEC8000


class I_inc2_wp_wp(Instruction_wp_wp_B):
    """INC2{.B} [Ws], [Wd]"""
    name = 'inc2'
    mask = 0xFF8000
    code = 0xE88000


#######################################
# IOR                              {{{2


class I_ior_f_wr(Instruction_f_wr_B):
    """IOR{.B} f, WREG"""
    name = 'ior'
    mask = 0xFFA000
    code = 0xB70000


class I_ior_f(Instruction_f_B):
    """IOR{.B} f"""
    name = 'ior'
    mask = 0xFFA000
    code = 0xB72000


class I_ior_l10_w(Instruction_l10_w_B):
    """IOR{.B} #lit10, Wn"""
    name = 'ior'
    mask = 0xFF8000
    code = 0xB30000


class I_ior_w_l5_wp(Instruction_w_l5_wp_B):
    """IOR{.B} Wb, #lit5, [Wd]"""
    name = 'ior'
    mask = 0xF80060
    code = 0x700060


class I_ior_w_wp_wp(Instruction_w_wp_wp_B):
    """IOR{.B} Wb, [Ws], [Wd]"""
    name = 'ior'
    mask = 0xF80000
    code = 0x700000


#######################################
# LNK                              {{{2


class I_lnk(Instruction):
    """LNK #lit14"""
    name = 'lnk'
    mask = 0xFFC001
    code = 0xFA0000
    feat = idaapi.CF_USE1

    def _decode(self, insn, code):
        set_op_imm(insn, 0, mask_k14_0(code))


#######################################
# LSR                              {{{2


class I_lsr_f_wr(Instruction_f_wr_B):
    """LSR{.B} f, WREG"""
    name = 'lsr'
    mask = 0xFFA000
    code = 0xD50000


class I_lsr_f(Instruction_f_B):
    """LSR{.B} f"""
    name = 'lsr'
    mask = 0xFFA000
    code = 0xD52000


class I_lsr_wp_wp(Instruction_wp_wp_B):
    """LSR{.B} [Ws], [Wd]"""
    name = 'lsr'
    mask = 0xFF8000
    code = 0xD10000


class I_lsr_w_l4_w(Instruction_w_l4_w):
    """LSR Wb, #lit4, Wnd"""
    name = 'lsr'
    mask = 0xFF8070
    code = 0xDE0040


class I_lsr_w_w_w(Instruction_w_w_w):
    """LSR Wb, Wns, Wnd"""
    name = 'lsr'
    mask = 0xFF8070
    code = 0xDE0000


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
    feat = idaapi.CF_USE1 | idaapi.CF_CHG2

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
    feat = idaapi.CF_USE1 | idaapi.CF_CHG2

    def _decode(self, insn, code):
        set_op_mem(insn, 0, mask_f15_4(code))
        set_op_reg(insn, 1, ireg.W0 + mask_d_0(code))


class I_mov_w_f(Instruction):
    """MOV Wns, f"""
    name = 'mov'
    mask = 0xF80000
    code = 0x880000
    feat = idaapi.CF_USE1 | idaapi.CF_CHG2

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))
        set_op_mem(insn, 1, mask_f15_4(code))


class I_mov_l8_w(Instruction):
    """MOV.B #lit8, Wnd"""
    name = 'mov'
    mask = 0xFFF000
    code = 0xB3C000
    feat = idaapi.CF_USE1 | idaapi.CF_CHG2

    def _decode(self, insn, code):
        set_op_imm(insn, 0, mask_k8_4(code))
        set_op_reg(insn, 1, ireg.W0 + mask_d_0(code))
        set_insn_byte(insn)


class I_mov_l16_w(Instruction):
    """MOV #lit16, Wnd"""
    name = 'mov'
    mask = 0xF00000
    code = 0x200000
    feat = idaapi.CF_USE1 | idaapi.CF_CHG2

    def _decode(self, insn, code):
        set_op_imm(insn, 0, mask_k16_4(code))
        set_op_reg(insn, 1, ireg.W0 + mask_d_0(code))


class I_mov_wso_w(Instruction):
    """MOV{.B} [Ws + Slit10], Wnd"""
    name = 'mov'
    mask = 0xF80000
    code = 0x900000
    feat = idaapi.CF_USE1 | idaapi.CF_CHG2

    def _decode(self, insn, code):
        set_op_displ(insn, 0, mask_s_0(code), mask_slit10_4(code))
        set_op_reg(insn, 1, ireg.W0 + mask_d_7(code))
        if mask_B_14(code):
            set_insn_byte(insn)
        else:
            insn.ops[0].addr *= 2


class I_mov_w_wso(Instruction):
    """MOV{.B} Wns, [Wd + Slit10]"""
    name = 'mov'
    mask = 0xF80000
    code = 0x980000
    feat = idaapi.CF_USE1 | idaapi.CF_CHG2

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))
        set_op_displ(insn, 1, mask_d_7(code), mask_slit10_4(code))
        if mask_B_14(code):
            set_insn_byte(insn)
        else:
            insn.Op2.addr *= 2


class I_mov_wp_wp(Instruction_wpo_wpo_B):
    """MOV{.B} Ws, Wd"""
    name = 'mov'
    mask = 0xF80000
    code = 0x780000


class I_movd_wp_w(Instruction):
    """MOV.D [Ws], Wnd"""
    name = 'mov.d'
    mask = 0xFFF880
    code = 0xBE0000
    feat = idaapi.CF_USE1 | idaapi.CF_CHG2

    def _decode(self, insn, code):
        set_op_phrase(insn, 0, mask_s_0(code), mask_p_4(code), 0)
        set_op_reg(insn, 0, ireg.W0 + mask_d_7(code))
        insn.ops[0].dtype = idaapi.dt_dword
        insn.ops[1].dtype = idaapi.dt_dword


#######################################
# MUL                              {{{2


class I_mul_f(Instruction_f_B):
    """MUL{.B} f"""
    name = 'mul'
    mask = 0xFFB000
    code = 0xBC0000
    feat = idaapi.CF_USE1


class I_mulss_w_wp_w(Instruction_w_wp_w):
    """MUL.SS Wb, [Ws], Wnd"""
    name = 'mul.ss'
    mask = 0xFF8000
    code = 0xB98000


class I_mulsu_w_l5_w(Instruction_w_l5_w):
    """MUL.SU Wb, #lit5, Wnd"""
    name = 'mul.su'
    mask = 0xFF8060
    code = 0xB90060


class I_mulsu_w_wp_w(Instruction_w_wp_w):
    """MUL.SU Wb, [Ws], Wnd"""
    name = 'mul.su'
    mask = 0xFF8000
    code = 0xB90000


class I_mulus_w_wp_w(Instruction_w_wp_w):
    """MUL.US Wb, [Ws], Wnd"""
    name = 'mul.us'
    mask = 0xFF8000
    code = 0xB88000


class I_muluu_w_l5_w(Instruction_w_l5_w):
    """MUL.UU Wb, #lit5, Wnd"""
    name = 'mul.uu'
    mask = 0xFF8060
    code = 0xB80060


class I_muluu_w_wp_w(Instruction_w_wp_w):
    """MUL.UU Wb, [Ws], Wnd"""
    name = 'mul.uu'
    mask = 0xFF8000
    code = 0xB80000


#######################################
# NEG                              {{{2


class I_neg_f_wr(Instruction_f_wr_B):
    """NEG{.B} f, WREG"""
    name = 'neg'
    mask = 0xFFA000
    code = 0xEE0000


class I_neg_f(Instruction_f_B):
    """NEG{.B} f"""
    name = 'neg'
    mask = 0xFFA000
    code = 0xEE2000


class I_neg_wp_wp(Instruction_wp_wp_B):
    """NEG{.B} [Ws], [Wd]"""
    name = 'neg'
    mask = 0xFF8000
    code = 0xEA0000


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
# POP                              {{{2


class I_pop_f(Instruction):
    """POP f"""
    name = 'pop'
    mask = 0xFF0000
    code = 0xF90000
    feat = idaapi.CF_CHG1

    def _decode(self, insn, code):
        set_op_mem(insn, 0, mask_f16_0(code))


class I_pop_wp(Instruction):
    """POP [Wd]"""
    name = 'pop'
    mask = 0xF8407F
    code = 0x78004F
    feat = idaapi.CF_CHG1

    def _decode(self, insn, code):
        set_op_phrase(
            insn, 0,
            mask_d_7(code),
            mask_h_11(code),
            mask_w_15(code)
        )


class I_popd_w(Instruction):
    """POP.D Wnd"""
    name = 'pop.d'
    mask = 0xFFF87F
    code = 0xBE004F
    feat = idaapi.CF_CHG1

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_d_7(code))
        insn.ops[0].dtype = idaapi.dt_dword


class I_pops(Instruction):
    """POP.S"""
    name = 'pop.s'
    mask = 0xFFFFFF
    code = 0xFE8000


#######################################
# PUSH                             {{{2


class I_push_f(Instruction):
    """PUSH f"""
    name = 'push'
    mask = 0xFF0000
    code = 0xF80000
    feat = idaapi.CF_USE1

    def _decode(self, insn, code):
        set_op_mem(insn, 0, mask_f16_0(code))


class I_push_wp(Instruction):
    """PUSH [Ws]"""
    name = 'push'
    mask = 0xF87F80
    code = 0x781F80
    feat = idaapi.CF_USE1

    def _decode(self, insn, code):
        set_op_phrase(
            insn, 0,
            mask_s_0(code),
            mask_g_4(code),
            mask_w_15(code)
        )


class I_pushd_w(Instruction):
    """PUSH.D Wns"""
    name = 'pop.d'
    mask = 0xFFFFF0
    code = 0xBE9F80
    feat = idaapi.CF_USE1

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))
        insn.ops[0].dtype = idaapi.dt_dword


class I_pushs(Instruction):
    """PUSH.S"""
    name = 'push.s'
    mask = 0xFFFFFF
    code = 0xFE9000


#######################################
# PWRSAV                           {{{2


class I_pwrsav(Instruction):
    """PWRSAV #lit1"""
    name = 'pwrsav'
    mask = 0xFFFFFE
    code = 0xFE4000
    feat = idaapi.CF_USE1

    def _decode(self, insn, code):
        set_op_imm(insn, 0, mask_k1_0(code))


#######################################
# RCALL                            {{{2


class I_rcall_slit16(Instruction):
    """RCALL Expr"""
    name = 'rcall'
    mask = 0xFF0000
    code = 0x070000
    feat = idaapi.CF_USE1 | idaapi.CF_CALL

    def _decode(self, insn, code):
        set_op_near_rel(insn, 0, mask_slit16_0(code))


class I_rcall_w(Instruction):
    """RCALL Wn"""
    name = 'rcall'
    mask = 0xFFFFF0
    code = 0x014000
    feat = idaapi.CF_USE1 | idaapi.CF_CALL | idaapi.CF_JUMP

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))


class I_rcall_w_E(Instruction):
    """RCALL Wn"""
    name = 'rcall'
    mask = 0xFFFFF0
    code = 0x010400
    feat = idaapi.CF_USE1 | idaapi.CF_CALL | idaapi.CF_JUMP

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))


#######################################
# REPEAT                           {{{2


class I_repeat_lit14(Instruction):
    """REPEAT #lit14"""
    name = 'repeat'
    mask = 0xFFC000
    code = 0x090000
    feat = idaapi.CF_USE1

    def _decode(self, insn, code):
        set_op_imm(insn, 0, mask_k14_0(code))


class I_repeat_w(Instruction):
    """REPEAT Wn"""
    name = 'repeat'
    mask = 0xFFFFF0
    code = 0x098000
    feat = idaapi.CF_USE1

    def _decode(self, insn, code):
        set_op_reg(insn, 0, mask_s_0(code))


#######################################
# RESET                            {{{2


class I_reset(Instruction):
    """RESET"""
    name = 'reset'
    mask = 0xFFFFFF
    code = 0xFE0000


#######################################
# RETFIE                           {{{2


class I_retfie(Instruction):
    """RETFIE"""
    name = 'retfie'
    mask = 0xFFFFFF
    code = 0x064000


#######################################
# RETLW                            {{{2


class I_retlw(Instruction_l10_w_B):
    """RETLW"""
    name = 'retlw'
    mask = 0xFF8000
    code = 0x050000


#######################################
# RETURN                           {{{2


class I_return(Instruction):
    """RETURN"""
    name = 'return'
    mask = 0xFFFFFF
    code = 0x060000


#######################################
# RLC                              {{{2


class I_rlc_f_wr(Instruction_f_wr_B):
    """RLC{.B} f, WREG"""
    name = 'rlc'
    mask = 0xFFA000
    code = 0xD68000


class I_rlc_f(Instruction_f_B):
    """RLC{.B} f"""
    name = 'rlc'
    mask = 0xFFA000
    code = 0xD6A000


class I_rlc_wp_wp(Instruction_wp_wp_B):
    """RLC{.B} [Ws], [Wd]"""
    name = 'rlc'
    mask = 0xFF8000
    code = 0xD28000


#######################################
# RLNC                             {{{2


class I_rlnc_f_wr(Instruction_f_wr_B):
    """RLNC{.B} f, WREG"""
    name = 'rlnc'
    mask = 0xFFA000
    code = 0xD60000


class I_rlnc_f(Instruction_f_B):
    """RLNC{.B} f"""
    name = 'rlnc'
    mask = 0xFFA000
    code = 0xD62000


class I_rlnc_wp_wp(Instruction_wp_wp_B):
    """RLNC{.B} [Ws], [Wd]"""
    name = 'rlnc'
    mask = 0xFF8000
    code = 0xD20000


#######################################
# RRC                              {{{2


class I_rrc_f_wr(Instruction_f_wr_B):
    """RRC{.B} f, WREG"""
    name = 'rrc'
    mask = 0xFFA000
    code = 0xD78000


class I_rrc_f(Instruction_f_B):
    """RRC{.B} f"""
    name = 'rrc'
    mask = 0xFFA000
    code = 0xD7A000


class I_rrc_wp_wp(Instruction_wp_wp_B):
    """RRC{.B} [Ws], [Wd]"""
    name = 'rrc'
    mask = 0xFF8000
    code = 0xD38000


#######################################
# RRNC                             {{{2


class I_rrnc_f_wr(Instruction_f_wr_B):
    """RRNC{.B} f, WREG"""
    name = 'rrnc'
    mask = 0xFFA000
    code = 0xD70000


class I_rrnc_f(Instruction_f_B):
    """RRNC{.B} f"""
    name = 'rrnc'
    mask = 0xFFA000
    code = 0xD72000


class I_rrnc_wp_wp(Instruction_wp_wp_B):
    """RRNC{.B} [Ws], [Wd]"""
    name = 'rrnc'
    mask = 0xFF8000
    code = 0xD30000


#######################################
# SE                               {{{2


class I_se(Instruction):
    """SE [Ws], Wnd"""
    name = 'se'
    mask = 0xFFF800
    code = 0xFB0000
    feat = idaapi.CF_USE1 | idaapi.CF_CHG2

    def _decode(self, insn, code):
        set_op_phrase(insn, 0, mask_s_0(code), mask_p_4(code), 0)
        insn.ops[0].dtype = idaapi.dt_byte
        set_op_reg(insn, 1, ireg.W0 + mask_d_7(code))


#######################################
# SETM                             {{{2


class I_setm_f_wr(Instruction_f_wr_B):
    """SETM{.B} f, WREG"""
    name = 'setm'
    mask = 0xFFA000
    code = 0xDF8000


class I_setm_f(Instruction_f_B):
    """SETM{.B} f"""
    name = 'setm'
    mask = 0xFFA000
    code = 0xDFA000


class I_setm_wp(Instruction_wp_B):
    """SETM{.B} [Wd]"""
    name = 'setm'
    mask = 0xFF807F
    code = 0xEB8000


#######################################
# SL                               {{{2


class I_sl_f_wr(Instruction_f_wr_B):
    """SL{.B} f, WREG"""
    name = 'sl'
    mask = 0xFFA000
    code = 0xD80000


class I_sl_f(Instruction_f_B):
    """SL{.B} f"""
    name = 'sl'
    mask = 0xFFA000
    code = 0xD82000


class I_sl_wp_wp(Instruction_wp_wp_B):
    """SL{.B} [Ws], [Wd]"""
    name = 'sl'
    mask = 0xFF8000
    code = 0xD00000


class I_sl_w_l4_w(Instruction_w_l4_w):
    """SL Wb, #lit4, Wnd"""
    name = 'sl'
    mask = 0xFF8070
    code = 0xDD0040


class I_sl_w_w_w(Instruction_w_w_w):
    """SL Wb, Wns, Wnd"""
    name = 'sl'
    mask = 0xFF8070
    code = 0xDD0000


#######################################
# SUB                              {{{2


class I_sub_f_wr(Instruction_f_wr_B):
    """SUB{.B} f, WREG"""
    name = 'sub'
    mask = 0xFFA000
    code = 0xB50000


class I_sub_f(Instruction_f_B):
    """SUB{.B} f"""
    name = 'sub'
    mask = 0xFFA000
    code = 0xB52000


class I_sub_l10_w(Instruction_l10_w_B):
    """SUB{.B} #lit10, Wn"""
    name = 'sub'
    mask = 0xFF8000
    code = 0xB10000


class I_sub_w_l5_wp(Instruction_w_l5_wp_B):
    """SUB{.B} Wb, #lit5, [Wd]"""
    name = 'sub'
    mask = 0xF80060
    code = 0x500060


class I_sub_w_wp_wp(Instruction_w_wp_wp_B):
    """SUB{.B} Wb [Ws], [Wd]"""
    name = 'sub'
    mask = 0xF80000
    code = 0x500000


class I_sub_a(Instruction):
    """SUB Acc"""
    name = 'sub'
    mask = 0xFF7FFF
    code = 0xCB3000
    feat = idaapi.CF_CHG1

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.A if mask_A_15(code) else ireg.B)


class I_subb_f_wr(Instruction_f_wr_B):
    """SUBB{.B} f, WREG"""
    name = 'subb'
    mask = 0xFFA000
    code = 0xB58000


class I_subb_f(Instruction_f_B):
    """SUBB{.B} f"""
    name = 'SUBB'
    mask = 0xFFA000
    code = 0xB5A000


class I_subb_l10_w(Instruction_l10_w_B):
    """SUBB{.B} #lit10, Wn"""
    name = 'subb'
    mask = 0xFF8000
    code = 0xB18000


class I_subb_w_l5_wp(Instruction_w_l5_wp_B):
    """SUBB{.B} Wb, #lit5, [Wd]"""
    name = 'subb'
    mask = 0xF80060
    code = 0x580060


class I_subb_w_wp_wp(Instruction_w_wp_wp_B):
    """SUBB{.B} Wb, [Ws], [Wd]"""
    name = 'subb'
    mask = 0xF80000
    code = 0x580000


class I_subbr_f_wr(Instruction_f_wr_B):
    """SUBBR{.B} f, WREG"""
    name = 'subbr'
    mask = 0xFFA000
    code = 0xBD8000


class I_subbr_f(Instruction_f_B):
    """SUBBR{.B} f"""
    name = 'SUBBR'
    mask = 0xFFA000
    code = 0xBDA000


class I_subbr_w_l5_wp(Instruction_w_l5_wp_B):
    """SUBBR{.B} Wb, #lit5, [Wd]"""
    name = 'subbr'
    mask = 0xF80060
    code = 0x180060


class I_subbr_w_wp_wp(Instruction_w_wp_wp_B):
    """SUBBR{.B} Wb, [Ws], [Wd]"""
    name = 'subbr'
    mask = 0xF80000
    code = 0x180000


class I_subr_f_wr(Instruction_f_wr_B):
    """SUBR{.B} f, WREG"""
    name = 'subr'
    mask = 0xFFA000
    code = 0xBD0000


class I_subr_f(Instruction_f_B):
    """SUBR{.B} f"""
    name = 'SUBR'
    mask = 0xFFA000
    code = 0xBD2000


class I_subr_w_l5_wp(Instruction_w_l5_wp_B):
    """SUBR{.B} Wb, #lit5, [Wd]"""
    name = 'subr'
    mask = 0xF80060
    code = 0x100060


class I_subr_w_wp_wp(Instruction_w_wp_wp_B):
    """SUBR{.B} Wb, [Ws], [Wd]"""
    name = 'subr'
    mask = 0xF80000
    code = 0x100000


#######################################
# SWAP                             {{{2


class I_swap(Instruction):
    """SWAP{.B} Wn"""
    name = 'swap'
    mask = 0xFFF800
    code = 0xFD0000
    feat = idaapi.CF_USE1 | idaapi.CF_CHG1

    def _decode(self, insn, code):
        set_op_reg(insn, 0, ireg.W0 + mask_s_0(code))
        if mask_B_14(code):
            set_insn_byte(insn)


#######################################
# TBLRD                            {{{2


class I_tblrdh(Instruction_wp_wp_B):
    """TBLRDH{.B} [Ws], [Wd]"""
    name = 'tlbrdh'
    mask = 0xFF8000
    code = 0xBA8000


class I_tblrdl(Instruction_wp_wp_B):
    """TBLRDL{.B} [Ws], [Wd]"""
    name = 'tlbrdl'
    mask = 0xFF8000
    code = 0xBA0000


#######################################
# TBLWT                            {{{2


class I_tblwth(Instruction_wp_wp_B):
    """TBLWTH{.B} [Ws], [Wd]"""
    name = 'tlbwth'
    mask = 0xFF8000
    code = 0xBB8000


class I_tblwtl(Instruction_wp_wp_B):
    """TBLWTL{.B} [Ws], [Wd]"""
    name = 'tlbwtl'
    mask = 0xFF8000
    code = 0xBB0000


#######################################
# ULNK                             {{{2


class I_ulnk(Instruction):
    """ULNK"""
    name = 'ulnk'
    mask = 0xFFFFFF
    code = 0xFA8000


#######################################
# XOR                              {{{2


class I_xor_f_wr(Instruction_f_wr_B):
    """XOR{.B} f, WREG"""
    name = 'xor'
    mask = 0xFFA000
    code = 0xB68000


class I_xor_f(Instruction_f_B):
    """XOR{.B} f"""
    name = 'xor'
    mask = 0xFFA000
    code = 0xB68000


class I_xor_l10_w(Instruction_l10_w_B):
    """XOR{.B} #lit10, Wn"""
    name = 'xor'
    mask = 0xFF8000
    code = 0xB28000


class I_xor_w_l5_wp(Instruction_w_l5_wp_B):
    """XOR{.B} Wb, #lit5, [Wd]"""
    name = 'xor'
    mask = 0xF80060
    code = 0x680060


class I_xor_w_wp_wp(Instruction_w_wp_wp_B):
    """XOR{.B} Wb, [Ws], [Wd]"""
    name = 'Xor'
    mask = 0xF80000
    code = 0x680000


#######################################
# ZE                               {{{2


class I_ze(Instruction):
    """ZE [Ws], Wnd"""
    name = 'ze'
    mask = 0xFFF800
    code = 0xFB8000
    feat = idaapi.CF_USE1 | idaapi.CF_CHG2

    def _decode(self, insn, code):
        set_op_phrase(insn, 0, mask_s_0(code), mask_p_4(code), 0)
        insn.ops[0].dtype = idaapi.dt_byte
        set_op_reg(insn, 1, ireg.W0 + mask_d_7(code))


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

    reg_names = registers

    segreg_size = 1
    reg_first_sreg = ireg.TBLPAG
    reg_last_sreg = ireg.DS
    reg_code_sreg = ireg.CS
    reg_data_sreg = ireg.DS

    instruc = ida_instructions
    instruc_start = 0
    instruc_end = len(instruc) + 1

    # base address for segments in data memory
    # this is the first location not addressable in 24 bits
    # so it will never collide with a code memory location
    DATA_EABASE = 0x1000000

    def notify_init(self, mod_name):
        cfg_file = idaapi.getsysfile('pic24.cfg', idaapi.CFG_SUBDIR)
        if cfg_file is None:
            raise Exception("Config file 'pic24.cfg' not found.")

        self.config = Config()
        with open(cfg_file, 'r') as cfg:
            self.config.read(cfg)

    def _add_segment(self, name, cls, base, start, end):
        s = idaapi.segment_t()
        s.start_ea = base + start
        s.end_ea = base + end
        s.sel = idaapi.allocate_selector(base >> 4)

        if cls == 'CODE':
            s.type = idaapi.SEG_CODE
            s.perm = idaapi.SEGPERM_EXEC
            s.bitness = 1  # 32-bit addresses (really 24)
        elif cls == 'SFR':
            s.type = idaapi.SEG_IMEM
            s.perm = idaapi.SEGPERM_READ | idaapi.SEGPERM_WRITE
        elif cls == 'DATA':
            s.type = idaapi.SEG_DATA
            s.perm = idaapi.SEGPERM_READ | idaapi.SEGPERM_WRITE

        idaapi.add_segm_ex(
            s,
            name,
            cls,
            idaapi.ADDSEG_NOSREG | idaapi.ADDSEG_NOTRUNC,
        )

    def notify_newfile(self, fname):
        self.config.select_device()

        for area in self.config.areas:
            base = 0
            if area.cls != 'CODE':
                base = self.DATA_EABASE

            self._add_segment(
                area.name,
                area.cls,
                base,
                area.start,
                area.end,
            )

        for port in self.config.ports:
            addr = self.DATA_EABASE + port.addr
            idaapi.create_word(addr, 2)
            if not idaapi.set_name(addr, port.name, idaapi.SN_NOWARN):
                idaapi.set_cmt(addr, port.name, 0)

    def notify_ana(self, insn):
        code = insn_get_next_word(insn)
        decode_map[(code >> 16) & 0xFF].decode(insn, code)
        return insn.size if insn.itype != 0 else 0

    def _emu_operand(self, insn, op, is_write):
        if op.type == idaapi.o_mem:
            # create data xrefs
            addr = self.DATA_EABASE + op.addr
            insn.create_op_data(addr, op)
            insn.add_dref(
                addr, op.offb,
                (idaapi.dr_W if is_write else idaapi.dr_R),
            )

        elif op.type == idaapi.o_near:
            # create code xrefs
            feat = insn.get_canon_feature()
            insn.add_cref(
                op.addr, op.offb,
                (idaapi.fl_CN if (feat & idaapi.CF_CALL) else idaapi.fl_JN)
            )

    def notify_emu(self, insn):
        feat = insn.get_canon_feature()

        for idx in range(0, idaapi.UA_MAXOP):
            op = insn.ops[idx]
            if op.type == idaapi.o_void:
                break
            if (feat & getattr(idaapi, 'CF_USE' + str(idx + 1))) != 0:
                self._emu_operand(insn, op, False)
            if (feat & getattr(idaapi, 'CF_CHG' + str(idx + 1))) != 0:
                self._emu_operand(insn, op, True)

        if not feat & idaapi.CF_STOP:
            idaapi.add_cref(insn.ea, insn.ea + insn.size, idaapi.fl_F)

        return 1

    def out_mnem(self, ctx):
        postfix = ""

        if ctx.insn.auxpref & AUX_SZ_BYTE:
            postfix = '.b'
        elif ctx.insn.auxpref & AUX_SZ_DWORD:
            postfix = '.d'

        ctx.out_mnem(8, postfix)
        return 1

    def notify_out_operand(self, ctx, op):
        if op.type == idaapi.o_reg:
            ctx.out_register(self.reg_names[op.reg])

        elif op.type == idaapi.o_imm:
            if instructions[ctx.insn.itype].is_bit:
                name = self.config.find_bit_name(ctx.insn.Op1.addr, op.value)
                if name is not None:
                    ctx.out_line(name, idaapi.COLOR_IMPNAME)
                    return True

            ctx.out_symbol('#')
            ctx.out_value(op, idaapi.OOFW_IMM)

        elif op.type == idaapi.o_mem:
            addr = self.DATA_EABASE + op.addr

            port_name = self.config.find_port_name(op.addr)
            if port_name is not None:
                ctx.out_addr_tag(addr)
                ctx.out_line(port_name, idaapi.COLOR_IMPNAME)

            elif not ctx.out_name_expr(op, addr):
                ctx.out_tagon(idaapi.COLOR_ERROR)
                ctx.out_value(op, idaapi.OOF_ADDR)
                ctx.out_tagoff(idaapi.COLOR_ERROR)
                idaapi.remember_problem(idaapi.PR_NONAME, ctx.insn.ea)

        elif op.type == idaapi.o_near:
            if not ctx.out_name_expr(op, op.addr):
                ctx.out_tagon(idaapi.COLOR_ERROR)
                ctx.out_value(op, idaapi.OOF_ADDR)
                ctx.out_tagoff(idaapi.COLOR_ERROR)
                idaapi.remember_problem(idaapi.PR_NONAME, ctx.insn.ea)

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

        elif op.type == o_cond:
            ctx.out_register(conditions[op.reg])

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

    def _out_equ(self, ctx, indent, name, value):
        ctx.clr_gen_label()

        ctx.out_spaces(indent)
        ctx.out_line(name)

        ctx.out_spaces(idaapi.get_inf_structure().indent)
        ctx.out_line('.equ', idaapi.COLOR_KEYWORD)

        ctx.out_char(' ')
        ctx.out_tagon(idaapi.COLOR_NUMBER)
        ctx.out_btoa(value)
        ctx.out_tagoff(idaapi.COLOR_NUMBER)

        # indent by negative int max
        # this serves to remove the default indent, whatever it is
        ctx.flush_outbuf(-sys.maxint - 1)

    def _out_port(self, ctx):
        s = idaapi.getseg(ctx.insn_ea)
        if not s or s.type != idaapi.SEG_IMEM:
            return False

        addr = ctx.insn_ea - self.DATA_EABASE
        port = self.config.find_port(addr)
        if not port:
            return False

        self._out_equ(ctx, 0, port.name, port.addr)
        for addr, bit in port.bits_by_addr.iteritems():
            self._out_equ(ctx, 2, bit, addr)

        ctx.gen_empty_line()
        return True

    def notify_out_data(self, ctx, analyze_only):
        if not self._out_port(ctx):
            ctx.out_data(analyze_only)


def PROCESSOR_ENTRY():
    return PIC24Processor()
