# Note: bytearray is used as a bitfield
# Each constructor is expected to increment pc as needed, and provide a return mechanism
import re
try:
    from typing import Self
except ImportError:
    Self = None
from typing import Any
import regexes
try:
    from colorama import Fore, Style
except ImportError:
    class Everything:
        def __getattr__(self, item):
            return ""

        def __getattribute__(self, item):
            return ""

        def __setattr__(self, key, value):
            pass
    Fore = Style = Everything()


def box_print(msg: str, right_char: str = "#", left_char: str = "#", top_char: str = "=", bottom_char: str = "="):
    middle = f"{left_char} {msg} {right_char}"
    print(top_char*len(middle))
    print(middle)
    print(bottom_char*len(middle))


def pad(num: str, count: int):
    return "0"*(count-len(num))+num


class MutableObject:
    def __init__(self, value):
        self.value = value


def bytearray_to_bin_str(array: bytearray) -> str:
    return "".join([str(int(x)) for x in array])


def to_int(array: bytearray) -> int:
    return int(bytearray_to_bin_str(array), 2)


def signed_bin(num: int, count: int, unsigned: bool = False) -> str:
    full_ones = eval("0b" + "1"*count)
    if num >= 0:
        bin_str = bin(num).replace("0b", "")
    elif not unsigned:
        bin_str = bin(abs(num+1)^full_ones).replace("0b", "")
    else:
        raise AssemblyError("Negative number cannot be interpreted as unsigned")
    return (count - len(bin_str))*"0" + bin_str


def fill_num(num: int, array: bytearray, unsigned: bool = False):
    fill(signed_bin(num, len(array), unsigned=unsigned), array)


def fill(bin_str: str, array: bytearray):
    bin_str = bin_str.replace("0b", "")
    assert len(bin_str) <= len(array)
    bin_str = "0"*(len(array)-len(bin_str)) + bin_str
    for i in range(len(array)):
        array[i] = int(bin_str[i])


def match(out: MutableObject, regex: str, text: str, flags: re.RegexFlag):
    out.value = re.match(regex, text, flags)
    return out.value


class BytecodeBuilder:
    def __init__(self):
        self.words: list[bytearray] = []
        self.pc = 0

    def add(self, *array: bytearray):
        self.words.extend(array)
        self.pc += len(array)


class Address:
    def __init__(self, text: str, program_counter: int, simplified: bool = False):
        self.text = text
        self.simplified = simplified
        self.ad = bytearray(1)
        self.ad_long = bytearray(2)
        self.reg_4bit = bytearray(4)
        self.extra_words: list[bytearray] = []
        flags = re.IGNORECASE
        matched = MutableObject(None)
        if re.match(regexes.REGISTER_DIRECT, text, flags):
            self._ad(0, 0)
            self._set_register(text)
        elif match(matched, regexes.REGISTER_INDEXED, text, flags):
            self._ad(0, 1)
            reg = matched.value["reg"]
            digits_value, hex_value = matched.value["digits"], matched.value["hex"]
            self._set_register(reg)
            if digits_value is not None:
                idx = int(digits_value)
            elif hex_value is not None:
                idx = int(hex_value, 16)
            else:
                raise AssemblyError("Unspecified index")
            if matched.value["sign"] == "-":
                idx = -idx
            arr = bytearray(16)
            fill_num(idx, arr) # signed
            self.extra_words.append(arr)
            program_counter += 2
        elif match(matched, regexes.REGISTER_SYMBOLIC, text, flags):
            self._ad(0, 1)
            reg = "PC"
            digits_value, hex_value = matched.value["digits"], matched.value["hex"]
            self._set_register(reg)
            if digits_value is not None:
                idx = int(digits_value)
            elif hex_value is not None:
                idx = int(hex_value, 16)
            else:
                raise AssemblyError("Unspecified index")
            arr = bytearray(16)
            fill_num(idx-program_counter, arr) #signed
            self.extra_words.append(arr)
            program_counter += 2
        elif match(matched, regexes.REGISTER_ABSOLUTE, text, flags):
            self._ad(0, 1)
            reg = "SR"
            digits_value, hex_value = matched.value["digits"], matched.value["hex"]
            self._set_register(reg)
            if digits_value is not None:
                idx = int(digits_value)
            elif hex_value is not None:
                idx = int(hex_value, 16)
            else:
                raise AssemblyError("Unspecified index")
            arr = bytearray(16)
            fill_num(idx, arr) # signed because using indexed mode
            self.extra_words.append(arr)
            program_counter += 2
        elif not simplified:
            if match(matched, regexes.REGISTER_INDIRECT, text, flags):
                reg = matched.value["reg"]
                autoincrement = matched.value["autoincrement"]
                if autoincrement == "+":
                    self._ad(1, 1)
                elif autoincrement == "":
                    self._ad(1, 0)
                else:
                    raise AssemblyError("Invalid register specification")
                self._set_register(reg)
            elif match(matched, regexes.REGISTER_IMMEDIATE, text, flags):
                digits_value, hex_value = matched.value["digits"], matched.value["hex"]
                if digits_value is not None:
                    val = int(digits_value)
                elif hex_value is not None:
                    val = int(hex_value, 16)
                else:
                    raise AssemblyError("Unspecified index")
                if matched.value["sign"] == "-":
                    val = -val
                constant_tricks = {
                    -1: ((1, 1), "CG"),
                    0: ((0, 0), "CG"),
                    1: ((0, 1), "CG"),
                    2: ((1, 0), "CG"),
                    4: ((1, 0), "SR"),
                    8: ((1, 1), "SR")
                }
                if val in constant_tricks:
                    self._ad(*constant_tricks[val][0])
                    self._set_register(constant_tricks[val][1])
                else:
                    self._ad(1, 1)
                    self._set_register("PC")
                    arr = bytearray(16)
                    fill_num(val, arr) # signed
                    self.extra_words.append(arr)
                    program_counter += 2
        else:
            raise AssemblyError(f"Register mode not found, or unavailable for argument {text}")

        self._set_ad()
        self.pc_out = program_counter

    def _set_register(self, reg: str):
        reg = reg.lower()
        replacements = {
            "pc": "r0",
            "sp": "r1",
            "sr": "r2",
            "cg": "r3"
        }
        if reg in replacements:
            reg = replacements[reg]
        fill(bin(int(reg.replace("r", ""))), self.reg_4bit)

    def _ad(self, high: int, low: int):
        assert high in [0, 1] and low in [0, 1]
        self.ad_long[0] = high
        self.ad_long[1] = low

    def _set_ad(self):
        if self.simplified and self.ad_long[0] == 1:
            raise AssemblyError("Unsupported register mode for argument")
        self.ad[0] = self.ad_long[1]


class InstructionType:
    def opcode_tuple(self) -> tuple[int]:
        raise NotImplementedError

    def get_mnemonic(self) -> str:
        raise NotImplementedError

    @classmethod
    def parse(cls, line: str, program_counter: int) -> tuple[Any, int]:
        raise NotImplementedError


class Instruction:
    def __init__(self, op_type: InstructionType):
        self.op_type = op_type

    def get_words(self) -> list[bytearray]:
        raise NotImplementedError

    def get_mnemonic(self) -> str:
        raise NotImplementedError

    def get_args(self) -> str:
        raise NotImplementedError


class DoubleOperandInstruction(Instruction):
    def __init__(self, op_type: InstructionType, byte_mode: bool, src: Address, dst: Address):
        super().__init__(op_type)
        self.byte_mode = byte_mode
        self.src = src
        self.dst = dst

        self.words: list[bytearray] = [bytearray(16)]
        ins = self.words[0]  # Instruction
        ins[0:4] = self.op_type.opcode_tuple()
        ins[4:8] = src.reg_4bit
        ins[8] = dst.ad[0]
        ins[9] = byte_mode
        ins[10:12] = src.ad_long
        ins[12:16] = dst.reg_4bit
        self.words.extend(src.extra_words)
        self.words.extend(dst.extra_words)

    def get_words(self) -> list[bytearray]:
        return self.words

    def get_mnemonic(self) -> str:
        return self.op_type.get_mnemonic() + (".B" if self.byte_mode else "")

    def get_args(self) -> str:
        return f"{self.src.text}, {self.dst.text}"


class SingleOperandInstruction(Instruction):
    def __init__(self, op_type: InstructionType, byte_mode: bool, src: Address):
        super().__init__(op_type)
        self.byte_mode = byte_mode
        self.src = src

        self.words: list[bytearray] = [bytearray(16)]
        ins = self.words[0]  # Instruction
        ins[0:9] = self.op_type.opcode_tuple()
        ins[9] = byte_mode
        ins[10:12] = src.ad_long
        ins[12:16] = src.reg_4bit
        self.words.extend(src.extra_words)

    def get_words(self) -> list[bytearray]:
        return self.words

    def get_mnemonic(self) -> str:
        return self.op_type.get_mnemonic() + (".B" if self.byte_mode else "")

    def get_args(self) -> str:
        return self.src.text


class RetiInstruction(SingleOperandInstruction):
    def __init__(self, op_type: InstructionType):
        super().__init__(op_type, False, Address("PC", 0, False))
        fill("0001001100000000", self.words[0])
        self.words = [self.words[0]]

    def get_words(self) -> list[bytearray]:
        return self.words

    def get_mnemonic(self) -> str:
        return "RETI"

    def get_args(self) -> str:
        return ""


class JumpInstruction(Instruction):
    def __init__(self, op_type: InstructionType, offset: str, original_mnemonic: str, original_offset: str):
        super().__init__(op_type)
        assert len(offset) == 10
        self.offset = offset
        self.original_mnemonic = original_mnemonic
        self.original_offset = original_offset

        self.words: list[bytearray] = [bytearray(16)]
        ins = self.words[0]  # Instruction
        ins[0:6] = self.op_type.opcode_tuple()
        ins[6:16] = [int(v) for v in self.offset]

    def get_words(self) -> list[bytearray]:
        return self.words

    def get_mnemonic(self) -> str:
        return self.original_mnemonic

    def get_args(self) -> str:
        return self.original_offset


class EmulatedInstructionType(InstructionType):
    ALL: dict[str, Self] = {}

    def __init__(self, mnemonic: str, has_arg: bool, has_byte_mode: bool, target: type[InstructionType], resolve_fmt: str):
        """Emulated instruction parser - resolves to a real instruction

        :param mnemonic: human-readable instruction name (like "BR" or "EINT")
        :param has_arg: whether the instruction takes an argument
        :param has_byte_mode: whether the instruction can be used in byte-mode
        :param target: the instruction type this emulated instruction resolves to
        :param resolve_fmt: the format string used to resolve the instruction {bm} is replaced with ".B" if the instruction is in byte mode, {arg} is replaced with the argument
        """
        self.mnemonic = mnemonic
        assert self.mnemonic not in EmulatedInstructionType.ALL
        EmulatedInstructionType.ALL[self.mnemonic] = self
        self.has_arg = has_arg
        self.has_byte_mode = has_byte_mode
        if self.has_byte_mode and not self.has_arg:
            raise ValueError("Byte mode is only supported for instructions with arguments")
        self.target = target
        self.resolve_fmt = resolve_fmt

    def opcode_tuple(self) -> tuple[int]:
        raise AssemblyError("Emulated instruction should resolve to a real instruction before assembling")

    def get_mnemonic(self) -> str:
        raise AssemblyError("Emulated instruction should resolve to a real instruction before assembling")

    @classmethod
    def parse(cls, line: str, program_counter: int) -> tuple[Instruction, int]:
        parsed = re.match(regexes.INST_EMULATED, line, re.IGNORECASE)
        if parsed:
            # don't increment program counter, as that is handled by the real instruction
            mnemonic: str = parsed["opcode"].upper() # noqa
            if mnemonic not in EmulatedInstructionType.ALL:
                raise WrongInstructionError(f"Unknown emulated instruction {mnemonic}")
            emulated = EmulatedInstructionType.ALL[mnemonic]
            if emulated.has_arg != (parsed["operand_src"] is not None):
                raise WrongInstructionError(f"Invalid argument for {mnemonic}")
            if not emulated.has_byte_mode and (parsed["byte_mode"] is not None):
                raise WrongInstructionError(f"Byte mode is not supported for {mnemonic}")

            resolved_instruction = emulated.resolve_fmt.format(bm=".B" if parsed["byte_mode"] is not None and parsed["byte_mode"].lower() == ".b" else "", arg=parsed["operand_src"] if parsed["operand_src"] is not None else "")
            return emulated.target.parse(resolved_instruction, program_counter)
        else:
            raise WrongInstructionError("Invalid emulated instruction")


class JumpInstructionType(InstructionType):
    ALL: dict[str, Self] = {}
    ALIASES: dict[str, str] = {}

    def __init__(self, mnemonic: str, opcode: str):
        """(Conditional) jump instruction parser

        :param mnemonic: human-readable instruction name (like ("JNE" or "JL")
        :param opcode: bytecode instruction (like "000" or "110") the ("001" is automatically prefixed)
        """
        self.mnemonic = mnemonic.upper()
        self.opcode = "001" + opcode
        assert self.mnemonic not in JumpInstructionType.ALL
        assert len(self.opcode) == 6
        JumpInstructionType.ALL[self.mnemonic] = self
        print(self.mnemonic, self.opcode)

    def opcode_tuple(self) -> tuple[int]:
        return tuple([int(v) for v in self.opcode])

    def get_mnemonic(self) -> str:
        return self.mnemonic

    @classmethod
    def parse(cls, line: str, program_counter: int) -> tuple[JumpInstruction, int]:
        parsed = re.match(regexes.INST_JMP, line, re.IGNORECASE)
        if parsed:
            program_counter += 2
            mnemonic: str = parsed['opcode'].upper() # noqa
            orig_mnemonic = mnemonic
            if mnemonic in JumpInstructionType.ALIASES:
                mnemonic = JumpInstructionType.ALIASES[mnemonic]
            if mnemonic not in JumpInstructionType.ALL:
                raise WrongInstructionError(f"Faild to find instruction {mnemonic} for instruction {line}")
            sign = parsed['sign']
            digits = parsed['digits']
            hex_digits = parsed['hex']
            if digits is not None:
                offset = int(digits)
                orig_offset = digits
            elif hex_digits is not None:
                offset = int(hex_digits, 16)
                orig_offset = "0x"+str(hex_digits)
            else:
                raise AssemblyError("Invalid jump instruction")
            if sign == "-":
                offset = -offset
                orig_offset = "-" + orig_offset
            offset -= 2
            offset /= 2
            if offset % 1 != 0:
                raise AssemblyError("Invalid jump offset: must be even")
            offset = int(offset)
            if offset > 512 or offset < -511:
                raise AssemblyError("Invalid jump offset: must be between -511 and 512 words")
            if offset < 0:
                offset += 1024
            return JumpInstruction(JumpInstructionType.ALL[mnemonic], signed_bin(offset, 10, True), orig_mnemonic, orig_offset), program_counter
        else:
            raise WrongInstructionError("Invalid jump instruction")



class SingleOperandInstructionType(InstructionType):
    ALL: dict[str, Self] = {}

    def __init__(self, mnemonic: str, opcode: str, supports_byte_mode: bool = True):
        """Single operand instruction parser

        :param mnemonic: human-readable instruction name (like "RRA", or "CALL")
        :param opcode: bytecode instruction (like "010", or "101") (the "000100" is automatically prefixed)
        """
        self.mnemonic = mnemonic.upper()
        self.opcode = "000100" + opcode
        self.supports_byte_mode = supports_byte_mode
        self.null_non_operand = self.mnemonic == "RETI"
        assert self.mnemonic not in SingleOperandInstructionType.ALL
        assert len(self.opcode) == 9
        SingleOperandInstructionType.ALL[self.mnemonic] = self
        print(self.mnemonic, self.opcode)

    def opcode_tuple(self) -> tuple[int]:
        return tuple([int(v) for v in self.opcode])

    def get_mnemonic(self) -> str:
        return self.mnemonic

    @classmethod
    def parse(cls, line: str, program_counter: int) -> tuple[SingleOperandInstruction, int]:
        if re.findall(regexes.INST_RETI, line, re.IGNORECASE):
            return RetiInstruction(SingleOperandInstructionType.ALL["RETI"]), program_counter
        parsed = re.findall(regexes.INST_SINGLE_OPERAND, line, re.IGNORECASE)
        if len(parsed) < 1 or len(parsed[0]) != 3:
            raise WrongInstructionError(f"Failed to parse single-operand instruction: {line}")
        program_counter += 2
        mnemonic, byte_mode, src = parsed[0]
        mnemonic = mnemonic.upper()
        if mnemonic == "RETI":
            raise AssemblyError("RETI instruction should not have arguments")
        if mnemonic not in SingleOperandInstructionType.ALL:
            raise WrongInstructionError(f"Failed to find instruction {mnemonic} for instruction {line}")

        op_type = SingleOperandInstructionType.ALL[mnemonic]

        byte_mode = byte_mode.upper().replace(".", "") == "B"

        if byte_mode and not op_type.supports_byte_mode:
            raise AssemblyError(f"Instruction {mnemonic} does not support byte mode")

        src_address = Address(src, program_counter)
        program_counter = src_address.pc_out

        return SingleOperandInstruction(op_type, byte_mode, src_address), program_counter


class DoubleOperandInstructionType(InstructionType):
    ALL: dict[str, Self] = {}

    def __init__(self, mnemonic: str, opcode: str):
        """Double operand instruction parser

        :param mnemonic: human-readable instruction name (like "MOV", or "ADD")
        :param opcode: bytecode instruction (like "0100", or "0101")
        """
        self.mnemonic = mnemonic.upper()
        self.opcode = opcode
        assert self.mnemonic not in DoubleOperandInstructionType.ALL
        assert len(self.opcode) == 4
        DoubleOperandInstructionType.ALL[self.mnemonic] = self
        print(self.mnemonic, self.opcode)

    def opcode_tuple(self) -> tuple[int]:
        return tuple([int(v) for v in self.opcode])

    def get_mnemonic(self) -> str:
        return self.mnemonic

    @classmethod
    def parse(cls, line: str, program_counter: int) -> tuple[DoubleOperandInstruction, int]:
        parsed = re.findall(regexes.INST_DOUBLE_OPERAND, line, re.IGNORECASE)
        if len(parsed) < 1 or len(parsed[0]) != 4:
            raise WrongInstructionError(f"Failed to parse double-operand instruction: {line}")
        program_counter += 2
        mnemonic, byte_mode, src, dst = parsed[0]
        mnemonic = mnemonic.upper()
        byte_mode = byte_mode.upper().replace(".", "") == "B"
        src_address = Address(src, program_counter)
        program_counter = src_address.pc_out
        dst_address = Address(dst, program_counter, True)
        program_counter = dst_address.pc_out
        if mnemonic not in DoubleOperandInstructionType.ALL:
            raise WrongInstructionError(f"Failed to find instruction {mnemonic} for instruction {line}")
        return DoubleOperandInstruction(DoubleOperandInstructionType.ALL[mnemonic], byte_mode, src_address, dst_address), program_counter


def clean_up_comments(line: str) -> str:
    if ";" not in line:
        return line
    return line[:line.index(";")]


class AssemblyError(ValueError):
    pass


class WrongInstructionError(AssemblyError):
    pass


class InvalidDirectiveError(AssemblyError):
    pass


instructions = [
    "RRC",
    "SWPB",
    "RRA",
    "SXT",
    "PUSH",
    "CALL",
    "RETI",

    "JNE", "JNZ",
    "JEQ", "JZ",
    "JNC", "JLO",
    "JC", "JHS",
    "JN",
    "JGE",
    "JL",
    "JMP",

    "MOV",
    "ADD",
    "ADDC",
    "SUBC",
    "SUB",
    "CMP",
    "DADD",
    "BIT",
    "BIC",
    "BIS",
    "XOR",
    "AND"
]


class OpcodeIncrementer:
    def __init__(self, start: int, length: int):
        self.current = start
        self.length = length

    def __call__(self) -> str:
        out = bin(self.current).replace("0b", "")
        self.current += 1
        ret = ("0" * (self.length - len(out))) + out
        assert len(ret) <= self.length
        return ret


box_print("Registering Instructions")

o = OpcodeIncrementer(4, 4)
double_opcode_instructions = ["MOV", "ADD", "ADDC", "SUBC", "SUB", "CMP", "DADD", "BIT", "BIC", "BIS", "XOR", "AND"]
for opc in double_opcode_instructions:
    DoubleOperandInstructionType(opc, o())


o = OpcodeIncrementer(0, 3)
single_opcode_instructions = {
    "RRC": True,
    "SWPB": False,
    "RRA": True,
    "SXT": False,
    "PUSH": True,
    "CALL": False,
    "RETI": False
}
for opc, bm in single_opcode_instructions.items():
    SingleOperandInstructionType(opc, o(), bm)


# instruction: (list of things aliasing to it)
jump_instructions = {
    "JNE": ["JNZ"],
    "JEQ": ["JZ"],
    "JNC": ["JLO"],
    "JC": ["JHS"],
    "JN": [],
    "JGE": [],
    "JL": [],
    "JMP": []
}

o = OpcodeIncrementer(0, 3)

for opc, aliases in jump_instructions.items():
    JumpInstructionType(opc, o())
    for alias in aliases:
        JumpInstructionType.ALIASES[alias] = opc


def e(emulated: str, fmt: str) -> EmulatedInstructionType:
    """

    :param emulated: something like DADC.x dst
    :param fmt: something like DADD.x #0,dst
    :return: built type
    """
    return EmulatedInstructionType(emulated.replace(".x", "").replace(" dst", ""),
                                   "dst" in emulated,
                                   ".x" in emulated,
                                   DoubleOperandInstructionType,
                                   fmt.replace(".x", "{bm}").replace("dst", "{arg}"))

#copied directly from wikipedia!
emulated_instructions = """
ADC.x dst	ADDC.x #0,dst
BR dst	MOV dst,PC
CLR.x dst	MOV.x #0,dst
CLRC	BIC #1,SR
CLRN	BIC #4,SR
CLRZ	BIC #2,SR
DADC.x dst	DADD.x #0,dst
DEC.x dst	SUB.x #1,dst
DECD.x dst	SUB.x #2,dst
DINT	BIC #8,SR
EINT	BIS #8,SR
INC.x dst	ADD.x #1,dst
INCD.x dst	ADD.x #2,dst
INV.x dst	XOR.x #−1,dst
NOP	MOV #0,R3
POP dst	MOV @SP+,dst
RET	MOV @SP+,PC
RLA.x dst	ADD.x dst,dst
RLC.x dst	ADDC.x dst,dst
SBC.x dst	SUBC.x #0,dst
SETC	BIS #1,SR
SETN	BIS #4,SR
SETZ	BIS #2,SR
TST.x dst	CMP.x #0,dst
"""
for emulated_instruction in emulated_instructions.split("\n"):
    if emulated_instruction == "":
        continue
    e(*emulated_instruction.split("\t"))


def u16_to_bytes(i: int) -> bytes:
    high = (i >> 8) & 0xFF
    low = i & 0xFF
    return bytes([low, high])


def parse_line(line: str, program_counter: int) -> tuple[Instruction, int]:
    try:
        instr, program_counter = DoubleOperandInstructionType.parse(line, program_counter)
    except WrongInstructionError as e1:
        try:
            instr, program_counter = SingleOperandInstructionType.parse(line, program_counter)
        except WrongInstructionError as e2:
            try:
                instr, program_counter = JumpInstructionType.parse(line, program_counter)
            except WrongInstructionError as e3:
                try:
                    instr, program_counter = EmulatedInstructionType.parse(line, program_counter)
                except WrongInstructionError as e4:
                    raise AssemblyError(
                        f"Failed to parse instruction: {line}\nDoubleOperand: {e1}\nSingleOperand: {e2}\nJump: {e3}\nEmulated: {e4}") from None
    return instr, program_counter


def parse(lines_text: str, start_pc: int = 0, log_level: int = 1) -> bytes:
    assert start_pc % 2 == 0
    lines = lines_text.split("\n")
    lines = [clean_up_comments(line) for line in lines]
    lines = [line.strip() for line in lines]
    lines = [line for line in lines if line != ""]

    old_lines = lines[:]
    lines = []

    defines = {}
    preliminary_labels = []
    used_symbols = set()

    for line in old_lines:
        if ":" in line:
            key = line.split(":")[0].strip()
            if key == "":
                raise InvalidDirectiveError("Empty label")
            if key in used_symbols or key.upper() in instructions:
                raise InvalidDirectiveError(f"Illegal or redefined label [{key}]")
            if not re.findall(regexes.LABEL, key):
                raise InvalidDirectiveError(f"Invalid label [{key}]")
            used_symbols.add(key)
            preliminary_labels.append(key)
        if line[0] == ".":
            line = line[1:]
            if line.startswith("define"):
                line = line[7:]
                args = re.findall(r"\"(.*)\", *([A-z$_][A-z0-9$_]*)", line)
                if len(args) != 1:
                    print(line, args)
                    raise InvalidDirectiveError("Invalid argument format: should be .define \"Value\", Key")
                value, key = args[0]
                if key in used_symbols or key.upper() in instructions:
                    raise InvalidDirectiveError(f"Illegal or redefined symbol [{key}] = {value}")
                defines[key] = value
                used_symbols.add(key)
            else:
                raise InvalidDirectiveError
        else:
            define_keys = list(defines.keys())
            define_keys.sort(key=lambda x: len(x), reverse=True)
            # fill in already defined defines
            for key in define_keys:
                line = line.replace(key, defines[key])
            lines.append(line)
    # Preliminary parsing for labels
    program_counter = start_pc
    labels = {}
    preliminary_labels.sort(key=lambda x: len(x), reverse=True)
    for line in lines:
        if ":" in line:
            label = line.split(":")[0].strip()
            labels[label] = program_counter
            line = line.split(":")[1].strip()
            if line == "":
                continue
        for label in preliminary_labels:
            line = line.replace(label, "0xa")
        _, program_counter = parse_line(line, program_counter)
    # Actual parsing
    program_counter = start_pc
    instrs = []
    label_keys = list(labels.keys())
    label_keys.sort(key=lambda x: len(x), reverse=True)
    lines_by_pc = {}
    for line in lines:
        prev_pc = program_counter
        lines_by_pc[prev_pc] = line
        if ":" in line:
            # label = line.split(":")[0].strip()
            # labels[label] = program_counter
            line = line.split(":")[1].strip()
            if line == "":
                continue
        for label in label_keys:
            addr = labels[label]
            abs_addr = f"0x{addr:x}".replace("0x-", "-0x")
            rel_addr = f"0x{addr - program_counter:x}".replace("0x-", "-0x")
            # print(f"\n\n\n\nBefore: {line}")
            line = line\
                .replace(f"{label}(", f"{abs_addr}(")\
                .replace(f"#{label}", f"#{abs_addr}")\
                .replace(f"&{label}", f"&{abs_addr}")\
                .replace(f"@{label}", f"{abs_addr}")\
                .replace(label, rel_addr)
            # print(f"After: {line}")
        instr, program_counter = parse_line(line, program_counter)
        instrs.append((prev_pc, instr))
        if log_level >= 3:
            print(program_counter, instrs[-1])

    if log_level >= 2:
        print("--------------------\nLines:")
        print(lines)
        print("--------------------\nDefines:")
        print(defines)
        print("--------------------\nLabels:")
        print(labels)
        for label, addr in labels.items():
            print(f"{label}: 0x{addr:04x}")
    if log_level >= 1:
        print("--------------------\nBytecode:")
#    byte_arrays = []
#    for _, instr in instrs:
#        byte_arrays.extend(instr.get_words())

#    for i, byte_array in enumerate(byte_arrays):
#        print(f"{i*2:04x}: ", end="")
#        bin_str = bytearray_to_bin_str(byte_array)
#        print(f"{bin_str} (0x{int(bin_str, 2):04x})")
    bytes_out = b""
    for pc, instr in instrs:
        words = instr.get_words()
        if log_level >= 1:
            print(f"{Fore.BLUE}{pc:04x}:  {Style.RESET_ALL}", end="")
            print(f"{Fore.MAGENTA}{to_int(words[0]):04x} ", end="")
            if len(words) > 1:
                print(f"{to_int(words[1]):04x} ", end="")
                if len(words) > 2:
                    print(f"{to_int(words[2]):04x} ", end="")
                else:
                    print(" "*5, end="")
            else:
                print(" "*10, end="")
            print(Style.RESET_ALL, end="")
            print(Fore.LIGHTYELLOW_EX +instr.get_mnemonic().lower().ljust(12, " "), end="")
            print(instr.get_args().ljust(20, " ")+Style.RESET_ALL, end="")
            print("; "+lines_by_pc[pc])
        bytes_out += b"".join([u16_to_bytes(to_int(word)) for word in words])
    return bytes_out



dat = parse("""
MOV #0x4400, SP
.define "R6", Test$Macro_1
AdD #10 Test$Macro_1 ;comment
; a comment
  ; more comments
; test weird upper+lowercase mixtures
CmP #11 0(R10)
MOV #test2, R5
JmP -0x8
PUsH.b @R5
; test emulated instructions
DINT
tst.B R10
POP 0(R11)

test_on_a_line:       ; and a comment



jmp test
test: PUSH #14
PUSH #154
test2: PUSH #241
JMP test
JMP test2
MOV #-8, test2(R5)
and.b #-0x1, r5
jmp 0x10 ; this outputs correctly, original would have been jmp 0x10 -> to get from input to correct, use this formula: (original - 2) / 2 --> then convert to signed
SWPB R5
and.b #-0x1, 25(r5)
cmp #0x8, r7
""", 0x4400, 2)

with open("test.bin", "wb") as f:
    f.write(dat)
