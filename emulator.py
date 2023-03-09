try:
    from typing import Self
except ImportError:
    Self = None

class ExecutionError(Exception):
    pass


def u8_to_s8(value: int) -> int:
    # convert integer to signed 8-bit integer using 2's complement
    if value > 0x7f:
        return value - 0x100
    else:
        return value


def s8_to_u8(value: int) -> int:
    # convert signed 8-bit integer to unsigned 8-bit integer using 2's complement
    if value < 0:
        return value + 0x100
    else:
        return value


def u16_to_s16(value: int) -> int:
    # convert integer to signed 16-bit integer using 2's complement
    if value > 0x7fff:
        return value - 0x10000
    else:
        return value


def s16_to_u16(value: int) -> int:
    # convert signed 16-bit integer to unsigned 16-bit integer using 2's complement
    if value < 0:
        return value + 0x10000
    else:
        return value

class Register:
    def __init__(self, number):
        self._contents = bytes(2)
        self.number = number

    def get(self) -> bytes:
        return self._contents

    def set(self, value: bytes):
        self._contents = value

    def get_word(self, signed: bool = False) -> int:
        return int.from_bytes(self._contents, byteorder='big', signed=signed)

    def get_byte(self, signed: bool = False) -> int:
        return int.from_bytes(self._contents[1:2], byteorder='big', signed=signed)

    def set_word(self, value: int, signed: bool = False):
        if value >= 0:
            hex_val = hex(value).replace("0x", "")
        elif signed:
            hex_val = hex(abs(value + 1) ^ 0xffff).replace("0x", "")
        else:
            raise ExecutionError("Attempting to set a negative value to a signed register")
        hex_val = ("0" * (4-len(hex_val))) + hex_val
        self.contents = bytes.fromhex(hex_val)
        assert len(self.contents) == 2

    def set_byte(self, value: int, signed: bool = False):
        if value > 0xff:
            raise ExecutionError("Overflow value")
        if value >= 0:
            hex_val = hex(value).replace("0x", "")
        elif signed:
            hex_val = hex(abs(value + 1) ^ 0xff).replace("0x", "")
        else:
            raise ExecutionError("Attempting to set a negative value to a signed register")
        hex_val = "00" + hex_val
        hex_val = ("0" * (4-len(hex_val))) + hex_val
        self.contents = bytes.fromhex(hex_val)
        assert len(self.contents) == 2

    def __set(self, value: bytes):
        self.set(value)

    def __get(self) -> bytes:
        return self.get()

    contents = property(fget=__get, fset=__set)


class ProgramCounterRegister(Register):
    def __init__(self):
        super().__init__(0)

    def set(self, value: bytes):
        super().set(value)
        if self.get_word() % 2 != 0:
            raise ExecutionError("Program counter must be word-aligned")


class StackPointerRegister(Register):
    def __init__(self):
        super().__init__(1)

    def set(self, value: bytes):
        super().set(value)
        if self.get_word() % 2 != 0:
            raise ExecutionError("Stack pointer must be word-aligned")

    def set_word(self, value: int, signed: bool = False):
        try:
            return super().set_word(value, signed)
        except ExecutionError:
            raise ExecutionError("Stack overflow")

    def set_byte(self, value: int, signed: bool = False):
        try:
            return super().set_byte(value, signed)
        except ExecutionError:
            raise ExecutionError("Stack overflow")


class StatusRegister(Register):
    def __init__(self):
        super().__init__(2)

    def get_byte(self, signed: bool = False) -> int:
        raise ExecutionError("Cannot read SR (R2) in byte mode")

    def set_byte(self, value: int, signed: bool = False):
        raise ExecutionError("Cannot write SR (R2) in byte mode")

    def _get_bit(self, msp430_doc_idx: int) -> bool:
        assert 0 <= msp430_doc_idx <= 15
        return (self.get_word() >> msp430_doc_idx) & 1 == 1

    def _set_bit(self, msp430_doc_idx: int, value: bool):
        assert 0 <= msp430_doc_idx <= 15
        curr = self.get_word()
        if value:
            curr = curr | 2**msp430_doc_idx
        else:
            curr = curr & (0xffff ^ 2**msp430_doc_idx)
        self.set_word(curr)

    def _get_overflow(self) -> bool:
        return self._get_bit(8)

    def _set_overflow(self, val: bool):
        self._set_bit(8, val)

    def _clr_overflow(self):
        self._set_bit(8, False)

    overflow = v = property(_get_overflow, _set_overflow, _clr_overflow)

    def _get_cpu_off(self) -> bool:
        return self._get_bit(4)

    def _set_cpu_off(self, val: bool):
        self._set_bit(4, val)

    def _clr_cpu_off(self):
        self._set_bit(4, False)

    cpu_off = property(_get_cpu_off, _set_cpu_off, _clr_cpu_off)

    def _get_negative(self) -> bool:
        return self._get_bit(2)

    def _set_negative(self, val: bool):
        self._set_bit(2, val)

    def _clr_negative(self):
        self._set_bit(2, False)

    negative = n = property(_get_negative, _set_negative, _clr_negative)

    def _get_zero(self) -> bool:
        return self._get_bit(1)

    def _set_zero(self, val: bool):
        self._set_bit(1, val)

    def _clr_zero(self):
        self._set_bit(1, False)

    zero = z = property(_get_zero, _set_zero, _clr_zero)

    def _get_carry(self) -> bool:
        return self._get_bit(0)

    def _set_carry(self, val: bool):
        self._set_bit(0, val)

    def _clr_carry(self):
        self._set_bit(0, False)

    carry = c = property(_get_carry, _set_carry, _clr_carry)


class ConstantGeneratorRegister(Register):
    def __init__(self):
        super().__init__(3)

    def get(self) -> bytes:
        return b"\x00\x00"


class MemoryMap:
    def __init__(self, size: int):
        self._memory = [0] * size

    def __len__(self):
        return len(self._memory)

    def __getitem__(self, item):
        """
        if slice step is "b", return sequence of bytes, otherwise return sequence (or single) word
        """
        if isinstance(item, slice):
            ret = self._memory[item.start:item.stop]
            if item.step is not None and (item.step.lower() == "b" or item.step is True or item.step == 1) or item.stop-item.start <= 1:
                pass
            elif item.step is None or item.step == "" or item.step.lower() == "w" or item.step is False:
                assert len(ret) % 2 == 0
                ret = [(ret[i] << 8) + ret[i+1] for i in range(0, len(ret), 2)]
            else:
                raise IndexError("Invalid memory address mode")
            if 0 > item.start or item.start > len(self._memory) or 0 > item.stop or item.stop > len(self._memory):
                raise ExecutionError(f"Out of bounds memory access (0x{item.start:04x} - 0x{item.stop:04x}) (bounds 0x0000 - 0x{len(self._memory):04x})")
            if len(ret) == 1:
                ret = ret[0]
            return ret
        else:
            return self._memory[item]

    def __setitem__(self, key, value):
        if isinstance(key, slice):
            number_included = key.stop - key.start
            if key.step is not None and (key.step.lower() == "b" or key.step is True or key.step == 1) or key.stop-key.start <= 1:
                byte_mode = True
            elif key.step is None or key.step == "" or key.step.lower() == "w" or key.step is False:
                byte_mode = False
            else:
                raise IndexError("Invalid memory address mode")
            try:
                length = len(value)
            except TypeError:
                length = 1
                value = [value]
            if not byte_mode and number_included != length * 2:
                raise IndexError("Invalid memory address mode")
            elif byte_mode and number_included != length:
                raise IndexError("Invalid memory address mode")
            if not byte_mode:
                old_val = value[:]
                value = []
                for i in range(len(old_val)):
                    value.append(old_val[i] >> 8)
                    value.append(old_val[i] & 0xff)
            for i in range(len(value)):
                self._memory[key.start + i] = value[i]
                assert isinstance(value[i], int) and 0x00 <= value[i] <= 0xff
        else:
            assert isinstance(value, int) and 0x00 <= value <= 0xff
            self._memory[key] = value


"""
Implementation:
Increment PC before each instruction

for double-operand:
Read source. if as == 01, increment PC (always 2), if as == 11, increment register (1 for byte-mode, 2 for word-mode)
Read dst (and store target). if ad == 1, increment PC
apply operation
write to stored dst

for single-operand:
Read src (and store target). if as == 01, increment PC (always 2), if as == 11, increment register (1 for byte-mode, 2 for word-mode)
apply operation
write to stored src

for jump:
already implemented
"""

class WriteTarget:
    def set_byte(self, val: int, signed: bool = False):
        raise NotImplementedError

    def set_word(self, val: int, signed: bool = False):
        raise NotImplementedError


class VoidWriteTarget(WriteTarget):
    def set_byte(self, val: int, signed: bool = False):
        pass

    def set_word(self, val: int, signed: bool = False):
        pass


class RegisterWriteTarget(WriteTarget):
    def __init__(self, register: Register):
        self.register = register

    def set_byte(self, val: int, signed: bool = False):
        self.register.set_byte(val, signed)

    def set_word(self, val: int, signed: bool = False):
        self.register.set_word(val, signed)

    def __str__(self) -> str:
        if self.register.number == 0:
            extra = " (PC)"
        elif self.register.number == 1:
            extra = " (SP)"
        elif self.register.number == 2:
            extra = " (SR)"
        elif self.register.number == 3:
            extra = " (CG)"
        else:
            extra = ""
        return f"<RegisterWriteTarget register=R{self.register.number}{extra}>"


class MemoryWriteTarget(WriteTarget):
    def __init__(self, addr: int, computer: "Computer"):
        self.addr = addr
        self.computer = computer

    def set_byte(self, val: int, signed: bool = False):
        self.computer.set_byte(self.addr, val, signed)

    def set_word(self, val: int, signed: bool = False):
        self.computer.set_word(self.addr, val, signed)

    def __str__(self) -> str:
        return f"<MemoryWriteTarget addr=0x{self.addr:04x}>"


class Computer:
    def __init__(self):
        self.registers = [ProgramCounterRegister(),  StackPointerRegister(), StatusRegister(), ConstantGeneratorRegister()]
        for i in range(12):
            self.registers.append(Register(i+4))
        self.setup_register_vars()

        self.memory = MemoryMap(0x10000) # 64KB of memory (addresses 0x0000 to 0xffff)

        self.silent = False
        self.input_function = lambda: input("program input: ")
        self.output_function = print
        self._output_buffer = b""

    def print(self, *args, **kwargs):
        if not self.silent:
            print(*args, **kwargs)

    def setup_register_vars(self):
        self.pc: ProgramCounterRegister = self.registers[0] # noqa
        self.sp: StackPointerRegister = self.registers[1] # noqa
        self.sr: StatusRegister = self.registers[2] # noqa
        self.cg: ConstantGeneratorRegister = self.registers[3] # noqa
        self.r0: Register = self.registers[0] # noqa
        self.r1: Register = self.registers[1] # noqa
        self.r2: Register = self.registers[2] # noqa
        self.r3: Register = self.registers[3] # noqa
        self.r4: Register = self.registers[4] # noqa
        self.r5: Register = self.registers[5] # noqa
        self.r6: Register = self.registers[6] # noqa
        self.r7: Register = self.registers[7] # noqa
        self.r8: Register = self.registers[8] # noqa
        self.r9: Register = self.registers[9] # noqa
        self.r10: Register = self.registers[10] # noqa
        self.r11: Register = self.registers[11] # noqa
        self.r12: Register = self.registers[12] # noqa
        self.r13: Register = self.registers[13] # noqa
        self.r14: Register = self.registers[14] # noqa
        self.r15: Register = self.registers[15] # noqa

    def reset(self):
        for i in range(16):
            self.registers[i].set(b"\x00\x00")
        for i in range(len(self.memory)):
            self.memory[i] = 0
        self._output_buffer = b""

    def get_byte(self, addr: int, signed: bool = False) -> int:
        val = self.memory[addr:addr+1]
        if signed:
            val = u8_to_s8(val)
        return val

    def get_word(self, addr: int, signed: bool = False) -> int:
        val = self.memory[addr:addr+2]
        if signed:
            val = u16_to_s16(val)
        return val

    def set_byte(self, addr: int, val: int, signed: bool = False):
        if signed:
            val = s8_to_u8(val)
        self.memory[addr:addr+1] = val

    def set_word(self, addr: int, val: int, signed: bool = False):
        if signed:
            val = s16_to_u16(val)
        self.memory[addr:addr+2] = val

    def print_status(self):
        space = " | "
        line1 = "" # (REG_ REG_ )*8 + (FLAG)
        line2 = "" # (VAL_ VAL_ )*8 + (NZCV)
        named = {
            0: "pc",
            1: "sp",
            2: "sr",
            3: "cg"
        }
        for i in range(16):
            if 3 < i < 10:
                line1 += "0"
            if i in named:
                line1 += named[i]
                line1 += "_" + str(i)
            else:
                line1 += str(i) + "  "
            line1 += space
            line2 += f"{self.registers[i].get_word():04x}" + space
        line1 += "FLAG"
        for name, value in [("N", self.sr.n), ("Z", self.sr.z), ("C", self.sr.c), ("V", self.sr.v)]:
            if value:
                line2 += name
            else:
                line2 += "_"
        self.print("\n\nStatus:")
        self.print(line1)
        self.print(line2)
        self.print("\n\n")

    def step(self):
        # Read opcode from pc, increment pc, execute operation
        if self.pc.get_word() == 0x10:
            self.print("Special case software interrupt")

            interrupt_kind = self.sr.get_word() >> 8 & 0b0111_1111 # only uses 7 bits for interrupts (max 127)

            if interrupt_kind == 0x00:
                self.print("putchar")
                char_val = self.get_word(self.sp.get_word() + 8) & 0xff
                self.print("sp", self.sp.get_word())
#                self.sp.set_word(self.sp.get_word() + 2)
                if char_val >> 7: # continuation byte
                    self._output_buffer += bytes([char_val])
                    # check if we have a full utf-8 char
                    if len(self._output_buffer) != 0:
                        expected_len = bin(self._output_buffer[0]>>4).replace("0b", "").count("1")
                        if len(self._output_buffer) > expected_len:
                            print(f"Error: buffer too long: {self._output_buffer}")
                            self._output_buffer = b""
                    try:
                        character = self._output_buffer.decode("utf-8")
                        if len(self._output_buffer) != expected_len:
                            print(f"Very bad: {self._output_buffer} resolves with the wrong length")
                    except UnicodeDecodeError as e:
                        if len(self._output_buffer) == expected_len:
                            print(f"Very bad: {self._output_buffer} fails to resolve with the correct length, error: {e}")
                            self._output_buffer = b""
#                        print(f"Error decoding utf-8: {e}, buffer: {self._output_buffer}")
                        character = None
                    if character is not None:
                        # print(f"output_buffer: {self._output_buffer}")
                        self.output_function(character, end="")
                        self._output_buffer = b""
                else:
                    self.output_function(chr(char_val), end="")
            elif interrupt_kind == 0x01:
                raise ExecutionError("No clean way to get a single char yet")
            elif interrupt_kind == 0x02:
                print("gets")
                sp = self.sp.get_word()
                dst = self.get_word(sp + 6)
                max_len = self.get_word(sp + 8)
                string = self.input_function()[:max_len]

                for i, v in enumerate(string):
                    self.memory[dst + i] = ord(v)
                self.memory[dst + len(string)] = 0
            elif interrupt_kind == 0x10:
                raise ExecutionError("DEP interrupt not implemented")
            elif interrupt_kind == 0x11:
                raise ExecutionError("DEP set interrupt not implemented")
            elif interrupt_kind == 0x20:
                raise ExecutionError("rand not yet implemented")
            elif interrupt_kind == 0x7d:
                raise ExecutionError("This isn't a LockIT, silly!")
            elif interrupt_kind == 0x7e:
                raise ExecutionError("This isn't a LockIT, silly!")
            elif interrupt_kind == 0x7f:
                raise ExecutionError("This isn't a LockIT, silly!")
            else:
                raise ExecutionError(f"Invalid interrupt kind {interrupt_kind}")

            # go back to normal execution
            self.pc.set_word(self.pc.get_word() + 2)
            # self._execute(0x4130) # ret
            self._execute(0x4130) # ret
        else:
            instruction = self.get_word(self.pc.get_word())
            self.pc.set_word(self.pc.get_word() + 2)
            self._execute(instruction)
            self.print_status()

    def _execute(self, instruction: int):
        # Execute a single TI MSP430 16-bit instruction
        # Decode opcode, execute operation
        # start by deciding if it is a jump instruction, single-operand instruction, or double-operand instruction
        # if the opcode starts with 000100 it is a single-operand instruction
        # if the opcode starts with 001 it is a jump instruction
        # otherwise, it is a double-operand instruction
        # check biggest 3 bits for jump, then check biggest 6 bits for single-operand
        instruction &= 0xffff
        if instruction >> 13 == 0b001:
            self.print("It is a jump instruction")
            self._execute_jump(instruction)
        elif instruction >> 10 == 0b000100:
            self.print("It is a single-operand instruction")
            self._execute_single_operand(instruction)
        else:
            self.print("It is a double-operand instruction")
            self._execute_double_operand(instruction)

    def _execute_jump(self, instruction: int):
        self.print("Jump instruction:", hex(instruction))
        # decode target (lowest 10 bits)
        offset = (instruction & 0b1111111111)
        if offset > 512:
            offset -= 1024
        condition = (instruction >> 10) & 0b111
        if condition == 0b000:   # JNE/JNZ
            self.print("JNE/JNZ")
            if self.sr.z:
                return
        elif condition == 0b001: # JEQ/JZ
            self.print("JEQ/JZ")
            if not self.sr.z:
                return
        elif condition == 0b010: # JNC/JLO
            self.print("JNC/JLO")
            if self.sr.c:
                return
        elif condition == 0b011: # JC/JHS
            self.print("JC/JHS")
            if not self.sr.c:
                return
        elif condition == 0b100: # JN
            self.print("JN")
            if not self.sr.n:
                return
        elif condition == 0b101: # JGE
            self.print("JGE")
            if self.sr.n ^ self.sr.v:
                return
        elif condition == 0b110: # JL
            self.print("JL")
            if not (self.sr.n ^ self.sr.v):
                return
        elif condition == 0b111: # JMP - done
            self.print("JMP")
        else:
            raise ExecutionError("Invalid jump instruction")
        self.pc.set_word(self.pc.get_word() + offset * 2)

    def _get_src(self, src_reg: int, as_: int, bw: bool, output_write_target: bool = False) -> int | tuple[int, WriteTarget]:
        if src_reg == 3 or (src_reg == 2 and as_ != 0b00): # CG or (SR outside of Register mode)
            src = 0
            if src_reg == 2:
                if as_ == 0b01:
                    src = 0
                elif as_ == 0b10:
                    src = 4
                elif as_ == 0b11:
                    src = 8
            elif src_reg == 3:
                if as_ == 0b00:
                    src = 0
                elif as_ == 0b01:
                    src = 1
                elif as_ == 0b10:
                    src = 2
                elif as_ == 0b11:
                    src = 0xff if bw else 0xffff
            if output_write_target:
                return src, VoidWriteTarget()
            else:
                return src
        if as_ == 0b00:
            if bw:
                src = self.registers[src_reg].get_byte()
            else:
                src = self.registers[src_reg].get_word()
            wt = RegisterWriteTarget(self.registers[src_reg])
        elif as_ == 0b01:
            offset = self.get_word(self.pc.get_word()) + self.registers[src_reg].get_word()  # noqa
            offset &= 0xffff
            self.pc.set_word(self.pc.get_word() + 2)
            if bw:
                src = self.get_byte(offset)
            else:
                src = self.get_word(offset)
            wt = MemoryWriteTarget(offset, self)
        elif as_ == 0b10:
            if bw:
                src = self.get_byte(self.registers[src_reg].get_word())
            else:
                src = self.get_word(self.registers[src_reg].get_word())
            wt = MemoryWriteTarget(self.registers[src_reg].get_word(), self)
        elif as_ == 0b11:
            mem_target = self.registers[src_reg].get_word()
            if bw:  # noqa
                src = self.get_byte(mem_target)
                extra = int(self.registers[src_reg] == self.pc or self.registers[src_reg] == self.sp)
                self.registers[src_reg].set_word(mem_target + 1 + extra)
            else:
                src = self.get_word(mem_target)
                self.registers[src_reg].set_word(mem_target + 2)
            wt = MemoryWriteTarget(mem_target, self)
        else:
            raise ExecutionError("Invalid source addressing mode")
        if output_write_target:
            return src, wt
        else:
            return src

    def _execute_single_operand(self, instruction: int): # PUSH implementation: decrement SP, then execute as usual
        self.print("Single-operand instruction:", hex(instruction))
        opcode = (instruction >> 7) & 0b111 # 3-bit
        src_reg = instruction & 0b1111 # 4-bit
        as_ = (instruction >> 4) & 0b11 # 2-bit
        bw = (instruction >> 6) & 0b1 == 1 # 1-bit

        # read source
        src, wt = self._get_src(src_reg, as_, bw, True)
        src: int
        wt: WriteTarget
        self.print("src:", src)

        no_write = False

        # apply operation
        if opcode == 0b000: # RRC
            self.print("RRC")
            # implement rotate right through carry
            goal_carry = src & 0b1 == 1
            src >>= 1
            # put carry back in, taking into account byte-mode as bw
            if bw:
                src |= (self.sr.carry << 7)
            else:
                src |= (self.sr.carry << 15)
            self.sr.carry = goal_carry
            self.sr.n = (src >> (7 if bw else 15) & 1) == 1
            self.sr.z = src == 0
            self.sr.v = False
        elif opcode == 0b001: # SWPB
            self.print("SWPB")
            # swap bytes
            if bw:
                raise ExecutionError("SWPB cannot be used in byte mode")
            src = ((src & 0xff00) >> 8) | ((src & 0xff) << 8)
        elif opcode == 0b010: # RRA
            self.print("RRA")
            self.sr.c = src & 0b1 == 1
            msb_to_or = src & (128 if bw else 32768)
            src >>= 1
            src |= msb_to_or
            self.sr.n = (src >> (7 if bw else 15) & 1) == 1
            self.sr.n = src == 0
            self.v = False
        elif opcode == 0b011: # SXT
            self.print("SXT")
            if bw:
                raise ExecutionError("SXT cannot be used in byte mode")
            src &= 0xff
            if (src >> 7 & 1) == 1:
                src |= 0xff00
                self.sr.n = True
            else:
                self.sr.n = False
            self.sr.z = src == 0
            self.sr.c = src != 0
            self.sr.v = False
        elif opcode == 0b100: # PUSH
            self.print("PUSH")
            self.sp.set_word(self.sp.get_word() - 2)
            if isinstance(wt, RegisterWriteTarget) and wt.register == self.pc:
                if bw:
                    src = self.pc.get_byte()
                else:
                    src = self.pc.get_word()
            no_write = True
            if bw:
                self.set_byte(self.sp.get_word(), src)
            else:
                self.set_word(self.sp.get_word(), src)
        elif opcode == 0b101: # CALL
            self.print("CALL")
            if bw:
                raise ExecutionError("CALL cannot be used in byte mode")
            self.sp.set_word(self.sp.get_word() - 2)
            self.set_word(self.sp.get_word(), self.pc.get_word())
            self.pc.set_word(src)
            no_write = True
        elif opcode == 0b110: # RETI
            self.print("RETI")
            raise NotImplementedError("RETI is not implemented, because interrupts don't exist")
        else:
            raise ExecutionError("Invalid single-operand opcode")

        # write value to dst
        if not no_write:
            if bw:
                wt.set_byte(src)
            else:
                wt.set_word(src)
    def _set_flags(self, src: int, prev_dst: int, full_dst: int, dst: int, byte_mode: bool):
        # set flags NZCV
        self.sr.zero = dst == 0
        self.sr.negative = (dst >> (7 if byte_mode else 15) & 1) == 1
        self.sr.carry = full_dst > (0xff if byte_mode else 0xffff)
        # overflow is set if the sign of the operands is the same, and the sign of the result is different (e.g. positive + positive = negative, or negative + negative = positive)
        self.sr.overflow = ((prev_dst >> (7 if byte_mode else 15) & 1) == (src >> (7 if byte_mode else 15) & 1)) and (
                    (prev_dst >> (7 if byte_mode else 15) & 1) != (dst >> (7 if byte_mode else 15) & 1))

    def _execute_double_operand(self, instruction: int):  # MOV order: read value, increment if needed, set value
        self.print("Double-operand instruction:", hex(instruction))
        opcode = instruction >> 12 # 4-bit
        src_reg = instruction >> 8 & 0b1111 # 4-bit
        ad = instruction >> 7 & 0b1 # 1-bit
        bw = instruction >> 6 & 0b1 == 1 # 1-bit (boolean)
        as_ = instruction >> 4 & 0b11 # 2-bit
        dst_reg = instruction & 0b1111 # 4-bit

        # read source
        src: int = self._get_src(src_reg, as_, bw)

        self.print(src)
        # read value of dst and make a WriteTarget
        if ad == 0b0:
            if bw:
                dst = self.registers[dst_reg].get_byte()
            else:
                dst = self.registers[dst_reg].get_word()
            wt = RegisterWriteTarget(self.registers[dst_reg])
        elif ad == 0b1:
            offset = self.get_word(self.pc.get_word()) + self.registers[dst_reg].get_word()  # noqa
            offset &= 0xffff
            self.pc.set_word(self.pc.get_word() + 2)
            if bw:
                dst = self.get_byte(offset)
            else:
                dst = self.get_word(offset)
            wt = MemoryWriteTarget(offset, self)
        else:
            raise ExecutionError("Invalid addressing destination mode")
        self.print("dst:", dst, "wt:", wt)

        no_write = False

        # apply operation
#        print("Totally executing opcode", hex(opcode), bin(opcode))
        if opcode == 0b0100:  # MOV - done
            self.print("MOV")
            dst = src
        elif opcode == 0b0101:  # ADD - done
            self.print("ADD")
            prev_dst = dst
            dst += src
            dst_full = dst
            dst = dst & (0xff if bw else 0xffff)
            self._set_flags(src, prev_dst, dst_full, dst, bw)
        elif opcode == 0b0110:  # ADDC - done
            self.print("ADDC")
            prev_dst = dst
            dst += src + self.sr.carry
            dst_full = dst
            dst = dst & (0xff if bw else 0xffff)
            self._set_flags(src, prev_dst, dst_full, dst, bw)
        elif opcode == 0b0111:  # SUBC - done
            self.print("SUBC")
            prev_dst = dst
            dst = dst - src - 1 + self.sr.carry
            dst_full = dst
            dst = dst & (0xff if bw else 0xffff)
            self._set_flags(src, prev_dst, dst_full, dst, bw)
        elif opcode == 0b1000:  # SUB - done
            self.print("SUB")
            prev_dst = dst
            dst -= src
            dst_full = dst
            dst = dst & (0xff if bw else 0xffff)
            self._set_flags(src, prev_dst, dst_full, dst, bw)
        elif opcode == 0b1001:  # CMP - done
            self.print("CMP")
            # do like SUB but use fake_dst instead of writing to dst
            prev_dst = dst
            fake_dst = dst - src
            dst_full = fake_dst
            fake_dst = fake_dst & (0xff if bw else 0xffff)
            self._set_flags(src, prev_dst, dst_full, fake_dst, bw)
            no_write = True
        elif opcode == 0b1010:  # DADD
            self.print("DADD")
            raise NotImplementedError("DADD")
        elif opcode == 0b1011:  # BIT - done
            self.print("BIT")
            #don't actually place in destination
            prev_dst = dst
            fake_dst = dst & src
            dst_full = fake_dst
            fake_dst = fake_dst & (0xff if bw else 0xffff)
            self._set_flags(src, prev_dst, dst_full, fake_dst, bw)
            self.sr.c = not self.sr.zero
            self.sr.v = False
            no_write = True
        elif opcode == 0b1100:  # BIC - done
            self.print("BIC")
            dst &= ~src
        elif opcode == 0b1101:  # BIS - done
            self.print("BIS")
            dst |= src
        elif opcode == 0b1110:  # XOR - done
            self.print("XOR")
            prev_dst = dst
            dst ^= src
            self.sr.n = (dst >> (7 if bw else 15) & 1) == 1
            self.sr.z = dst == 0
            self.sr.c = dst != 0
            # src.v if src and prev_dst are negative
            self.sr.v = (src >> (7 if bw else 15) & 1) == 1 and (prev_dst >> (7 if bw else 15) & 1) == 1
        elif opcode == 0b1111:  # AND - done
            self.print("AND")
            dst &= src
            self.sr.n = (dst >> (7 if bw else 15) & 1) == 1
            self.sr.z = dst == 0
            self.sr.c = dst != 0
            self.v = False
        else:
            raise ExecutionError("Invalid double-operand opcode")

        # write value to dst
        if not no_write:
            if bw:
                wt.set_byte(dst)
            else:
                wt.set_word(dst)


if __name__ == "__main__":
    c = Computer()
    # load in a jump, single-operand, and a double-operand instruction
    c.memory[0x0000:0x0002] = 0x3c07 # jmp         0x10
    c.memory[0x0010:0x0012] = 0x1085 # swpb        R5
    c.memory[0x0012:0x0014] = 0xf375 # and.b       #-0x1, r5
    c.memory[0x0014:0x0016] = 0xf3f5 # and.b       #-0x1, 25(r5) ; 1st word (has 1 extension word)
    c.memory[0x0016:0x0018] = 0x0019 # and.b       #-0x1, 25(r5) ; 2nd word (extension word)
    c.memory[0x0018:0x001a] = 0x9237 # cmp         #0x8, r7
    c.step()
    print(c.pc.get_word())
    c.step()
    print(c.pc.get_word())
    c.step()
    print(c.pc.get_word())
    c.step()
    print(c.pc.get_word())
    c.step()
    print(c.pc.get_word())
