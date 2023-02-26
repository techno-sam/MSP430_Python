########
# Misc #
########
UNSIGNED_NUMBER = r"^(?:(?:0[xX](?P<hex>[0-9a-fA-F]{1,4}))|(?P<digits>\d+))$"
SIGN = r"(?P<sign>[-+]?)"


#############
# Registers #
#############
# All of these should be matched case insensitive
REGISTER_DIRECT = r"^(?P<reg>PC|SP|SR|CG|(?:R[0-9])|(?:R1[0-5]))$"
REGISTER_INDEXED = r"^"+SIGN+r"(?:(?:0[xX](?P<hex>[0-9a-fA-F]{1,4}))|(?P<digits>\d+))" \
                   r"[(](?P<reg>PC|SP|SR|CG|(?:R[0-9])|(?:R1[0-5]))[)]$"

# also optionally matches autoincrement
REGISTER_INDIRECT = r"^@(?P<reg>PC|SP|SR|CG|(?:R[0-9])|(?:R1[0-5]))(?P<autoincrement>\+?)$"

REGISTER_SYMBOLIC = UNSIGNED_NUMBER  # 0x0fe2 or 234 are memory addresses of operand
REGISTER_ABSOLUTE = r"^&(?:(?:0[xX](?P<hex>[0-9a-fA-F]{1,4}))|(?P<digits>\d+))$" # noqa: similar to above, absolute mode used though
REGISTER_IMMEDIATE = r"^#"+SIGN+r"(?:(?:0[xX](?P<hex>[0-9a-fA-F]{1,4}))|(?P<digits>\d+))$"


################
# Instructions #
################
INST_DOUBLE_OPERAND = r"^(?P<opcode>[a-zA-Z]+)(?P<byte_mode>\.[BbWw])?(?:\s+)(?P<operand_src>[#A-Za-z0-9@\(\)+]+)(?:(?:,\s*)|(?:\s+))(?P<operand_dst>[#A-Za-z0-9@\(\)+]+)$"
INST_SINGLE_OPERAND = r"^(?P<opcode>[a-zA-Z]+)(?P<byte_mode>\.[BbWw])?(?:\s+)(?P<operand_src>[#A-Za-z0-9@\(\)+]+)$"
INST_RETI = r"^RETI$"
INST_JMP = r"^(?P<opcode>[a-zA-Z]+)(?:\s+)"+SIGN+r"(?:(?:0[xX](?P<hex>[0-9a-fA-F]{1,4}))|(?P<digits>\d+))$"
INST_EMULATED = r"^(?P<opcode>[a-zA-Z]+)(?P<byte_mode>\.[BbWw])?((?:\s+)(?P<operand_src>[#A-Za-z0-9@\(\)+]+))?$"