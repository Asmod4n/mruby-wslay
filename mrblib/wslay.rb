module Wslay
  def self.is_ctrl_frame?(opcode)
    opcode = Integer(OpCode[opcode])
    ((opcode >> 3) & 1) != 0
  end
end
