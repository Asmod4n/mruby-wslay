module Wslay
  def self.is_ctrl_frame?(opcode)
    opcode = Integer(OpCode[opcode])
    ((opcode >> 3) & 1) != 0
  end

  def self.get_rsv1(rsv)
    rsv = Integer(rsv)
    ((rsv >> 2) & 1)
  end

  def self.get_rsv2(rsv)
    rsv = Integer(rsv)
    ((rsv >> 1) & 1)
  end

  def self.get_rsv3(rsv)
    rsv = Integer(rsv)
    (rsv & 1)
  end
end
