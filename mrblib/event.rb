module Wslay
  module Event
    class OnMsgRecvArg < Struct.new(:rsv, :opcode, :msg, :status_code) do
        def to_str
          msg
        end
      end
    end

    class Callbacks
      def recv_callback(&block)
        raise ArgumentError, "no block given" unless block_given?
        @recv_callback = block
      end

      def send_callback(&block)
        raise ArgumentError, "no block given" unless block_given?
        @send_callback = block
      end

      def genmask_callback(&block)
        raise ArgumentError, "no block given" unless block_given?
        @genmask_callback = block
      end

      def on_msg_recv_callback(&block)
        raise ArgumentError, "no block given" unless block_given?
        @on_msg_recv_callback = block
      end
    end
  end
end
