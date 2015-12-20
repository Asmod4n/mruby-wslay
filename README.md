# mruby-wslay

wslay is a callback based WebSocket Client and Server library written in C, it doesn't come with a event loop or does I/O operations on its own. https://github.com/tatsuhiro-t/wslay

Currently this wrapper needs https://github.com/jedisct1/libsodium, installation instructions: https://download.libsodium.org/doc/installation/index.html.

The following callbacks are exposed in this wrapper

```ruby
wslay_callbacks = Wslay::Event::Callbacks.new

wslay_callbacks.recv_callback do |buf, len|
  # when wslay wants to read data
  # buf is a cptr, if your I/O gem can write to a C pointer you have to write at most len bytes into it
  # or else return a mruby String or a object which can be converted into a String via to_str
  # and be up to len bytes long
  # the I/O object must be in non blocking mode and return EAGAIN/EWOULDBLOCK when there is nothing to read
end

wslay_callbacks.on_msg_recv_callback do |msg|
  # when a WebSocket msg is fully recieved this callback is called
  # you get a Wslay::Event::OnMsgRecvArg Struct back with the following fields
  # :rsv => reserved field from WebSocket spec, there are Wslay.get_rsv1/2/3 helper methods
  # :opcode => :continuation_frame, :text_frame, :binary_frame, :connection_close, :ping or
  # :pong, Wslay.is_ctrl_frame? helper method is provided too
  # :msg => the message revieced
  # :status_code => :normal_closure, :going_away, :protocol_error, :unsupported_data, :no_status_rcvd,
  # :abnormal_closure, :invalid_frame_payload_data, :policy_violation, :message_too_big, :mandatory_ext,
  # :internal_server_error, :tls_handshake
  # to_str => returns the message revieced
end

wslay_callbacks.send_callback |buf|
  # when there is data to send, you have to return the bytes send here
  # the I/O object must be in non blocking mode and return EAGAIN/EWOULDBLOCK when sending would block
end
```

How to setup
```ruby
client = Wslay::Event::Client.new wslay_callbacks
```

To queue a message for sending
```ruby
client.queue_msg("hello world", #optional :opcode)
```

To queue a close message
```ruby
client.queue_close(:status_code, #optional reason)
```

For a fully working example: https://github.com/Asmod4n/mruby-websockets/blob/master/mrblib/client.rb

Acknowledgements
================
This is using code from https://github.com/tatsuhiro-t/wslay

The MIT License

Copyright (c) 2011, 2012, 2015 Tatsuhiro Tsujikawa

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
