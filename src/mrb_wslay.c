#include "mruby/wslay.h"
#include "mrb_wslay.h"

static void
mrb_wslay_event_on_msg_recv_callback(wslay_event_context_ptr ctx,
  const struct wslay_event_on_msg_recv_arg *arg, void *user_data)
{
  mrb_wslay_user_data *data = (mrb_wslay_user_data *) user_data;
  mrb_state *mrb = data->mrb;

  int ai = mrb_gc_arena_save(mrb);
  struct mrb_jmpbuf *prev_jmp = mrb->jmp;
  struct mrb_jmpbuf c_jmp;

  MRB_TRY(&c_jmp) {
    mrb->jmp = &c_jmp;

    mrb_value argv[4];
    argv[0] = mrb_fixnum_value(arg->rsv);
    argv[1] = MRB_GET_OPCODE(mrb_fixnum_value(arg->opcode));
    argv[2] = mrb_str_new(mrb, (const char *) arg->msg, arg->msg_length);
    argv[3] = MRB_GET_STATUSCODE(mrb_fixnum_value(arg->status_code));

    mrb_value on_msg_recv_arg = mrb_obj_new(mrb,
      mrb_class_get_under(mrb,
        mrb_module_get_under(mrb,
          mrb_module_get(mrb, "Wslay"), "Event"), "OnMsgRecvArg"), NELEMS(argv), argv);

    mrb_assert(mrb_type(data->on_msg_recv_callback) == MRB_TT_PROC);
    mrb_yield(mrb, data->on_msg_recv_callback, on_msg_recv_arg);

    mrb_gc_arena_restore(mrb, ai);

    mrb->jmp = prev_jmp;
  } MRB_CATCH(&c_jmp) {
    mrb->jmp = prev_jmp;
    wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
    mrb_gc_arena_restore(mrb, ai);
    MRB_THROW(mrb->jmp);
  } MRB_END_EXC(&c_jmp);
}

static ssize_t
mrb_wslay_event_recv_callback(wslay_event_context_ptr ctx,
  uint8_t *buf, size_t len, int flags, void *user_data)
{
  mrb_wslay_user_data *data = (mrb_wslay_user_data *) user_data;
  mrb_state*mrb = data->mrb;
  int ai = mrb_gc_arena_save(mrb);

  struct mrb_jmpbuf *prev_jmp = mrb->jmp;
  struct mrb_jmpbuf c_jmp;

  mrb_int ret = -1;
  MRB_TRY(&c_jmp) {
    mrb->jmp = &c_jmp;

    mrb_value argv[2];
    argv[0] = mrb_cptr_value(mrb, buf);
    argv[1] = mrb_fixnum_value(len);

    errno = 0;
    mrb_assert(mrb_type(data->recv_callback) == MRB_TT_PROC);
    mrb_value buf_obj = mrb_yield_argv(mrb, data->recv_callback, NELEMS(argv), argv);

    if (mrb_fixnum_p(buf_obj)) {
      ret = mrb_fixnum(buf_obj);
    } else {
      buf_obj = mrb_str_to_str(mrb, buf_obj);
      ret = RSTRING_LEN(buf_obj);
      if (ret < 0||ret > len) {
        mrb_raise(mrb, E_RANGE_ERROR, "returned buf doesn't fit");
      }
      if (ret > 0) {
        memmove(buf, (uint8_t *) RSTRING_PTR(buf_obj), ret);
      }
    }

    mrb->jmp = prev_jmp;
  } MRB_CATCH(&c_jmp) {
    mrb->jmp = prev_jmp;
    if (mrb_obj_is_kind_of(mrb,
        mrb_obj_value(mrb->exc),
            mrb_class_get_under(mrb,
                mrb_module_get(mrb, "Errno"), "EAGAIN"))||
    mrb_obj_is_kind_of(mrb,
        mrb_obj_value(mrb->exc),
            mrb_class_get_under(mrb,
                mrb_module_get(mrb, "Errno"), "EWOULDBLOCK"))) {
      mrb->exc = NULL;
      wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
    } else {
      wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
    }
  } MRB_END_EXC(&c_jmp);

  mrb_gc_arena_restore(mrb, ai);

  return ret;
}

static ssize_t
mrb_wslay_event_send_callback(wslay_event_context_ptr ctx,
  const uint8_t *buf, size_t len,
  int flags, void *user_data)
{
  mrb_wslay_user_data *data = (mrb_wslay_user_data *) user_data;
  mrb_state* mrb = data->mrb;
  int ai = mrb_gc_arena_save(mrb);

  struct mrb_jmpbuf *prev_jmp = mrb->jmp;
  struct mrb_jmpbuf c_jmp;
  mrb_int ret = -1;
  MRB_TRY(&c_jmp) {
    data->mrb->jmp = &c_jmp;

    errno = 0;
    mrb_value buf_obj = mrb_str_new_static(mrb, (const char *) buf, len);
    mrb_assert(mrb_type(data->send_callback) == MRB_TT_PROC);
    mrb_value sent = mrb_yield(mrb, data->send_callback, buf_obj);

    ret = mrb_int(mrb, sent);

    mrb_assert(ret >= 0&&ret <= len);

    mrb->jmp = prev_jmp;
  } MRB_CATCH(&c_jmp) {
    mrb->jmp = prev_jmp;
    if (mrb_obj_is_kind_of(mrb,
        mrb_obj_value(mrb->exc),
            mrb_class_get_under(mrb,
                mrb_module_get(mrb, "Errno"), "EAGAIN"))||
    mrb_obj_is_kind_of(mrb,
        mrb_obj_value(mrb->exc),
            mrb_class_get_under(mrb,
                mrb_module_get(mrb, "Errno"), "EWOULDBLOCK"))) {
      mrb->exc = NULL;
      wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
    } else {
      wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
    }
  } MRB_END_EXC(&c_jmp);

  mrb_gc_arena_restore(mrb, ai);

  return ret;
}

static int
mrb_wslay_event_genmask_callback(wslay_event_context_ptr ctx,
  uint8_t *buf, size_t len,
  void *user_data)
{
  mrb_sysrandom_buf(buf, len);

  return 0;
}

static mrb_value
mrb_wslay_event_config_set_no_buffering(mrb_state *mrb, mrb_value self)
{
  mrb_wslay_user_data *data = (mrb_wslay_user_data *) DATA_PTR(self);
  mrb_assert(data);

  mrb_bool val;

  mrb_get_args(mrb, "b", &val);

  wslay_event_config_set_no_buffering(data->ctx, val);

  return self;
}

static mrb_value
mrb_wslay_event_config_set_max_recv_msg_length(mrb_state *mrb, mrb_value self)
{
  mrb_wslay_user_data *data = (mrb_wslay_user_data *) DATA_PTR(self);
  mrb_assert(data);

  mrb_int val;

  mrb_get_args(mrb, "i", &val);

  if (val < 0||val > UINT64_MAX)
    mrb_raise(mrb, E_RANGE_ERROR, "val is out of range");

  wslay_event_config_set_max_recv_msg_length(data->ctx, val);

  return self;
}

static mrb_value
mrb_wslay_event_recv(mrb_state *mrb, mrb_value self)
{
  mrb_wslay_user_data *data = (mrb_wslay_user_data *) DATA_PTR(self);
  mrb_assert(data);

  int err = wslay_event_recv(data->ctx);
  if (err == WSLAY_ERR_NOMEM) {
    mrb_sys_fail(mrb, "wslay_event_recv");
  }
  else if (err == WSLAY_ERR_CALLBACK_FAILURE) {
    mrb_exc_raise(mrb, mrb_obj_value(mrb->exc));
  }
  else if (err != 0) {
    return MRB_WSLAY_ERROR(mrb_fixnum_value(err));
  }

  return self;
}

static mrb_value
mrb_wslay_event_send(mrb_state *mrb, mrb_value self)
{
  mrb_wslay_user_data *data = (mrb_wslay_user_data *) DATA_PTR(self);
  mrb_assert(data);

  int err = wslay_event_send(data->ctx);
  if (err == WSLAY_ERR_NOMEM) {
    mrb_sys_fail(mrb, "wslay_event_send");
  }
  else if (err == WSLAY_ERR_CALLBACK_FAILURE) {
    mrb_exc_raise(mrb, mrb_obj_value(mrb->exc));
  }
  else if (err != 0) {
    return MRB_WSLAY_ERROR(mrb_fixnum_value(err));
  }

  return self;
}

static mrb_value
mrb_wslay_event_queue_msg(mrb_state *mrb, mrb_value self)
{
  mrb_wslay_user_data *data = (mrb_wslay_user_data *) DATA_PTR(self);
  mrb_assert(data);

  mrb_value msg;
  mrb_sym opcode;

  mrb_int opc;

  if (mrb_get_args(mrb, "S|n", &msg, &opcode) == 1) {
    if (mrb_str_is_utf8(msg)) {
      opc = WSLAY_TEXT_FRAME;
    } else {
      opc = WSLAY_BINARY_FRAME;
    }
  } else {
    opc = mrb_fixnum(MRB_GET_OPCODE(mrb_symbol_value(opcode)));
  }

  struct wslay_event_msg msgarg = {
    opc, (const uint8_t *) RSTRING_PTR(msg), RSTRING_LEN(msg)
  };

  int err = wslay_event_queue_msg(data->ctx, &msgarg);
  if (err == WSLAY_ERR_NOMEM) {
    mrb_sys_fail(mrb, "wslay_event_queue_msg");
  }
  else if (err == WSLAY_ERR_NO_MORE_MSG) {
    mrb_raise(mrb, E_WSLAY_ERROR, "further message queueing is not allowed");
  }
  else if (err == WSLAY_ERR_INVALID_ARGUMENT) {
    mrb_raise(mrb, E_WSLAY_ERROR, "the given message is invalid");
  }
  else if (err != 0) {
    return MRB_WSLAY_ERROR(mrb_fixnum_value(err));
  }

  return self;
}

static mrb_value
mrb_wslay_event_queue_close(mrb_state *mrb, mrb_value self)
{
  mrb_wslay_user_data *data = (mrb_wslay_user_data *) DATA_PTR(self);
  mrb_assert(data);

  mrb_sym status_code;
  char *reason = NULL;
  mrb_int reason_length = 0;

  mrb_get_args(mrb, "n|s!", &status_code, &reason, &reason_length);

  mrb_int stc = mrb_fixnum(MRB_GET_STATUSCODE(mrb_symbol_value(status_code)));

  int err = wslay_event_queue_close(data->ctx, stc, (const uint8_t *) reason, reason_length);
  if (err == WSLAY_ERR_NOMEM) {
    mrb_sys_fail(mrb, "wslay_event_queue_close");
  }
  else if (err == WSLAY_ERR_NO_MORE_MSG) {
    mrb_raise(mrb, E_WSLAY_ERROR, "further message queueing is not allowed");
  }
  else if (err == WSLAY_ERR_INVALID_ARGUMENT) {
    mrb_raise(mrb, E_WSLAY_ERROR, "the given message is invalid");
  }
  else if (err != 0) {
    return MRB_WSLAY_ERROR(mrb_fixnum_value(err));
  }

  return self;
}

static mrb_value
mrb_wslay_event_want_read(mrb_state *mrb, mrb_value self)
{
  return mrb_bool_value(wslay_event_want_read(((mrb_wslay_user_data *) DATA_PTR(self))->ctx));
}

static mrb_value
mrb_wslay_event_want_write(mrb_state *mrb, mrb_value self)
{
  return mrb_bool_value(wslay_event_want_write(((mrb_wslay_user_data *) DATA_PTR(self))->ctx));
}

static mrb_value
mrb_wslay_event_get_close_received(mrb_state *mrb, mrb_value self)
{
  return mrb_bool_value(wslay_event_get_close_received(((mrb_wslay_user_data *) DATA_PTR(self))->ctx));
}

static mrb_value
mrb_wslay_event_get_close_sent(mrb_state *mrb, mrb_value self)
{
  return mrb_bool_value(wslay_event_get_close_sent(((mrb_wslay_user_data *) DATA_PTR(self))->ctx));
}

static mrb_value
mrb_wslay_event_get_status_code_received(mrb_state *mrb, mrb_value self)
{
  return MRB_GET_STATUSCODE(mrb_fixnum_value(wslay_event_get_status_code_received(((mrb_wslay_user_data *) DATA_PTR(self))->ctx)));
}

static mrb_value
mrb_wslay_event_get_status_code_sent(mrb_state *mrb, mrb_value self)
{
  return MRB_GET_STATUSCODE(mrb_fixnum_value(wslay_event_get_status_code_sent(((mrb_wslay_user_data *) DATA_PTR(self))->ctx)));
}

static mrb_value
mrb_wslay_event_get_queued_msg_count(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(wslay_event_get_queued_msg_count(((mrb_wslay_user_data *) DATA_PTR(self))->ctx));
}

static mrb_value
mrb_wslay_event_get_queued_msg_length(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(wslay_event_get_queued_msg_length(((mrb_wslay_user_data *) DATA_PTR(self))->ctx));
}

static mrb_value
mrb_wslay_event_context_server_init(mrb_state *mrb, mrb_value self)
{
  mrb_value callbacks_obj;

  mrb_get_args(mrb, "o", &callbacks_obj);

  mrb_value recv_callback, send_callback, on_msg_recv_callback;
  recv_callback = mrb_iv_get(mrb, callbacks_obj, mrb_intern_lit(mrb, "@recv_callback"));
  if (mrb_type(recv_callback) != MRB_TT_PROC) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "recv_callback missing");
  }
  send_callback = mrb_iv_get(mrb, callbacks_obj, mrb_intern_lit(mrb, "@send_callback"));
  if (mrb_type(send_callback) != MRB_TT_PROC) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "send_callback missing");
  }
  on_msg_recv_callback = mrb_iv_get(mrb, callbacks_obj, mrb_intern_lit(mrb, "@on_msg_recv_callback"));
  if (mrb_type(on_msg_recv_callback) != MRB_TT_PROC) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "on_msg_recv_callback missing");
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "callbacks"), callbacks_obj);
  mrb_wslay_user_data *data = (mrb_wslay_user_data *) mrb_malloc(mrb, sizeof(mrb_wslay_user_data));
  mrb_data_init(self, data, &mrb_wslay_user_data_type);
  data->mrb = mrb;
  data->recv_callback = recv_callback;
  data->send_callback = send_callback;
  data->on_msg_recv_callback = on_msg_recv_callback;
  struct wslay_event_callbacks server_callbacks = {
    mrb_wslay_event_recv_callback,
    mrb_wslay_event_send_callback,
    NULL,
    NULL,
    NULL,
    NULL,
    mrb_wslay_event_on_msg_recv_callback
  };

  int err = wslay_event_context_server_init(&data->ctx, &server_callbacks, data);
  if (err == WSLAY_ERR_NOMEM) {
    mrb_sys_fail(mrb, "wslay_event_context_server_init");
  }
  else if (err != 0) {
    return MRB_WSLAY_ERROR(mrb_fixnum_value(err));
  }

  return self;
}

static mrb_value
mrb_wslay_event_context_client_init(mrb_state *mrb, mrb_value self)
{
  mrb_value callbacks_obj;

  mrb_get_args(mrb, "o", &callbacks_obj);

  mrb_value recv_callback, send_callback, on_msg_recv_callback;
  recv_callback = mrb_iv_get(mrb, callbacks_obj, mrb_intern_lit(mrb, "@recv_callback"));
  if (mrb_type(recv_callback) != MRB_TT_PROC) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "recv_callback missing");
  }
  send_callback = mrb_iv_get(mrb, callbacks_obj, mrb_intern_lit(mrb, "@send_callback"));
  if (mrb_type(send_callback) != MRB_TT_PROC) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "send_callback missing");
  }
  on_msg_recv_callback = mrb_iv_get(mrb, callbacks_obj, mrb_intern_lit(mrb, "@on_msg_recv_callback"));
  if (mrb_type(on_msg_recv_callback) != MRB_TT_PROC) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "on_msg_recv_callback missing");
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "callbacks"), callbacks_obj);
  mrb_wslay_user_data *data = (mrb_wslay_user_data *) mrb_malloc(mrb, sizeof(mrb_wslay_user_data));
  mrb_data_init(self, data, &mrb_wslay_user_data_type);
  data->mrb = mrb;
  data->recv_callback = recv_callback;
  data->send_callback = send_callback;
  data->on_msg_recv_callback = on_msg_recv_callback;
  struct wslay_event_callbacks client_callbacks = {
    mrb_wslay_event_recv_callback,
    mrb_wslay_event_send_callback,
    mrb_wslay_event_genmask_callback,
    NULL,
    NULL,
    NULL,
    mrb_wslay_event_on_msg_recv_callback
  };

  int err = wslay_event_context_client_init(&data->ctx, &client_callbacks, data);
  if (err == WSLAY_ERR_NOMEM) {
    mrb_sys_fail(mrb, "wslay_event_context_client_init");
  }
  else if (err != 0) {
    return MRB_WSLAY_ERROR(mrb_fixnum_value(err));
  }

  return self;
}

static mrb_value
mrb_wslay_get_rsv1(mrb_state *mrb, mrb_value self)
{
  mrb_int rsv;

  mrb_get_args(mrb, "i", &rsv);

  return mrb_fixnum_value(wslay_get_rsv1(rsv));
}

static mrb_value
mrb_wslay_get_rsv2(mrb_state *mrb, mrb_value self)
{
  mrb_int rsv;

  mrb_get_args(mrb, "i", &rsv);

  return mrb_fixnum_value(wslay_get_rsv2(rsv));
}

static mrb_value
mrb_wslay_get_rsv3(mrb_state *mrb, mrb_value self)
{
  mrb_int rsv;

  mrb_get_args(mrb, "i", &rsv);

  return mrb_fixnum_value(wslay_get_rsv3(rsv));
}

void
mrb_mruby_wslay_gem_init(mrb_state* mrb) {
  struct RClass *wslay_mod, *wslay_error_cl, *wslay_event_mod,
  *wslay_event_context_cl, *wslay_event_context_server_cl, *wslay_event_context_client_cl;

  wslay_mod = mrb_define_module(mrb, "Wslay");
  mrb_define_module_function(mrb, wslay_mod, "get_rsv1", mrb_wslay_get_rsv1, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, wslay_mod, "get_rsv2", mrb_wslay_get_rsv2, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, wslay_mod, "get_rsv3", mrb_wslay_get_rsv3, MRB_ARGS_REQ(1));
  wslay_error_cl = mrb_define_class_under(mrb, wslay_mod, "Err", E_RUNTIME_ERROR);
  mrb_value wslay_error_hash = mrb_hash_new_capa(mrb, 9 * 2);
  mrb_define_const(mrb, wslay_mod, "Error", wslay_error_hash);
  mrb_hash_set(mrb, wslay_error_hash, mrb_fixnum_value(WSLAY_ERR_WANT_READ), mrb_symbol_value(mrb_intern_lit(mrb, "want_read")));
  mrb_hash_set(mrb, wslay_error_hash, mrb_fixnum_value(WSLAY_ERR_WANT_WRITE), mrb_symbol_value(mrb_intern_lit(mrb, "want_write")));
  mrb_hash_set(mrb, wslay_error_hash, mrb_fixnum_value(WSLAY_ERR_PROTO), mrb_symbol_value(mrb_intern_lit(mrb, "proto")));
  mrb_hash_set(mrb, wslay_error_hash, mrb_fixnum_value(WSLAY_ERR_INVALID_ARGUMENT), mrb_symbol_value(mrb_intern_lit(mrb, "invalid_argument")));
  mrb_hash_set(mrb, wslay_error_hash, mrb_fixnum_value(WSLAY_ERR_INVALID_CALLBACK), mrb_symbol_value(mrb_intern_lit(mrb, "invalid_callback")));
  mrb_hash_set(mrb, wslay_error_hash, mrb_fixnum_value(WSLAY_ERR_NO_MORE_MSG), mrb_symbol_value(mrb_intern_lit(mrb, "no_more_msg")));
  mrb_hash_set(mrb, wslay_error_hash, mrb_fixnum_value(WSLAY_ERR_CALLBACK_FAILURE), mrb_symbol_value(mrb_intern_lit(mrb, "callback_failure")));
  mrb_hash_set(mrb, wslay_error_hash, mrb_fixnum_value(WSLAY_ERR_WOULDBLOCK), mrb_symbol_value(mrb_intern_lit(mrb, "wouldblock")));
  mrb_hash_set(mrb, wslay_error_hash, mrb_fixnum_value(WSLAY_ERR_NOMEM), mrb_symbol_value(mrb_intern_lit(mrb, "nomem")));
  mrb_value wslay_error_hash_keys = mrb_hash_keys(mrb, wslay_error_hash);
  for (mrb_int i = 0; i < RARRAY_LEN(wslay_error_hash_keys); i++) {
    mrb_value key = mrb_ary_ref(mrb, wslay_error_hash_keys, i);
    mrb_hash_set(mrb, wslay_error_hash,
      mrb_hash_get(mrb, wslay_error_hash, key), key);
  }

  mrb_value wslay_status_code_hash = mrb_hash_new_capa(mrb, 12 * 2);
  mrb_define_const(mrb, wslay_mod, "StatusCode", wslay_status_code_hash);
  mrb_hash_set(mrb, wslay_status_code_hash, mrb_fixnum_value(WSLAY_CODE_NORMAL_CLOSURE), mrb_symbol_value(mrb_intern_lit(mrb, "normal_closure")));
  mrb_hash_set(mrb, wslay_status_code_hash, mrb_fixnum_value(WSLAY_CODE_GOING_AWAY), mrb_symbol_value(mrb_intern_lit(mrb, "going_away")));
  mrb_hash_set(mrb, wslay_status_code_hash, mrb_fixnum_value(WSLAY_CODE_PROTOCOL_ERROR), mrb_symbol_value(mrb_intern_lit(mrb, "protocol_error")));
  mrb_hash_set(mrb, wslay_status_code_hash, mrb_fixnum_value(WSLAY_CODE_UNSUPPORTED_DATA), mrb_symbol_value(mrb_intern_lit(mrb, "unsupported_data")));
  mrb_hash_set(mrb, wslay_status_code_hash, mrb_fixnum_value(WSLAY_CODE_NO_STATUS_RCVD), mrb_symbol_value(mrb_intern_lit(mrb, "no_status_rcvd")));
  mrb_hash_set(mrb, wslay_status_code_hash, mrb_fixnum_value(WSLAY_CODE_ABNORMAL_CLOSURE), mrb_symbol_value(mrb_intern_lit(mrb, "abnormal_closure")));
  mrb_hash_set(mrb, wslay_status_code_hash, mrb_fixnum_value(WSLAY_CODE_INVALID_FRAME_PAYLOAD_DATA), mrb_symbol_value(mrb_intern_lit(mrb, "invalid_frame_payload_data")));
  mrb_hash_set(mrb, wslay_status_code_hash, mrb_fixnum_value(WSLAY_CODE_POLICY_VIOLATION), mrb_symbol_value(mrb_intern_lit(mrb, "policy_violation")));
  mrb_hash_set(mrb, wslay_status_code_hash, mrb_fixnum_value(WSLAY_CODE_MESSAGE_TOO_BIG), mrb_symbol_value(mrb_intern_lit(mrb, "message_too_big")));
  mrb_hash_set(mrb, wslay_status_code_hash, mrb_fixnum_value(WSLAY_CODE_MANDATORY_EXT), mrb_symbol_value(mrb_intern_lit(mrb, "mandatory_ext")));
  mrb_hash_set(mrb, wslay_status_code_hash, mrb_fixnum_value(WSLAY_CODE_INTERNAL_SERVER_ERROR), mrb_symbol_value(mrb_intern_lit(mrb, "internal_server_error")));
  mrb_hash_set(mrb, wslay_status_code_hash, mrb_fixnum_value(WSLAY_CODE_TLS_HANDSHAKE), mrb_symbol_value(mrb_intern_lit(mrb, "tls_handshake")));
  mrb_value wslay_status_code_hash_keys = mrb_hash_keys(mrb, wslay_status_code_hash);
  for (mrb_int i = 0; i < RARRAY_LEN(wslay_status_code_hash_keys); i++) {
    mrb_value key = mrb_ary_ref(mrb, wslay_status_code_hash_keys, i);
    mrb_hash_set(mrb, wslay_status_code_hash,
      mrb_hash_get(mrb, wslay_status_code_hash, key), key);
  }

  mrb_value io_flags_hash = mrb_hash_new_capa(mrb, 2);
  mrb_define_const(mrb, wslay_mod, "IoFlags", io_flags_hash);
  mrb_hash_set(mrb, io_flags_hash, mrb_fixnum_value(WSLAY_MSG_MORE), mrb_symbol_value(mrb_intern_lit(mrb, "msg_more")));
  mrb_hash_set(mrb, io_flags_hash, mrb_symbol_value(mrb_intern_lit(mrb, "msg_more")), mrb_fixnum_value(WSLAY_MSG_MORE));

  mrb_value wslay_opcode_hash = mrb_hash_new_capa(mrb, 6 * 2);
  mrb_define_const(mrb, wslay_mod, "OpCode", wslay_opcode_hash);
  mrb_hash_set(mrb, wslay_opcode_hash, mrb_fixnum_value(WSLAY_CONTINUATION_FRAME), mrb_symbol_value(mrb_intern_lit(mrb, "continuation_frame")));
  mrb_hash_set(mrb, wslay_opcode_hash, mrb_fixnum_value(WSLAY_TEXT_FRAME), mrb_symbol_value(mrb_intern_lit(mrb, "text_frame")));
  mrb_hash_set(mrb, wslay_opcode_hash, mrb_fixnum_value(WSLAY_BINARY_FRAME), mrb_symbol_value(mrb_intern_lit(mrb, "binary_frame")));
  mrb_hash_set(mrb, wslay_opcode_hash, mrb_fixnum_value(WSLAY_CONNECTION_CLOSE), mrb_symbol_value(mrb_intern_lit(mrb, "connection_close")));
  mrb_hash_set(mrb, wslay_opcode_hash, mrb_fixnum_value(WSLAY_PING), mrb_symbol_value(mrb_intern_lit(mrb, "ping")));
  mrb_hash_set(mrb, wslay_opcode_hash, mrb_fixnum_value(WSLAY_PONG), mrb_symbol_value(mrb_intern_lit(mrb, "pong")));
  mrb_value wslay_opcode_hash_keys = mrb_hash_keys(mrb, wslay_opcode_hash);
  for (mrb_int i = 0; i < RARRAY_LEN(wslay_opcode_hash_keys); i++) {
    mrb_value key = mrb_ary_ref(mrb, wslay_opcode_hash_keys, i);
    mrb_hash_set(mrb, wslay_opcode_hash,
      mrb_hash_get(mrb, wslay_opcode_hash, key), key);
  }

  wslay_event_mod = mrb_define_module_under(mrb, wslay_mod, "Event");
  wslay_event_context_cl = mrb_define_class_under(mrb, wslay_event_mod, "Context", mrb->object_class);
  MRB_SET_INSTANCE_TT(wslay_event_context_cl, MRB_TT_DATA);
  mrb_define_method(mrb, wslay_event_context_cl, "no_buffering=",         mrb_wslay_event_config_set_no_buffering,        MRB_ARGS_REQ(1));
  mrb_define_method(mrb, wslay_event_context_cl, "max_recv_msg_length=",  mrb_wslay_event_config_set_max_recv_msg_length, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, wslay_event_context_cl, "recv",                  mrb_wslay_event_recv,                           MRB_ARGS_NONE());
  mrb_define_method(mrb, wslay_event_context_cl, "send",                  mrb_wslay_event_send,                           MRB_ARGS_NONE());
  mrb_define_method(mrb, wslay_event_context_cl, "queue_msg",             mrb_wslay_event_queue_msg,                      MRB_ARGS_REQ(2));
  mrb_define_method(mrb, wslay_event_context_cl, "queue_close",           mrb_wslay_event_queue_close,                    MRB_ARGS_ARG(1, 1));
  mrb_define_method(mrb, wslay_event_context_cl, "want_read?",            mrb_wslay_event_want_read,                      MRB_ARGS_NONE());
  mrb_define_method(mrb, wslay_event_context_cl, "want_write?",           mrb_wslay_event_want_write,                     MRB_ARGS_NONE());
  mrb_define_method(mrb, wslay_event_context_cl, "close_received?",       mrb_wslay_event_get_close_received,             MRB_ARGS_NONE());
  mrb_define_method(mrb, wslay_event_context_cl, "close_sent?",           mrb_wslay_event_get_close_sent,                 MRB_ARGS_NONE());
  mrb_define_method(mrb, wslay_event_context_cl, "status_code_received",  mrb_wslay_event_get_status_code_received,       MRB_ARGS_NONE());
  mrb_define_method(mrb, wslay_event_context_cl, "status_code_sent",      mrb_wslay_event_get_status_code_sent,           MRB_ARGS_NONE());
  mrb_define_method(mrb, wslay_event_context_cl, "queued_msg_count",      mrb_wslay_event_get_queued_msg_count,           MRB_ARGS_NONE());
  mrb_define_method(mrb, wslay_event_context_cl, "queued_msg_length",     mrb_wslay_event_get_queued_msg_length,          MRB_ARGS_NONE());

  wslay_event_context_server_cl = mrb_define_class_under(mrb, wslay_event_context_cl, "Server", wslay_event_context_cl);
  mrb_define_method(mrb, wslay_event_context_server_cl, "initialize", mrb_wslay_event_context_server_init, MRB_ARGS_REQ(1));

  wslay_event_context_client_cl = mrb_define_class_under(mrb, wslay_event_context_cl, "Client", wslay_event_context_cl);
  mrb_define_method(mrb, wslay_event_context_client_cl, "initialize", mrb_wslay_event_context_client_init, MRB_ARGS_REQ(1));
}

void mrb_mruby_wslay_gem_final(mrb_state* mrb) {}
