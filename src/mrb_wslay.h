#ifndef MRB_WSLAY_H
#define MRB_WSLAY_H

#include <wslay/wslay.h>
#include <mruby/throw.h>
#include <mruby/variable.h>
#include <mruby/string.h>
#include <mruby/string_is_utf8.h>
#include <string.h>
#include <mruby/data.h>
#include <mruby/class.h>
#include <mruby/hash.h>
#include <mruby/array.h>
#include <errno.h>
#include <sodium.h>
#include <mruby/error.h>

#define MRB_WSLAY_ERROR(err) (mrb_hash_get(mrb, mrb_const_get(mrb, mrb_obj_value(mrb_module_get(mrb, "Wslay")), mrb_intern_lit(mrb, "Error")), err))
#define MRB_GET_OPCODE(opcode) (mrb_hash_get(mrb, mrb_const_get(mrb, mrb_obj_value(mrb_module_get(mrb, "Wslay")), mrb_intern_lit(mrb, "OpCode")), opcode))
#define MRB_GET_STATUSCODE(status_code) (mrb_hash_get(mrb, mrb_const_get(mrb, mrb_obj_value(mrb_module_get(mrb, "Wslay")), mrb_intern_lit(mrb, "StatusCode")), status_code))
#define NELEMS(x) (sizeof(x) / sizeof((x)[0]))

typedef struct {
  wslay_event_context_ptr ctx;
  mrb_state *mrb;
  mrb_value recv_callback;
  mrb_value send_callback;
  mrb_value on_msg_recv_callback;
} mrb_wslay_user_data;

static void
mrb_wslay_user_data_free(mrb_state *mrb, void *p)
{
  mrb_wslay_user_data *data = (mrb_wslay_user_data *) p;
  wslay_event_context_free(data->ctx);
  mrb_free(mrb, p);
}

static const struct mrb_data_type mrb_wslay_user_data_type = {
  "$mrb_i_wslay_user_data", mrb_wslay_user_data_free,
};

#endif
