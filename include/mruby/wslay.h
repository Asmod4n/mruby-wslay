#ifndef MRUBY_WSLAY_H
#define MRUBY_WSLAY_H

#include <mruby.h>

#ifdef MRB_INT16
# error MRB_INT16 is too small for mruby-wslay.
#endif

MRB_BEGIN_DECL

#define E_WSLAY_ERROR (mrb_class_get_under(mrb, mrb_module_get(mrb, "Wslay"), "Err"))

MRB_END_DECL

#endif
