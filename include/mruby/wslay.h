#ifdef MRB_INT16
# error MRB_INT16 is too small for mruby-wslay.
#endif

#ifndef MRUBY_WSLAY_H
#define MRUBY_WSLAY_H

#include <mruby.h>

#ifdef __cplusplus
extern "C" {
#endif

#define E_WSLAY_ERROR (mrb_class_get_under(mrb, mrb_module_get(mrb, "Wslay"), "Err"))

#ifdef __cplusplus
}
#endif

#endif
