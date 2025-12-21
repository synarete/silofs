#ifndef HAVE_CONFIG_H
#error "HAVE_CONFIG_H is not defined"
#endif

#ifdef NULL
#error "this header file must be included before system headers"
#endif

#ifdef SILOFS_STR
#error "this header file must be included first"
#endif

#ifdef SILOFS_CONFIGS_ONCE
#error "this header file must be included once"
#endif

#include <silofs/config.h>

#define SILOFS_CONFIGS_ONCE 1
