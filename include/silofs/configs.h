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

#ifndef HAVE_NULLPTR
#error "can not compile without C23 nullptr keyword"
#endif

#define SILOFS_CONFIGS_ONCE 1
