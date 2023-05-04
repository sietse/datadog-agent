#ifndef _CONSTANTS_FENTRY_MACRO_H_
#define _CONSTANTS_FENTRY_MACRO_H_

#ifdef USE_FENTRY

typedef unsigned long long ctx_t;
#define CTX_PARM1(ctx) (void *)(ctx[0])

#else

typedef struct pt_regs ctx_t;
#define CTX_PARM1(ctx) PT_REGS_PARM1(ctx)

#endif

#endif
