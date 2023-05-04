#ifndef _CONSTANTS_FENTRY_MACRO_H_
#define _CONSTANTS_FENTRY_MACRO_H_

#ifdef USE_FENTRY

#define CTX_PARM1(ctx) (void *)(ctx[0])

#else

#define CTX_PARM1(ctx) PT_REGS_PARM1(ctx)

#endif

#endif
