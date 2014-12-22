#ifndef B_DEBUG
#define B_DEBUG 1

#define bdbg(x) if(b_debug >= x)
#define bdbgl(x) b_debug = x
unsigned long b_debug = 0;

#endif
