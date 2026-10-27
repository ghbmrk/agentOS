#include "textflag.h"

// func trap() uintptr: returns 0. A hostile driver would put SYSCALL here.
TEXT ·trap(SB), NOSPLIT, $0-8
	MOVQ $0, ret+0(FP)
	RET
