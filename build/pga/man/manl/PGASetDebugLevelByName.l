.TH PGASetDebugLevelByName 3 "05/01/95" " " "PGAPack"
.SH NAME
PGASetDebugLevelByName \- Turn on debugging of the named function.
.SH INPUT PARAMETERS
.PD 0
.TP
ctx
- context variable
.PD 0
.TP
funcname
- name of the function to turn on debugging output
.PD 1
.SH OUTPUT PARAMETERS
.PD 0
.TP
none

.PD 1
.SH SYNOPSIS
.nf
#include "pgapack.h"
void  PGASetDebugLevelByName(ctx, funcname)
PGAContext *ctx
char *funcname
.fi
.SH LOCATION
debug.c
.SH EXAMPLE
.nf
PGAContext *ctx;
:
PGASetDebugLevelByName(ctx, "PGAGetBinaryAllele");

.fi
