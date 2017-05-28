.TH PGAClearDebugLevelByName 3 "05/01/95" " " "PGAPack"
.SH NAME
PGAClearDebugLevelByName \- Turn off debugging of the named function.
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
void  PGAClearDebugLevelByName(ctx, funcname)
PGAContext *ctx
char *funcname
.fi
.SH LOCATION
debug.c
.SH EXAMPLE
.nf
PGAContext *ctx;
:
PGAClearDebugLevelByName(ctx, "PGAGetBinaryAllele");

.fi
