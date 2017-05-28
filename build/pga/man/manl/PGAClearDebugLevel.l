.TH PGAClearDebugLevel 3 "05/01/95" " " "PGAPack"
.SH NAME
PGAClearDebugLevel \- Turn off a debul level.  
.SH DESCRIPTION
Only valid if PGAPack
was compiled to include debugging calls.  See the user guide for details.
.SH INPUT PARAMETERS
.PD 0
.TP
ctx
- context variable
.PD 0
.TP
level
- the debug level to set to PGA_FALSE.
.PD 1
.SH OUTPUT PARAMETERS
.PD 0
.TP
none

.PD 1
.SH SYNOPSIS
.nf
#include "pgapack.h"
void  PGAClearDebugLevel(ctx, level)
PGAContext *ctx
int level
.fi
.SH LOCATION
debug.c
.SH EXAMPLE
.nf
Example:
PGAContext *ctx;
:
PGAClearDebugLevel(ctx, 70)

.fi
