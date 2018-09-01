.TH PGADebugPrint 3 "05/01/95" " " "PGAPack"
.SH NAME
PGADebugPrint \- Write debugging information
.SH INPUT PARAMETERS
.PD 0
.TP
ctx
- context variable
.PD 0
.TP
level
- a symbolic constant that maps to the type of print requested
(e.g., an entry or exit print).  Valid values are
PGA_DEBUG_ENTERED, PGA_DEBUG_EXIT, PGA_DEBUG_MALLOC,
PGA_DEBUG_PRINTVAR, PGA_DEBUG_SEND, and PGA_DEBUG_RECV.
.PD 0
.TP
funcname
- the name of the function that called this routine
.PD 0
.TP
msg
- message to print
.PD 0
.TP
datatype
- a symbolic constant that maps to the data type of the
parameter data.  Valid choices are PGA_INT, PGA_DOUBLE,
PGA_CHAR and PGA_VOID (no data).
.PD 0
.TP
data
- a pointer, whose contents will be interpreted based upon the
datatype parameter (or NULL, if PGA_VOID).
.PD 1
.SH OUTPUT PARAMETERS
.PD 0
.TP
none

.PD 1
.SH SYNOPSIS
.nf
#include "pgapack.h"
void  PGADebugPrint(ctx, level, funcname, msg, datatype, data)
PGAContext *ctx
int level
char *funcname
char *msg
int datatype
void *data
.fi
.SH LOCATION
debug.c
.SH EXAMPLE
.nf
Example:
If the debugging level includes printing variables (level 82), print the
value of the integer variable num as a debugging tool in the routine
Add2Nums

PGAContext *ctx;
int num;
:
PGADebugPrint(ctx, PGA_DEBUG_PRINTVAR, "Add2Nums", "num = ", PGA_INT,
(void *) &num);

.fi
