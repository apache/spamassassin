# Generated automatically from Makefile.in by configure.
CC          = cc
PRECFLAGS   = -O -fPIC
CPPFLAGS    = -I../include -Dlinux -DWL=32 -DFORTRANUNDERSCORE -DOPTIMIZE -DFAKE_MPI 
HEADERS     = ../include/pgapack.h
PGA_LIB_DIR = ../lib/linux
PGA_LIB     = pgaO
RM          = /bin/rm -f
OBJS        = $(PGA_LIB_DIR)/binary.o        \
      $(PGA_LIB_DIR)/char.o          \
      $(PGA_LIB_DIR)/cmdline.o       \
      $(PGA_LIB_DIR)/create.o        \
      $(PGA_LIB_DIR)/cross.o         \
      $(PGA_LIB_DIR)/debug.o         \
      $(PGA_LIB_DIR)/duplcate.o      \
      $(PGA_LIB_DIR)/evaluate.o      \
      $(PGA_LIB_DIR)/fitness.o       \
      $(PGA_LIB_DIR)/hamming.o       \
      $(PGA_LIB_DIR)/heap.o          \
      $(PGA_LIB_DIR)/integer.o       \
      $(PGA_LIB_DIR)/mutation.o      \
      $(PGA_LIB_DIR)/parallel.o      \
      $(PGA_LIB_DIR)/pga.o           \
      $(PGA_LIB_DIR)/pop.o           \
      $(PGA_LIB_DIR)/random.o        \
      $(PGA_LIB_DIR)/real.o          \
      $(PGA_LIB_DIR)/report.o        \
      $(PGA_LIB_DIR)/restart.o       \
      $(PGA_LIB_DIR)/select.o        \
      $(PGA_LIB_DIR)/stop.o          \
      $(PGA_LIB_DIR)/system.o        \
      $(PGA_LIB_DIR)/user.o          \
      $(PGA_LIB_DIR)/utility.o $(PGA_LIB_DIR)/f2c.o $(PGA_LIB_DIR)/mpi_stub.o
SHELL       = /bin/sh
RANLIB      = ranlib

CFLAGS      = -o $@ -c $(PRECFLAGS)
COMPILE.c   = $(CC) $(CFLAGS) $(CPPFLAGS)

########################################################
#                    The Target                        #
########################################################

$(PGA_LIB_DIR)/lib$(PGA_LIB).a: $(OBJS)
	ar ruv $(PGA_LIB_DIR)/lib$(PGA_LIB).a $(OBJS)
	$(RANLIB) $(PGA_LIB_DIR)/lib$(PGA_LIB).a

########################################################
#                    The Source code                   #
########################################################

$(PGA_LIB_DIR)/binary.o: binary.c $(HEADERS)
	$(COMPILE.c) binary.c

$(PGA_LIB_DIR)/char.o: char.c $(HEADERS)
	$(COMPILE.c) char.c

$(PGA_LIB_DIR)/cmdline.o: cmdline.c $(HEADERS)
	$(COMPILE.c) cmdline.c

$(PGA_LIB_DIR)/create.o: create.c $(HEADERS)
	$(COMPILE.c) create.c

$(PGA_LIB_DIR)/cross.o: cross.c $(HEADERS)
	$(COMPILE.c) cross.c

$(PGA_LIB_DIR)/debug.o: debug.c $(HEADERS)
	$(COMPILE.c) debug.c

$(PGA_LIB_DIR)/duplcate.o: duplcate.c $(HEADERS)
	$(COMPILE.c) duplcate.c

$(PGA_LIB_DIR)/evaluate.o: evaluate.c $(HEADERS)
	$(COMPILE.c) evaluate.c

$(PGA_LIB_DIR)/fitness.o: fitness.c $(HEADERS)
	$(COMPILE.c) fitness.c

$(PGA_LIB_DIR)/f2c.o: f2c.c $(HEADERS)
	$(COMPILE.c) f2c.c

$(PGA_LIB_DIR)/hamming.o: hamming.c $(HEADERS)
	$(COMPILE.c) hamming.c

$(PGA_LIB_DIR)/heap.o: heap.c $(HEADERS)
	$(COMPILE.c) heap.c

$(PGA_LIB_DIR)/integer.o: integer.c $(HEADERS)
	$(COMPILE.c) integer.c

$(PGA_LIB_DIR)/mpi_stub.o: mpi_stub.c $(HEADERS)
	$(COMPILE.c) mpi_stub.c

$(PGA_LIB_DIR)/mutation.o: mutation.c $(HEADERS)
	$(COMPILE.c) mutation.c

$(PGA_LIB_DIR)/parallel.o: parallel.c $(HEADERS)
	$(COMPILE.c) parallel.c

$(PGA_LIB_DIR)/pga.o: pga.c $(HEADERS)
	$(COMPILE.c) pga.c

$(PGA_LIB_DIR)/pop.o: pop.c $(HEADERS)
	$(COMPILE.c) pop.c

$(PGA_LIB_DIR)/random.o: random.c $(HEADERS)
	$(COMPILE.c) random.c

$(PGA_LIB_DIR)/real.o: real.c $(HEADERS)
	$(COMPILE.c) real.c

$(PGA_LIB_DIR)/report.o: report.c $(HEADERS)
	$(COMPILE.c) report.c

$(PGA_LIB_DIR)/restart.o: restart.c $(HEADERS)
	$(COMPILE.c) restart.c

$(PGA_LIB_DIR)/select.o: select.c $(HEADERS)
	$(COMPILE.c) select.c

$(PGA_LIB_DIR)/stop.o: stop.c $(HEADERS)
	$(COMPILE.c) stop.c

$(PGA_LIB_DIR)/system.o: system.c $(HEADERS)
	$(COMPILE.c) system.c

$(PGA_LIB_DIR)/user.o: user.c $(HEADERS)
	$(COMPILE.c) user.c

$(PGA_LIB_DIR)/utility.o: utility.c $(HEADERS)
	$(COMPILE.c) utility.c
