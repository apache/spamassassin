# Generated automatically from Makefile.in by configure.
CC          = cc
FC          = f77
PRECFLAGS   = -O 
PREFFLAGS   = -w
CPPFLAGS    = -I/usr/local/pga/include -Dlinux -DWL=32 -DFORTRANUNDERSCORE -DOPTIMIZE -DFAKE_MPI 
RM          = /bin/rm -f
LDFLAGS     = -s  -L/usr/local/pga/lib/linux  -lpgaO  -lm
SHELL       = /bin/sh

#    "$@" expands to the target; "$?" expands to the dependency list
CFLAGS      = -o $@ $? $(PRECFLAGS)
FFLAGS      = -o $@ $? $(PREFFLAGS)

LINK.c      = @echo "  Compiling $@" ; $(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS)
LINK.f      = @if test -n "$(FC)"; \
                  then echo "  Compiling $@" ; $(FC) $(FFLAGS) $(LDFLAGS); \
              else \
                  echo "$@: Fortran compiler unavailable"; fi

default:
	@make instverf 

instverf: instverf.c
	$(LINK.c)

clean: 
	@$(RM) instverf instverf.o
