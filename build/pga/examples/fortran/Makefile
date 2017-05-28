# Generated automatically from Makefile.in by configure.
FC           = f77
PREFFLAGS    = -w
RM           = /bin/rm -f
LDFLAGS      = -s  -L/usr/local/pga/lib/linux  -lpgaO  -lm
SHELL        = /bin/sh

#    "$@" expands to the target; "$?" expands to the dependency list
FFLAGS      = -o $@ $? $(PREFFLAGS)

LINK.f       = if test -n "$(FC)"; \
                   then echo "  Compiling $@" ; $(FC) $(FFLAGS) $(LDFLAGS); \
               else \
                   echo "$@: Fortran compiler unavailable"; fi

default:
	@make classic
	@make dejong
	@make example
	@make maxbit
	@make maxchar
	@make maxint 
	@make name
	@make namefull


classic: classic.f
	@$(LINK.f)

dejong: dejong.f
	@$(LINK.f)

example: example.f
	@$(LINK.f)

maxbit: maxbit.f
	@$(LINK.f)

maxchar: maxchar.f
	@$(LINK.f)

maxint: maxint.f
	@$(LINK.f)

name: name.f
	@$(LINK.f)

namefull: namefull.f
	@$(LINK.f)

clean: 
	@$(RM) classic dejong example maxbit maxchar maxint name namefull *.o

