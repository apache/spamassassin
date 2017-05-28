# Generated automatically from Makefile.in by configure.
FC    = f77
RM    = /bin/rm -f
SHELL = /bin/sh

default:
	@echo "Making C examples"
	@make C
	@echo "Making fortran examples"
	@make Fortran

C:
	@cd c; make

Fortran:
	@if test -n "$(FC)" ; then\
		cd fortran; make; cd ..;\
		cd mgh; make;\
	else\
		echo "Fortran compiler unavailable";\
	fi

clean:
	@cd c; make clean
	@cd fortran; make clean
	@cd mgh; make clean

