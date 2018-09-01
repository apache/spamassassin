# Generated automatically from Makefile.in by configure.
RM      = /bin/rm -f
SHELL   = /bin/sh

default:
	@echo "Choices are:"
	@echo "make install       (install the PGAPack distribution)"
	@echo "make clean         (return to the state just after configure was run)"
	@echo "make spotless      (keep ONLY *.a and include files)"

install: 
	@echo "Installing PGAPack . . ."
	@cd source ; make
	@echo "Installing Examples . . ."
	@cd examples ; make
	@echo "Installing Test program . . ."
	@cd test ; make
	@echo "Install successful."
	@echo "	Please \"cd test\" and run the \"instverf\" program"
	@echo "        to verify the correctness of your installation."

clean:
	@echo "Removing superfluous files . . ."
	@$(RM) lib/*/*.o
	@cd examples ; make clean
	@cd test ; make clean

spotless:
	@echo "WARNING:  Removing docs, man, examples, and source directories"
	@echo "          in 5 seconds!!"
	@sleep 1
	@echo " .. 4 .."
	@sleep 1
	@echo " .. 3 .."
	@sleep 1
	@echo " .. 2 .."
	@sleep 1
	@echo " .. 1 .."
	@sleep 1
	@echo " .. 0 .."
	@echo " .. Removing everything except libraries and includes!!"
	@sleep 1
	@$(RM) -rf docs examples man source test util lib/*/*.o

distribution:
	@/home/pgapack/util/make_distribution	

