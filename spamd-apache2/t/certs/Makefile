.PHONY: usage
.SUFFIXES: .key .csr .crt .pem
.PRECIOUS: %.key %.csr %.crt %.pem

usage:
	@echo "This makefile allows you to create:"
	@echo "  o public/private key pairs"
	@echo "  o SSL certificate signing requests (CSRs)"
	@echo "  o self-signed SSL test certificates"
	@echo
	@echo "To create a key pair, run \"make SOMETHING.key\"."
	@echo "To create a CSR, run \"make SOMETHING.csr\"."
	@echo "To create a test certificate, run \"make SOMETHING.crt\"."
	@echo "To create a key and a test certificate in one file, run \"make SOMETHING.pem\"."
	@echo
	@echo "To create a key for use with Apache, run \"make genkey\"."
	@echo "To create a CSR for use with Apache, run \"make certreq\"."
	@echo "To create a test certificate for use with Apache, run \"make testcert\"."
	@echo
	@echo Examples:
	@echo "  make server.key"
	@echo "  make server.csr"
	@echo "  make server.crt"
	@echo "  make stunnel.pem"
	@echo "  make genkey"
	@echo "  make certreq"
	@echo "  make testcert"

%.pem:
	umask 77 ; \
	PEM1=`/bin/mktemp /tmp/openssl.XXXXXX` ; \
	PEM2=`/bin/mktemp /tmp/openssl.XXXXXX` ; \
	/usr/bin/openssl req -newkey rsa:1024 -keyout $$PEM1 -nodes -x509 -days 365 -out $$PEM2 ; \
	cat $$PEM1 >  $@ ; \
	echo ""    >> $@ ; \
	cat $$PEM2 >> $@ ; \
	$(RM) $$PEM1 $$PEM2

%.key:
	umask 77 ; \
	/usr/bin/openssl genrsa -des3 1024 > $@

%.csr: %.key
	umask 77 ; \
	/usr/bin/openssl req -new -key $^ -out $@

%.crt: %.key
	umask 77 ; \
	/usr/bin/openssl req -new -key $^ -x509 -days 365 -out $@

KEY=/etc/httpd/conf/ssl.key/server.key
CSR=/etc/httpd/conf/ssl.csr/server.csr
CRT=/etc/httpd/conf/ssl.crt/server.crt

genkey: $(KEY)
certreq: $(CSR)
testcert: $(CRT)

$(CSR): $(KEY)
	umask 77 ; \
	/usr/bin/openssl req -new -key $(KEY) -out $(CSR)

$(CRT): $(KEY)
	umask 77 ; \
	/usr/bin/openssl req -new -key $(KEY) -x509 -days 365 -out $(CRT)
