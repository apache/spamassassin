#!/usr/bin/perl -w -T

use strict;
use lib '.'; use lib 't';
use SATest; sa_t_init("debug");

use Mail::SpamAssassin;

use Test::More;
plan tests => 3;

# list of known debug facilities
my %facility = map( ($_, 1),
  qw( accessdb archive-iterator async auto-welcomelist bayes check config daemon
      dcc dkim askdns dns dnseval eval generic https_http_mismatch facility FreeMail
      ident ignore info ldap learn locker log logger markup HashBL
      message metadata mimeheader netset plugin prefork progress pyzor razor2
      received-header replacetags reporter rules rules-all spamd spf textcat
      timing TxRep uri uridnsbl util pdfinfo asn geodb FromNameSpoof
      PHISHTAG resourcelimits https_http_mismatch DMARC ));

my $fh = IO::File->new_tmpfile();
open(OLDERR, ">&STDERR");
open(STDERR, ">&=".fileno($fh)) || die "Cannot reopen STDERR";

ok(sarun("-t -D < data/spam/dnsbl.eml"));

seek($fh, 0, 0);
my $error = do {
    local $/;
    <$fh>;
};

my $malformed = 0;
my $unlisted = 0;
for (split(/^/m, $error)) {

    # ditch a syslog-like timestamp if present
    s/^ [a-z]{3} \s+ \d{1,2} \s+
        \d{1,2} : \d{1,2} : \d{1,2} (?: \. \d* )? \s*//xsi;

    if (/^(?: \[ \d+ \] \s+)? (dbg|info): \s* ([^:\s]+) : \s* (.*)/x) {
	if (!exists $facility{$2}) {
	    $unlisted++;
	    print OLDERR "unlisted debug facility: $2\n";
	}
    }
    elsif (/^(?: \[ \d+ \] \s+)? (warn|error):/x) {
	# ok
    }
    else {
	print "malformed debug message: $_";
#	$malformed = 1;
    }
}

ok(!$malformed);
ok(!$unlisted);
