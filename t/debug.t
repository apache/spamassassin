#!/usr/bin/perl -w

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_names.t", kluge around ...
    chdir 't';
  }

  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib');
  }
}

my $prefix = '.';
if (-e 'test_dir') {            # running from test directory, not ..
  $prefix = '..';
}

use strict;
use SATest; sa_t_init("debug");
use Test;
use Mail::SpamAssassin;

use constant TEST_ENABLED => conf_bool('run_long_tests');

BEGIN { 
  plan tests => (TEST_ENABLED ? 3 : 0);
};
exit unless TEST_ENABLED;

# list of known debug facilities
my %facility = map( ($_, 1),
  qw( accessdb archive-iterator async auto-whitelist bayes check config daemon
      dcc dkim askdns dns eval generic https_http_mismatch facility FreeMail
      hashcash ident ignore info ldap learn locker log logger markup
      message metadata mimeheader netset plugin prefork progress pyzor razor2
      received-header replacetags reporter rules rules-all spamd spf textcat
      timing TxRep uri uridnsbl util ));

my $fh = IO::File->new_tmpfile();
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
	    print "unlisted debug facility: $2\n";
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
