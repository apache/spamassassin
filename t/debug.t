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

plan tests => 2;

# list of known debug facilities
my %facility = map {; $_ => 1 }
  qw( accessdb auto-whitelist bayes check config daemon dcc dns eval
      generic facility hashcash ident ignore info ldap learn locker log
      logger markup message metadata plugin prefork pyzor razor2
      received-header reporter rules spf textcat uri uridnsbl util ),
;

# initialize SpamAssassin
my $sa = Mail::SpamAssassin->new({
    rules_filename => "$prefix/t/log/test_rules_copy",
    site_rules_filename => "$prefix/t/log/test_default.cf",
    userprefs_filename  => "$prefix/masses/spamassassin/user_prefs",
    local_tests_only    => 1,
    debug             => 1,
    dont_copy_prefs   => 1,
});
$sa->init(0); # parse rules

my $fh = IO::File->new_tmpfile();
open(STDERR, ">&=".fileno($fh)) || die "Cannot reopen STDERR";
sarun("-t -D < data/spam/dnsbl.eml");
seek($fh, 0, 0);
my $error = do {
    local $/;
    <$fh>;
};

my $malformed = 0;
my $unlisted = 0;
for (split(/^/m, $error)) {
    if (/^(\w+):\s+(\S+?):\s*(.*)/) {
	if (!exists $facility{$2}) {
	    $unlisted++;
	    print "unlisted debug facility: $2\n";
	}
    }
    else {
	print "malformed debug message: $_";
#disabled until bug 4061 is fixed
#	$malformed = 1;
    }
}

ok(!$malformed);
ok(!$unlisted);
