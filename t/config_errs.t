#!/usr/bin/perl -w

use Test::More;

# TODO: Now we're using Test::More, we could choose to make the failing tests TODO tests so we know if they start passing.
plan skip_all => q{This script does not work yet. There are (a) lots of failures and (b) the 'plan' line means all tests are effectively ignored from 'make test'.};
exit 0;

# ---------------------------------------------------------------------------

# these items either kill the test or are valid with no arg
my $WHITELIST = qr/^
    require_version
    |\S+_template
    |clear_trusted_networks
    |clear_internal_networks
    |clear_msa_networks
    |clear_headers
    |descriptions
    |test
$/ox;

# ---------------------------------------------------------------------------

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
use lib '.'; use lib 't';
use SATest; sa_t_init("config_errs");
use Mail::SpamAssassin;

# initialize SpamAssassin
my $sa = create_saobj({'dont_copy_prefs' => 1});

$sa->init(0); # parse rules

my @want;
my $cf = '';

foreach my $cmd (@{$sa->{conf}{registered_commands}}) {
  my $name = $cmd->{setting};
  next if ($name =~ $WHITELIST);

  $cf .= "$name\n";
  push (@want, qr/failed to parse line, (?:no value provided|\"\" is not valid) for \"$name\", skipping: / );  # "
}

plan tests => $#want+3;

tstlocalrules ($cf);

my $fh = IO::File->new_tmpfile();
ok($fh);
open(STDERR, ">&=".fileno($fh)) || die "Cannot reopen STDERR";

sarun ("-L < data/nice/001", \&patterns_run_cb);
ok(1);

seek($fh, 0, 0);
my $error = do {
  local $/;
  <$fh>;
};

print "# $error\n";

foreach my $item (@want) {
  ok ($error =~ $item) or print "(wanted: $item)\n";
}


