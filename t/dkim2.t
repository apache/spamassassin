#!/usr/bin/perl

use strict;
use warnings;
use lib '.'; use lib 't';

use SATest; sa_t_init("dkim");
use Test;
use vars qw(%patterns %anti_patterns);

use constant num_tests => 41;

use constant TEST_ENABLED => conf_bool('run_net_tests');
use constant HAS_MODULES => eval { require Mail::DKIM; require Mail::DKIM::Verifier; };

use constant DO_RUN => TEST_ENABLED && HAS_MODULES;

BEGIN {
  
  plan tests => (DO_RUN ? num_tests : 0);

};

exit unless (DO_RUN);

# ---------------------------------------------------------------------------

# ensure rules will fire
tstlocalrules ("
  score DKIM_SIGNED              -0.1
  score DKIM_VERIFIED            -0.1
");

my $dirname = "data/dkim";
my $fn;
local *DIR;


# mail samples test-pass* should all pass DKIM validation
#
%patterns = (
  q{ DKIM_SIGNED }, 'DKIM_SIGNED', q{ DKIM_VERIFIED }, 'DKIM_VERIFIED',
);
%anti_patterns = ();
opendir(DIR, $dirname) or die "Cannot open directory $dirname: $!";
while (defined($fn = readdir(DIR))) {
  next  if $fn eq '.' || $fn eq '..';
  next  if $fn !~ /^test-pass-\d*\.msg$/;
  sarun ("-t < $dirname/$fn", \&patterns_run_cb);
  ok ok_all_patterns();
}
closedir(DIR) or die "Error closing directory $dirname: $!";


# this mail sample is special, doesn't have any signature
#
%patterns = ();
%anti_patterns = ( q{ DKIM_VERIFIED }, 'DKIM_VERIFIED' );
sarun ("-t < $dirname/test-fail-01.msg", \&patterns_run_cb);
ok ok_all_patterns();

# mail samples test-fail* should all fail DKIM validation
#
%patterns      = ( q{ DKIM_SIGNED },   'DKIM_SIGNED' );
%anti_patterns = ( q{ DKIM_VERIFIED }, 'DKIM_VERIFIED' );
opendir(DIR, $dirname) or die "Cannot open directory $dirname: $!";
while (defined($fn = readdir(DIR))) {
  next  if $fn eq '.' || $fn eq '..';
  next  if $fn !~ /^test-fail-\d*\.msg$/;
  next  if $fn eq "test-fail-01.msg";  # no signature
  sarun ("-t < $dirname/$fn", \&patterns_run_cb);
  ok ok_all_patterns();
}
closedir(DIR) or die "Error closing directory $dirname: $!";
