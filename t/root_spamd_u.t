#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("root_spamd_u");

use constant HAS_SUDO => $RUNNING_ON_WINDOWS || eval { $_ = untaint_cmd("which sudo 2>/dev/null"); chomp; -x };

use Test::More;
plan skip_all => "root tests disabled" unless conf_bool('run_root_tests');
plan skip_all => "not running tests as root" unless eval { ($> == 0); };
plan skip_all => "sudo executable not found in path" unless HAS_SUDO;
plan tests => 11;

# ---------------------------------------------------------------------------

%patterns = (
  q{ Return-Path: sb55sb55@yahoo.com}, 'firstline',
  q{ Subject: There yours for FREE!}, 'subj',
  q{ X-Spam-Status: Yes, score=}, 'status',
  q{ X-Spam-Flag: YES}, 'flag',
  q{ X-Spam-Level: **********}, 'stars',
  q{ TEST_ENDSNUMS}, 'endsinnums',
  q{ TEST_NOREALNAME}, 'noreal',
  q{ This must be the very last line}, 'lastline',
);

# run spamc as unpriv uid
$spamc = "sudo -u nobody $spamc";

ok(start_spamd("-L -u nobody"));

$SIG{ALRM} = sub { die "timed out"; };
alarm 10;
ok(spamcrun("< data/spam/001", \&patterns_run_cb));
alarm 0;
ok_all_patterns();

ok(stop_spamd());

