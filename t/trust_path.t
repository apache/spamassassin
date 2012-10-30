#!/usr/bin/perl

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_tests.t", kluge around ...
    chdir 't';
  }

  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib');
    unshift(@INC, '../lib');
  }
}

our $have_patricia = 0;
eval {
  require Net::Patricia;
  Net::Patricia->VERSION(1.16);  # need AF_INET6 support
  import Net::Patricia;
  $have_patricia = 1;
};

my $prefix = '.';
if (-e 'test_dir') {            # running from test directory, not ..
  $prefix = '..';
}

use lib '.'; use lib 't';
use SATest; sa_t_init("trust_path");

use constant TEST_ENABLED => conf_bool('run_long_tests');
use Test;

BEGIN { plan tests => TEST_ENABLED ? 96 : 0 };
exit unless TEST_ENABLED;

use IO::File;
use strict;

# make a _copy_ of the STDERR file descriptor
# (so we can restore it after redirecting it)
open(OLDERR, ">&STDERR") || die "Cannot copy STDERR file handle";

# quiet "used only once" warnings
1 if *OLDERR;

my @data = (

# ---------------------------------------------------------------------------

# 127/8 implicitly trusted as default - #1
q{

  Received: from sender.net (127.0.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:01 -0000

} => q{

Trusted: [ ip=127.0.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: 

},

# ---------------------------------------------------------------------------

# 127/8 explicitly trusted - #2
q{

  trusted_networks 127/8
  Received: from sender.net (127.0.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:02 -0000

} => q{

Netset-Warn
Trusted: [ ip=127.0.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: 

},

# ---------------------------------------------------------------------------

# 127/8 explicitly trusted along with others #3
q{

  trusted_networks 127/8 1.2.2.1
  Received: from sender.net (127.0.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:03 -0000

} => q{

Netset-Warn
Trusted: [ ip=127.0.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: 

},

# ---------------------------------------------------------------------------

# 127/8 explicitly untrusted -- which is not possible to do - #4
q{

  trusted_networks 1.2/16 !127/8
  internal_networks 1.2/16 !127/8
  Received: from sender.net (127.0.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:04 -0000

} => q{

Netset-Warn
Patricia-Failure
Trusted: [ ip=127.0.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: 

},

# ---------------------------------------------------------------------------

# 127/8 implicitly trusted #5
q{

  trusted_networks 1.2/16
  Received: from sender.net (127.0.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:05 -0000

} => q{

Trusted: [ ip=127.0.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: 

},

# ---------------------------------------------------------------------------

# 10/8 implicitly trusted by auto-detection - #6
# note: it should also be internal!
q{

  Received: from sender.net (10.0.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:06 -0000

} => q{

Trusted: [ ip=10.0.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: 

},

# ---------------------------------------------------------------------------

# trusted, then not (which is trusted, we do first match wins) - #7
q{

  trusted_networks 1.2/16 !1.2/16
  Received: from sender.net (1.2.3.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:07 -0000

} => q{

Netset-Warn
Patricia-Failure
Trusted: [ ip=1.2.3.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# #8
q{

  trusted_networks 1.2/16
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:08 -0000

} => q{

Trusted:
Untrusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ]

},

# ---------------------------------------------------------------------------

# #9
q{

  trusted_networks 1.1/16
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:09 -0000

} => q{

Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# #10
q{

  trusted_networks 1.1/16
  internal_networks 1.1/16
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:10 -0000

} => q{

Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# with an unset trusted_networks, internal_networks is documented to
# be used instead - #11
q{

  internal_networks 1.1/16
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:11 -0000

} => q{

Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# #12
q{

  trusted_networks 1.1/16 1.2/16
  internal_networks 1.2/16
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:12 -0000

} => q{

Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# this should be a lint error; internal_networks is not a subset of trusted.
# note: "intl=0" is expected; even though the internal_networks config is
# invalid it was still defined by the user, so we do not use trusted for internal
# #13
q{

  trusted_networks 1.1/16
  internal_networks 1.2.8/24
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:13 -0000

} => q{

Lint-Error
Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# this should be a lint error; internal_networks is not a subset of trusted.
# note: "intl=0" is expected; even though the internal_networks config is
# invalid it was still defined by the user, so we do not use trusted for internal
# #14
q{

  trusted_networks 1.1.1/24
  internal_networks 1.1/16
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:14 -0000

} => q{

Lint-Error
Patricia-Failure
Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# this should be a lint error; internal_networks is not a subset of trusted.
# note: "intl=0" is expected; even though the internal_networks config is
# invalid it was still defined by the user, so we do not use trusted for internal
# #15
q{

  trusted_networks !1.1.1.1 1.1/16
  internal_networks 1.1.1.1
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:15 -0000

} => q{

Lint-Error
Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# this should be a lint error; you can't exclude a network after you've already
# included it (TODO: it is currently not a lint error, netset just warns about it)
# #16
q{

  trusted_networks 1/8 !1.1.1.2
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:16 -0000

} => q{

Netset-Warn
Patricia-Failure
Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# internal_networks are valid, even if the !4.3.2.1 is pointless - #17
q{

  trusted_networks 1.1/16
  internal_networks !4.3.2.1 1.1/16
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:17 -0000

} => q{

Trusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# test msa_networks functionality, MSA trusted+internal - #18
q{

  trusted_networks 1.1/16
  msa_networks 1.1.1.2
  Received: from sender.net (1.1.1.1) by receiver.net
              with SMTP; 10 Nov 2005 00:00:18 -0000
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:18 -0000
  Received: from sender.net (5.5.5.5) by receiver.net
              with SMTP; 10 Nov 2005 00:00:18 -0000

} => q{

Trusted: [ ip=1.1.1.1 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ] [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=1 ] [ ip=5.5.5.5 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# test msa_networks functionality, MSA trusted - #19
q{

  trusted_networks 1.1/16
  internal_networks !1.1.1.2 1.1/16
  msa_networks 1.1.1.2
  Received: from sender.net (1.1.1.1) by receiver.net
              with SMTP; 10 Nov 2005 00:00:19 -0000
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:19 -0000
  Received: from sender.net (5.5.5.5) by receiver.net
              with SMTP; 10 Nov 2005 00:00:19 -0000

} => q{

Trusted: [ ip=1.1.1.1 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ] [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=1 ] [ ip=5.5.5.5 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# test msa_networks functionality, 5.5.5.5 outside of trust boundary  #20
q{

  trusted_networks !1.1.1.2 1.1/16 5.5.5.5
  msa_networks 5.5.5.5
  Received: from sender.net (1.1.1.1) by receiver.net
              with SMTP; 10 Nov 2005 00:00:20 -0000
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:20 -0000
  Received: from sender.net (5.5.5.5) by receiver.net
              with SMTP; 10 Nov 2005 00:00:20 -0000

} => q{

Trusted: [ ip=1.1.1.1 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ] [ ip=5.5.5.5 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ]

},

# ---------------------------------------------------------------------------

# test msa_networks functionality, 5.5.5.5 not trusted, so cannot be an MSA #21
q{

  trusted_networks 1.1/16
  msa_networks 5.5.5.5
  Received: from sender.net (1.1.1.1) by receiver.net
              with SMTP; 10 Nov 2005 00:00:21 -0000
  Received: from sender.net (1.1.1.2) by receiver.net
              with SMTP; 10 Nov 2005 00:00:21 -0000
  Received: from sender.net (5.5.5.5) by receiver.net
              with SMTP; 10 Nov 2005 00:00:21 -0000

} => q{

Lint-Error
Trusted: [ ip=1.1.1.1 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ] [ ip=1.1.1.2 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: [ ip=5.5.5.5 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ]

},

# ---------------------------------------------------------------------------

# test to make sure netset is detecting overlap correctly when using short CIDR notations #22
q{

  trusted_networks 1/8 !1/8
  Received: from sender.net (1.1.1.1) by receiver.net
              with SMTP; 10 Nov 2005 00:00:22 -0000

} => q{

Netset-Warn
Patricia-Failure
Trusted: [ ip=1.1.1.1 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# bug 5680: 'X-Originating-IP' - #23
q{

  trusted_networks 1/8
  Received: from sender.net (1.1.1.1) by receiver.net
              with SMTP; 10 Nov 2005 00:00:23 -0000
  X-Originating-IP: 2.2.2.2

} => q{

Trusted: [ ip=1.1.1.1 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: [ ip=2.2.2.2 rdns= helo= by= ident= envfrom= intl=0 id= auth= msa=0 ]

},

# ---------------------------------------------------------------------------

# bug 5680: 'X-Originating-IP', trusted - #24
q{

  trusted_networks 1/8 2/8
  internal_networks 1/8
  Received: from sender.net (1.1.1.1) by receiver.net
              with SMTP; 10 Nov 2005 00:00:24 -0000
  X-Originating-IP: 2.2.2.2

} => q{

Trusted: [ ip=1.1.1.1 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ] [ ip=2.2.2.2 rdns= helo= by= ident= envfrom= intl=0 id= auth= msa=0 ]
Untrusted: 

},

# ---------------------------------------------------------------------------

# bug 5680: 'X-Originating-IP', msa - #25
q{

  trusted_networks 1/8
  msa_networks 1/8
  Received: from sender.net (1.1.1.1) by receiver.net
              with SMTP; 10 Nov 2005 00:00:25 -0000
  X-Originating-IP: 2.2.2.2

} => q{

Trusted: [ ip=1.1.1.1 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=1 ] [ ip=2.2.2.2 rdns= helo= by= ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: 

},

# ---------------------------------------------------------------------------

# bug 5680: 'X-Originating-IP', internal - #26
q{

  trusted_networks 1/8 2/8
  internal_networks 1/8 2/8
  Received: from sender.net (1.1.1.1) by receiver.net
              with SMTP; 10 Nov 2005 00:00:26 -0000
  X-Originating-IP: 2.2.2.2

} => q{

Trusted: [ ip=1.1.1.1 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ] [ ip=2.2.2.2 rdns= helo= by= ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: 

},

# ---------------------------------------------------------------------------

# test to make sure netset is detecting overlap correctly when using short CIDR notations - #27
q{

  trusted_networks !1/8 1/8
  Received: from sender.net (1.1.1.1) by receiver.net
              with SMTP; 10 Nov 2005 00:00:27 -0000

} => q{

Netset-Warn
Patricia-Failure
Trusted:
Untrusted: [ ip=1.1.1.1 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id= auth= msa=0 ]

},

# ---------------------------------------------------------------------------
# IPv6 - 28

q{

  trusted_networks DEAD:BEEF:0000:0102:0304:0506:0708:0a0b
  Received: from sender.net (sender.net [DEAD:BEEF:0000:0102:0304:0506:0708:0a0b])
        by receiver.net (Postfix) with ESMTP id A96E18BD97;
        10 Nov 2005 00:00:28 -0000

} => q{

Trusted: [ ip=DEAD:BEEF:0000:0102:0304:0506:0708:0a0b rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id=A96E18BD97 auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------
# bug 4503 - #29

q{

  trusted_networks DEAD:BEEF:0000:0102:0304:0506:0708:0a0b
  Received: from sender.net (sender.net [IPv6:2002:abcd:ef10::1])
        by receiver.net (Postfix) with ESMTP id A96E18BD97;
        10 Nov 2005 00:00:29 -0000

} => q{

Trusted: 
Untrusted: [ ip=2002:abcd:ef10::1 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id=A96E18BD97 auth= msa=0 ]

},

# ---------------------------------------------------------------------------

# ::1 implicitly trusted as default - #30
q{

  Received: from sender.net (::1) by receiver.net
              with SMTP; 10 Nov 2005 00:00:30 -0000

} => q{

Trusted: [ ip=::1 rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id= auth= msa=0 ]
Untrusted: 

},

# ---------------------------------------------------------------------------

# #31
q{

  trusted_networks DEAD:BEEF:0000:0102:0304:0506:0708:0000/108
  Received: from sender.net (sender.net [DEAD:BEEF:0000:0102:0304:0506:0708:0a0b])
        by receiver.net (Postfix) with ESMTP id A96E18BD97;
        10 Nov 2005 00:00:31 -0000

} => q{

Trusted: [ ip=DEAD:BEEF:0000:0102:0304:0506:0708:0a0b rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=1 id=A96E18BD97 auth= msa=0 ]
Untrusted:

},

# ---------------------------------------------------------------------------

# #32
q{

  trusted_networks DEAD:BEEF:0000:0102:0304:0506:0708:0a0c
  Received: from sender.net (sender.net [DEAD:BEEF:0000:0102:0304:0506:0708:0a0b])
        by receiver.net (Postfix) with ESMTP id A96E18BD97;
        10 Nov 2005 00:00:32 -0000

} => q{

Trusted:
Untrusted: [ ip=DEAD:BEEF:0000:0102:0304:0506:0708:0a0b rdns=sender.net helo=sender.net by=receiver.net ident= envfrom= intl=0 id=A96E18BD97 auth= msa=0 ]

},

# ---------------------------------------------------------------------------

);


my ($i);
while (1) {
  my $hdrs = shift @data;
  my $expected = shift @data;
  $i++;
  print "Data Set: #$i\n"; 
  last unless defined $expected;

  #SKIP TESTS FOR TESTING PURPOSES
  #my $test_data_set = 4;
  #if ($i < $test_data_set or $i > $test_data_set) {
  #  ok (1); ok (1); ok (1); next;
  #}

  my $test_failure = 0;

  my $conf = "add_header all Untrusted _RELAYSUNTRUSTED_\n".
            "add_header all Trusted _RELAYSTRUSTED_\n".
            "clear_trusted_networks\n".
            "clear_internal_networks\n".
            "clear_msa_networks\n";

  if ($hdrs =~ s/^\s*(trusted_networks\s+[^\n]*)//gs) {
    $conf .= $1."\n";
  }
  if ($hdrs =~ s/^\s*(internal_networks\s+[^\n]*)//gs) {
    if ($1) { $conf .= $1."\n"; }
  }
  if ($hdrs =~ s/^\s*(msa_networks\s+[^\n]*)//gs) {
    if ($1) { $conf .= $1."\n"; }
  }

  tstprefs ($conf);

  my $netset_warn = 0;
  my $fh;
  if ($expected =~ s/^\s*Netset-Warn\s*//) {    
    # create a file descriptor for logging STDERR
    # (we do not want warnings for regexps we know are invalid)
    $fh = IO::File->new_tmpfile();
    open(STDERR, ">&".fileno($fh)) || die "Cannot create LOGERR temp file";
    $netset_warn = 1;
    print "[netset warning expected here...]\n";
  }

  my $sa = create_saobj({
              userprefs_filename => "log/tst.cf",
              # debug => 1
            });

  #TEST #1 - OBJECT CREATION
  ok($sa);

  $sa->{lint_callback} = sub {
    my %opts = @_;
    print "lint error: $opts{msg}\n";
  };


  #TEST #2 - LINT TEST
  if ($expected =~ s/^\s*Lint-Error\s*//) {
    print "[lint error expected here...]\n";
    ok ($sa->lint_rules() != 0) or $test_failure=1;
  } else {
    ok ($sa->lint_rules() == 0) or $test_failure=1;
  }

  my $msg = $hdrs."\n\n[no body]\n";
  $msg =~ s/^\s+(Received|X-\S+): /$1: /gm;
  my $status = $sa->check_message_text ($msg);
  my $result = $status->rewrite_mail();

  if ($netset_warn) {
    open(STDERR, ">&=OLDERR") || die "Cannot reopen STDERR";

    seek($fh, 0, 0);
    my $error = do {
      local $/;
      <$fh>;
    };
    close $fh;

    $test_failure=1;
    for (split(/^/m, $error)) {
      if (/^netset: /) {
	$test_failure=0;
	print "netset warn: $_";
      } else {
	warn $_;
      }
    }
  }

  $result =~ s/\n[ \t]+/ /gs;
  $result =~ /(?:\n|^)X-Spam-Trusted: ([^\n]*)\n/s;
  my $relays_t = $1;
  $result =~ /(?:\n|^)X-Spam-Untrusted: ([^\n]*)\n/s;
  my $relays_u = $1;

  my $relays = "Trusted: $relays_t Untrusted: $relays_u";
  $relays =~ s/\s+/ /gs; $expected =~ s/\s+/ /gs;
  $relays =~ s/^ //gs; $expected =~ s/^ //gs;
  $relays =~ s/ $//gs; $expected =~ s/ $//gs;


  my $skip_test = 0;
  if ($expected =~ s/^\s*Patricia-Failure\s*//) {
    if ($have_patricia > 0) {
      $skip_test = 1;
    }
  } 

  #TEST #3 - RESULTS VS EXPECTED RESULTS
  if ($skip_test) {
    #SKIP TEST KNOWN TO FAIL WITH NET::PATRICIA
    # These test failures follow a garbage-in / garbage-out principle:
    # when configuration specifies invalid or conflicting data, then
    # the outcome is unspecified, tests can return different results
    # depending on modules installed
    print "[skipping test known error with Net::Patricia - Bug 6508...]\n";
    ok (1);
  } else {
    unless (ok ($relays eq $expected)) {
      $test_failure = 1;
    }
  }

  if ($test_failure) {
    print "conf: ", ('-' x 67), "\n", $conf;
    print "hdr sample: ", ('-' x 67), $hdrs, ('-' x 78), "\n\n";
    print "expected: $expected\n";
    print "got     : $relays\n\n";
    print "msg     : $msg\n\n";

    die "Dying on first test failure.";
  }

  $status->finish();
  $sa->finish();
}

