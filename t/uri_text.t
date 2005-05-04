#!/usr/bin/perl -w

# test URIs as grabbed from text/plain messages

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
use SATest; sa_t_init("uri_text");
use Test;
use Mail::SpamAssassin;
use IO::File;
use vars qw(%patterns %anti_patterns);

# settings
plan tests => 2;

# initialize SpamAssassin
my $sa = Mail::SpamAssassin->new({
    rules_filename => "$prefix/t/log/test_rules_copy",
    site_rules_filename => "$prefix/t/log/test_default.cf",
    userprefs_filename  => "$prefix/masses/spamassassin/user_prefs",
    local_tests_only    => 1,
    debug             => 0,
    dont_copy_prefs   => 1,
});
$sa->init(0); # parse rules

# load tests and write mail
my $mail = 'log/uri_text.eml';
%patterns = ();
%anti_patterns = ();
write_mail();

# test message
my $fh = IO::File->new_tmpfile();
open(STDERR, ">&=".fileno($fh)) || die "Cannot reopen STDERR";
ok(sarun("-t --debug=uri < log/uri_text.eml"));
seek($fh, 0, 0);
my $error = do {
    local $/;
    <$fh>;
};

# run patterns and anti-patterns
my $failures = 0;
for my $pattern (keys %patterns) {
  if ($error !~ /\Q${pattern}\E/) {
    print "did not find $pattern\n";
    $failures++;
  }
}
for my $anti_pattern (keys %anti_patterns) {
  if ($error =~ /\Q${anti_pattern}\E/) {
    print "did find $anti_pattern\n";
    $failures++;
  }
}
ok(!$failures);

# function to write test email
sub write_mail {
  if (open(MAIL, ">$mail")) {
    print MAIL <<'EOF';
Message-ID: <clean.1010101@example.com>
Date: Mon, 07 Oct 2002 09:00:00 +0000
From: Sender <sender@example.com>
MIME-Version: 1.0
To: Recipient <recipient@example.com>
Subject: this is a trivial message
Content-Type: text/plain
Content-Transfer-Encoding: 7bit

EOF
    while (<DATA>) {
      if (/^(.*?)\t+(.*?)\s*$/) {
	my $string = $1;
	my @patterns = split(' ', $2);
	if ($string && @patterns) {
	  print MAIL "$string\n";
	  for my $pattern (@patterns) {
	    if ($pattern =~ /^\!(.*)/) {
	      $anti_patterns{$1} = 1;
	    }
	    else {
	      $patterns{$pattern} = 1;
	    }
	  }
	}
      }
    }
    close(MAIL);
  }
  else {
    die "can't open output file: $!";
  }
}

# <line>    : <string><tabs><matches>
# <string>  : string in the body
# <tabs>    : one or more tabs
# <matches> : patterns expected to be found in URI output, if preceded by ! if
#             it is an antipattern, each pattern is separated by whitespace
__DATA__
www5.poh6feib.com	poh6feib
vau6yaer.com		vau6yaer
www5.poh6feib.info	poh6feib
Haegh3de.co.uk		Haegh3de

ftp.yeinaix3.co.uk	ftp://ftp.yeinaix3.co.uk !http://ftp.yeinaix3.co.uk
ftp5.riexai5r.co.uk	http://ftp5.riexai5r.co.uk !ftp://ftp5.riexai5r.co.uk

10.1.1.1		!10.1.1.1
10.1.2.1/		!10.1.2.1
http://10.1.3.1/	10.1.3.1

quau0wig.quau0wig	!quau0wig
foo.Cahl1goo.php	!Cahl1goo
www5.mi1coozu.php	!mi1coozu
www.mezeel0P.php	!mezeel0P
bar.neih6fee.com.php	!neih6fee
www.zai6Vuwi.com.bar	!zai6Vuwi

=www.deiJ1pha.com	www.deiJ1pha.com
@www.Te0xohxu.com	www.Te0xohxu.com
.www.kuiH5sai.com	www.kuiH5sai.com

a=www.zaiNgoo7.com	www.zaiNgoo7.com
b@www.vohWais0.com	mailto:b@www.vohWais0.com !http://www.vohWais0.com
c.www.moSaoga8.com	www.moSaoga8.com

foo @ cae8kaip.com	mailto:foo@cae8kaip.com
xyz..geifoza0.com	!geifoza0

joe@koja3fui.koja3fui	!koja3fui
