#!/usr/bin/perl

# supporting tests for: Bug 6362 - Change urirhssub mask syntax

use strict;
use warnings;
use re 'taint';
use lib '.'; use lib 't';

use SATest; sa_t_init("dnsbl_subtests");
use Test;

use vars qw(%patterns %anti_patterns);
use constant num_tests => 30;
use constant DO_RUN => 1;

BEGIN {
  plan tests => (DO_RUN ? num_tests : 0);
};

exit unless DO_RUN;

my $prefix = '.';
if (-e 'test_dir') {            # running from test directory, not ..
  $prefix = '..';
}

# Bug 5761 (no 127.0.0.1 in jail, use SPAMD_LOCALHOST if specified)
my $dns_server_localaddr = $ENV{'SPAMD_LOCALHOST'};
$dns_server_localaddr = '127.0.0.1'  if !$dns_server_localaddr;
$dns_server_localaddr = '::1'        if !$dns_server_localaddr;

my $dns_server_localport = '5353';  # some port (mdns), hopefully free

# test zone
my $z = 'sa-dbl-test.spamassassin.org';

my $local_conf = <<"EOD";
  use_bayes 0
  use_razor2 0
  use_pyzor 0
# use_auto_whitelist 0
# use_dcc 0
  score NO_RELAYS 0
  score NO_RECEIVED 0
  score TVD_SPACE_RATIO 0

  rbl_timeout 5
  dns_available yes
  clear_dns_servers
  dns_server [$dns_server_localaddr]:$dns_server_localport

  urirhssub  X_URIBL_Y_2A   $z  A  127.0.1.2
  body       X_URIBL_Y_2A   eval:check_uridnsbl('X_URIBL_Y_2A')

  urirhssub  X_URIBL_Y_2B   $z  A  127.0.1.2-127.0.1.2
  body       X_URIBL_Y_2B   eval:check_uridnsbl('X_URIBL_Y_2B')

  urirhssub  X_URIBL_Y_2C   $z  A  127.0.1.2/0xffffffff
  body       X_URIBL_Y_2C   eval:check_uridnsbl('X_URIBL_Y_2C')

  urirhssub  X_URIBL_Y_2D   $z  A  127.0.1.2/255.255.255.255
  body       X_URIBL_Y_2D   eval:check_uridnsbl('X_URIBL_Y_2D')

  urirhssub  X_URIBL_Y_2E   $z  A  127.0.1.2/127.0.1.2
  body       X_URIBL_Y_2E   eval:check_uridnsbl('X_URIBL_Y_2E')

  urirhssub  X_URIBL_Y_2F   $z  A  0/128.255.254.253
  body       X_URIBL_Y_2F   eval:check_uridnsbl('X_URIBL_Y_2F')

  urirhssub  X_URIBL_Y_2G   $z  A  2
  body       X_URIBL_Y_2G   eval:check_uridnsbl('X_URIBL_Y_2G')

  urirhssub  X_URIBL_N_2G   $z  A  5
  body       X_URIBL_N_2G   eval:check_uridnsbl('X_URIBL_N_2G')

  urirhssub  X_URIBL_Y_ANY  $z  A  127.0.1.1-127.0.1.254
  body       X_URIBL_Y_ANY  eval:check_uridnsbl('X_URIBL_Y_ANY')

  urirhssub  X_URIBL_Y_3    $z  A  127.0.1.3-127.0.1.19
  body       X_URIBL_Y_3    eval:check_uridnsbl('X_URIBL_Y_3')

  urirhssub  X_URIBL_N_3    $z  A  127.0.1.4-127.0.1.18
  body       X_URIBL_N_3    eval:check_uridnsbl('X_URIBL_Y_3')

  urirhssub  X_URIBL_N_0A   $z  A  127.0.0.0
  body       X_URIBL_N_0A   eval:check_uridnsbl('X_URIBL_N_0A')

  urirhssub  X_URIBL_N_0B   $z  A  127.0.1.0
  body       X_URIBL_N_0B   eval:check_uridnsbl('X_URIBL_N_0B')

  urirhssub  X_URIBL_N_255A $z  A  127.0.1.255
  body       X_URIBL_N_255A eval:check_uridnsbl('X_URIBL_N_255A')

  urirhssub  X_URIBL_N_255B $z  A  0.0.0.255/0.0.0.255
  body       X_URIBL_N_255B eval:check_uridnsbl('X_URIBL_N_255B')
EOD

my(@testzone) = map { chomp; s/[ \t]+//; $_ } split(/^/, <<"EOD");
  $z               3600 IN SOA  ns.$z hostmaster.$z (1 10800 1800 2419200 3600)
  $z               3600 IN NS   ns.$z
  $z               3600 IN MX 0 .
  ns.$z            3600 IN A    127.0.0.1
  ns.$z            3600 IN AAAA ::1
  foo.$z           3600 IN A    10.1.2.3
  foo.$z           3600 IN A    10.1.2.4
  dbltest.com.$z   3600 IN A    127.0.1.2
  dbltest.com.$z   3600 IN TXT  "test answer on dbltest.com"
  dbltest03.com.$z 3600 IN A    127.0.1.3
  dbltest19.com.$z 3600 IN A    127.0.1.19
  dbltest20.com.$z 3600 IN A    127.0.1.20
  dbltest21.com.$z 3600 IN A    127.0.1.21
  dbltest39.com.$z 3600 IN A    127.0.1.39
  dbltest40.com.$z 3600 IN A    127.0.1.40
  dbltest50.com.$z 3600 IN A    127.0.1.50
  dbltest59.com.$z 3600 IN A    127.0.1.59
  dbltest99.com.$z 3600 IN A    127.0.1.99
  dbltestER.com.$z 3600 IN A    127.0.1.255
  dbltestER.com.$z 3600 IN TXT  "No IP queries allowed"
  10.1.2.3.$z      3600 IN A    127.0.1.255
  10.1.2.3.$z      3600 IN TXT  "No IP queries allowed"
EOD

# ---------------------------------------------------------------------------

use Net::DNS::Nameserver;

sub reply_handler {
  my($qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
  my($rcode, @ans, @auth, @add);
  my $qclass_uc = uc $qclass;
  my $qtype_uc  = uc $qtype;
# print "Received query from $peerhost to ". $conn->{"sockhost"}. "\n";
# $query->print;
  $rcode = "NXDOMAIN";
  for my $rec_str (@testzone) {
    my($rrname,$rrttl,$rrclass,$rrtype,$rrdata) = split(' ',$rec_str,5);
    if ($qclass_uc eq uc($rrclass) && lc($rrname) eq lc($qname)) {
      $rcode = 'NOERROR';
      if ($qtype_uc eq uc($rrtype) || $qtype_uc eq 'ANY') {
        push(@ans, Net::DNS::RR->new(
                     join(' ', $qname, $rrttl, $qclass, $rrtype, $rrdata)));
      }
    }
  }
  # special DBL test case - numerical IP query handling
  if ($qclass_uc eq 'IN' && $qname =~ /^[0-9.]+\.\Q$z\E\z/is) {
    $rcode = 'NOERROR';
    if ($qtype_uc eq 'A' || $qtype_uc eq 'ANY') {
      push(@ans, Net::DNS::RR->new(join(' ',
                 $qname, '3600', $qclass, 'A', '127.0.1.255')));
    }
    if ($qtype_uc eq 'TXT' || $qtype_uc eq 'ANY') {
      push(@ans, Net::DNS::RR->new(join(' ',
                 $qname, '3600', $qclass, 'TXT', '"No IP queries allowed"')));
    }
  }
  return ($rcode, \@ans, \@auth, \@add);
}

sub dns_server($$) {
  my($local_addr, $local_port) = @_;
  my $ns = Net::DNS::Nameserver->new(
    LocalAddr => $local_addr, LocalPort => $local_port,
    ReplyHandler => \&reply_handler, Verbose => 0);
  $ns  or die "Cannot create a nameserver object";
  $ns->main_loop;
}

# ---------------------------------------------------------------------------

use Mail::SpamAssassin;
my $spamassassin_obj;

sub process_sample_urls(@) {
  my(@url_list) = @_;
  my($mail_obj, $per_msg_status, $spam_report);
  $spamassassin_obj->timer_reset;

  my $msg = <<'EOD';
From: "DNSBL Testing" <ab@example.org>
To: someone@example.org
Subject: test
Date: Mon, 8 Mar 2010 15:10:44 +0100
Message-Id: <test.123.test@example.org>

EOD
  $msg .= $_."\n" for @url_list;

  $mail_obj = $spamassassin_obj->parse($msg,0);
  if ($mail_obj) {
    local($1,$2,$3,$4,$5,$6);  # avoid Perl 5.8.x bug, $1 can get tainted
    $per_msg_status = $spamassassin_obj->check($mail_obj);
  }
  if ($per_msg_status) {
    $spam_report = $per_msg_status->get_tag('REPORT');
    $per_msg_status->finish;
  }
  if ($mail_obj) {
    $mail_obj->finish;
  }
  $spam_report =~ s/\A(\s*\n)+//s;
# print "\t$spam_report\n";
  return $spam_report;
}

sub test_samples($$) {
  my($patt_antipatt_list,$url_list_ref) = @_;
  my $el = $patt_antipatt_list->[0];
  shift @$patt_antipatt_list  if @$patt_antipatt_list > 1;  # last autorepeats
  my($patt,$anti) = split(m{\s* / \s*}x, $el, 2);
  %patterns      = map { (" $_ ", $_) } split(' ',$patt);
  %anti_patterns = map { (" $_ ", $_) } split(' ',$anti);
  my $spam_report = process_sample_urls(@$url_list_ref);
  clear_pattern_counters();
  patterns_run_cb($spam_report);
  my $status = ok_all_patterns();
  printf("\nTest on %s failed:\n%s\n",
         join(', ',@$url_list_ref), $spam_report)  if !$status;
}

# detach a DNS server process
my $pid = fork();
defined $pid or die "Cannot fork: $!";
if (!$pid) {  # child
  dns_server($dns_server_localaddr, $dns_server_localport);
  exit;
}

# parent
# print STDERR "Forked a DNS server process [$pid]\n";
sleep 1;

$spamassassin_obj = Mail::SpamAssassin->new({
# rules_filename      => "$prefix/t/log/test_rules_copy",
# require_rules       => 1,
  rules_filename      => "/dev/null",
  site_rules_filename => "$prefix/t/log/localrules.tmp",
  userprefs_filename  => "$prefix/masses/spamassassin/user_prefs",
  post_config_text    => $local_conf,
  dont_copy_prefs     => 1,
# debug               => 'dns,async,uridnsbl',
});
ok($spamassassin_obj);
$spamassassin_obj->compile_now;  # try to preloaded most modules

test_samples(
  [q{ X_URIBL_Y_2A X_URIBL_Y_2B X_URIBL_Y_2C X_URIBL_Y_2D X_URIBL_Y_2E
      X_URIBL_Y_2F X_URIBL_Y_2G X_URIBL_Y_ANY / X_URIBL_N_2E X_URIBL_N_2G
      X_URIBL_N_3 X_URIBL_N_0A X_URIBL_N_0B X_URIBL_N_255A X_URIBL_N_255B }],
  [qw( http://dbltest.com/ )]);

test_samples(
  [q{ X_URIBL_Y_2A X_URIBL_Y_2B X_URIBL_Y_2C X_URIBL_Y_2D X_URIBL_Y_2E
      X_URIBL_Y_2F X_URIBL_Y_2G X_URIBL_Y_ANY X_URIBL_Y_3 / X_URIBL_N_3
      X_URIBL_N_0A X_URIBL_N_0B X_URIBL_N_255A X_URIBL_N_255B }],
  [qw( http://dbltest.com/ http://dbltest03.com/ http://dbltest19.com/
       http://10.11.22.33/ )]);

if ($pid) {
  kill('TERM',$pid) or die "Cannot stop a DNS server [$pid]: $!";
  waitpid($pid,0);
  undef $pid;
}

END {
  $spamassassin_obj->finish  if $spamassassin_obj;
  kill('KILL',$pid)  if $pid;  # ignoring status
}
