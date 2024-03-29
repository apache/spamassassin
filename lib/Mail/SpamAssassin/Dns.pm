# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

use strict;  # make Test::Perl::Critic happy
package Mail::SpamAssassin::Dns; 1;

package Mail::SpamAssassin::PerMsgStatus;

use strict;
use warnings;
# use bytes;
use re 'taint';

use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::PerMsgStatus;
use Mail::SpamAssassin::AsyncLoop;
use Mail::SpamAssassin::Constants qw(:ip);
use Mail::SpamAssassin::Util qw(untaint_var am_running_on_windows compile_regexp);

use File::Spec;
use IO::Socket;
use POSIX ":sys_wait_h";


our $KNOWN_BAD_DIALUP_RANGES; # Nothing uses this var???
our $LAST_DNS_CHECK = 0;

# use very well-connected domains (fast DNS response, many DNS servers,
# geographical distribution is a plus, TTL of at least 3600s)
# these MUST contain both A/AAAA records so we can test dns_options v6
# Updated 8/2019 from https://ip6.nl/#!list?db=alexa500
# 
our @EXISTING_DOMAINS = qw{
  akamai.com
  bing.com
  cloudflare.com
  digitalpoint.com
  facebook.com
  google.com
  linkedin.com
  netflix.com
  php.net
  wikipedia.org
  yahoo.com
};

our $IS_DNS_AVAILABLE = undef;

#Removed $VERSION per BUG 6422
#$VERSION = 'bogus';     # avoid CPAN.pm picking up razor ver

###########################################################################

sub do_rbl_lookup {
  my ($self, $rule, $set, $type, $host, $subtest) = @_;

  if (defined $subtest) {
    if ($subtest =~ /^sb:/) {
      info("dns: ignored $rule, SenderBase rules are deprecated");
      return 0;
    }
    # Compile as regex if not pure ip/bitmask (same check in process_dnsbl_result)
    if ($subtest !~ /^\d+(?:\.\d+\.\d+\.\d+)?$/) {
      my ($rec, $err) = compile_regexp($subtest, 0);
      if (!$rec) {
        warn("dns: invalid rule $rule subtest regexp '$subtest': $err\n");
        return 0;
      }
      $subtest = $rec;
    }
  }

  dbg("dns: launching rule %s, set %s, type %s, %s", $rule, $set, $type,
    defined $subtest ? "subtest $subtest" : 'no subtest');

  my $ent = {
    rulename => $rule,
    type => "DNSBL",
    set => $set,
    subtest => $subtest,
  };
  my $ret = $self->{async}->bgsend_and_start_lookup($host, $type, undef, $ent,
    sub { my($ent, $pkt) = @_; $self->process_dnsbl_result($ent, $pkt) },
    master_deadline => $self->{master_deadline}
  );

  return 0 if defined $ret; # no query started
  return; # return undef for async status
}

# Deprecated, was only used from DNSEval.pm?
sub do_dns_lookup {
  my ($self, $rule, $type, $host) = @_;

  my $ent = {
    rulename => $rule,
    type => "DNSBL",
  };
  $self->{async}->bgsend_and_start_lookup($host, $type, undef, $ent,
    sub { my($ent, $pkt) = @_; $self->process_dnsbl_result($ent, $pkt) },
    master_deadline => $self->{master_deadline}
  );
}

###########################################################################

sub dnsbl_hit {
  my ($self, $rule, $question, $answer) = @_;

  my $log = "";
  if (substr($rule, 0, 2) eq "__") {
    # don't bother with meta rules
  } elsif ($answer->type eq 'TXT') {
    # txtdata returns a non- zone-file-format encoded result, unlike rdstring;
    # avoid space-separated RDATA <character-string> fields if possible,
    # txtdata provides a list of strings in a list context since Net::DNS 0.69
    $log = join('', $answer->txtdata);
    utf8::encode($log)  if utf8::is_utf8($log);
    local $1;
    $log =~ s{ (?<! [<(\[] ) (https? : // \S+)}{<$1>}xgi;
  } else {  # assuming $answer->type eq 'A'
    local($1,$2,$3,$4,$5);
    if ($question->string =~ /^((?:[0-9a-fA-F]\.){32})(\S+\w)/) {
      $log = ' listed in ' . lc($2);
      my $ipv6addr = join('', reverse split(/\./, lc $1));
      $ipv6addr =~ s/\G(....)/$1:/g;  chop $ipv6addr;
      $ipv6addr =~ s/:0{1,3}/:/g;
      $log = $ipv6addr . $log;
    } elsif ($question->string =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)\.(\S+\w)/) {
      $log = "$4.$3.$2.$1 listed in " . lc($5);
    } elsif ($question->string =~ /^(\S+)(?<!\.)/) {
      $log = "listed in ".lc($1);
    }
  }

  if ($log) {
    $self->test_log($log, $rule);
  }

  if (!$self->{tests_already_hit}->{$rule}) {
    dbg("dns: rbl rule $rule hit");
    $self->got_hit($rule, "RBL: ", ruletype => "dnsbl");
  }
}

sub dnsbl_uri {
  my ($self, $question, $answer) = @_;

  my $rdatastr;
  if ($answer->UNIVERSAL::can('txtdata')) {
    # txtdata returns a non- zone-file-format encoded result, unlike rdstring;
    # avoid space-separated RDATA <character-string> fields if possible,
    # txtdata provides a list of strings in a list context since Net::DNS 0.69
    $rdatastr = join('', $answer->txtdata);
  } else {
    $rdatastr = $answer->rdstring;
    # encoded in a RFC 1035 zone file format (escaped), decode it
    $rdatastr =~ s{ \\ ( [0-9]{3} | (?![0-9]{3}) . ) }
                  { length($1)==3 && $1 <= 255 ? chr($1) : $1 }xgse;
  }

  # Bug 7236: Net::DNS attempts to decode text strings in a TXT record as
  # UTF-8 since version 0.69, which is undesired: octets failing the UTF-8
  # decoding are converted to a Unicode "replacement character" U+FFFD, and
  # ASCII text is unnecessarily flagged as perl native characters.
  utf8::encode($rdatastr)  if utf8::is_utf8($rdatastr);

  my $qname = $question->qname;
  if (defined $qname && defined $rdatastr) {
    my $qclass = $question->qclass;
    my $qtype = $question->qtype;
    my @vals;
    push(@vals, "class=$qclass") if $qclass ne "IN";
    push(@vals, "type=$qtype") if $qtype ne "A";
    my $uri = "dns:$qname" . (@vals ? "?" . join(";", @vals) : "");

    $self->{dnsuri}{$uri}{$rdatastr} = 1;
    dbg("dns: hit <$uri> $rdatastr");
  }
}

# called as a completion routine to bgsend by DnsResolver::poll_responses;
# returns 1 on successful packet processing
sub process_dnsbl_result {
  my ($self, $ent, $pkt) = @_;

  return if !$pkt;
  my $question = ($pkt->question)[0];
  return if !$question;

  my $rulename = $ent->{rulename};

  # Mark rule ready for meta rules, but only if this was the last lookup
  # pending, rules can have many lookups launched for different IPs
  if (!$self->get_async_pending_rules($rulename)) {
    $self->rule_ready($rulename);
    # Mark depending check_rbl_sub rules too
    if (exists $self->{rbl_subs}{$ent->{set}}) {
      foreach (@{$self->{rbl_subs}{$ent->{set}}}) {
        $self->rule_ready($_->[1]);
      }
    }
  }

  # DNSBL tests are here
  foreach my $answer ($pkt->answer) {
    next if !$answer;
    # track all responses
    $self->dnsbl_uri($question, $answer);
    my $answ_type = $answer->type;
    # TODO: there are some CNAME returns that might be useful
    next if $answ_type ne 'A' && $answ_type ne 'TXT';

    my $rdatastr;
    if ($answer->UNIVERSAL::can('txtdata')) {
      # txtdata returns a non- zone-file-format encoded result, unlike rdstring;
      # avoid space-separated RDATA <character-string> fields if possible,
      # txtdata provides a list of strings in a list context since Net::DNS 0.69
      $rdatastr = join('', $answer->txtdata);
    } else {
      $rdatastr = $answer->rdstring;
      # encoded in a RFC 1035 zone file format (escaped), decode it
      $rdatastr =~ s{ \\ ( [0-9]{3} | (?![0-9]{3}) . ) }
                    { length($1)==3 && $1 <= 255 ? chr($1) : $1 }xgse;
    }

    # Bug 7236: Net::DNS attempts to decode text strings in a TXT record as
    # UTF-8 since version 0.69, which is undesired: octets failing the UTF-8
    # decoding are converted to a Unicode "replacement character" U+FFFD, and
    # ASCII text is unnecessarily flagged as perl native characters.
    utf8::encode($rdatastr)  if utf8::is_utf8($rdatastr);

    # skip any A record that isn't on 127.0.0.0/8
    next if $answ_type eq 'A' && $rdatastr !~ /^127\./;

    # check_rbl tests
    if (defined $ent->{subtest}) {
      if ($self->check_subtest($rdatastr, $ent->{subtest})) {
        $self->dnsbl_hit($rulename, $question, $answer);
      }
    } else {
      $self->dnsbl_hit($rulename, $question, $answer);
    }

    # check_rbl_sub tests
    if (exists $self->{rbl_subs}{$ent->{set}}) {
      $self->process_dnsbl_set($ent->{set}, $question, $answer, $rdatastr);
    }
  }

  return 1;
}

sub process_dnsbl_set {
  my ($self, $set, $question, $answer, $rdatastr) = @_;

  foreach my $args (@{$self->{rbl_subs}{$set}}) {
    my $subtest = $args->[0];
    my $rule = $args->[1];
    next if $self->{tests_already_hit}->{$rule};
    if ($self->check_subtest($rdatastr, $subtest)) {
      $self->dnsbl_hit($rule, $question, $answer);
    }
  }
}

sub check_subtest {
  my ($self, $rdatastr, $subtest) = @_;

  # regular expression
  if (ref($subtest) eq 'Regexp') {
    if ($rdatastr =~ $subtest) {
      return 1;
    }
  }
  # bitmask
  elsif ($subtest =~ /^\d+$/) {
    # Bug 6803: response should be within 127.0.0.0/8, ignore otherwise
    if ($rdatastr =~ m/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/ &&
        Mail::SpamAssassin::Util::my_inet_aton($rdatastr) & $subtest)
    {
      return 1;
    }
  }
  else {
    # test for exact equality (an IPv4 address)
    if ($subtest eq $rdatastr) {
      return 1;
    }
  }

  return 0;
}

# Deprecated since 4.0, meta rules do not depend on priorities anymore
sub harvest_until_rule_completes {}

sub harvest_dnsbl_queries {
  my ($self) = @_;

  dbg("dns: harvest_dnsbl_queries");

  for (my $first=1;  ; $first=0) {
    # complete_lookups() may call completed_callback(), which may
    # call start_lookup() again (like in Plugin::URIDNSBL)

    # the first time around we specify a 0 timeout, which gives
    # complete_lookups a chance to ripe any available results and
    # abort overdue requests, without needlessly waiting for more

    my ($alldone,$anydone) =
      $self->{async}->complete_lookups($first ? 0 : 1.0,  1);

    last  if $alldone || $self->{deadline_exceeded} || $self->{shortcircuited};

    dbg("dns: harvest_dnsbl_queries - check_tick");
    $self->{main}->call_plugins ("check_tick", { permsgstatus => $self });
  }

  # explicitly abort anything left
  $self->{async}->abort_remaining_lookups();
  $self->{async}->log_lookups_timing();
  1;
}

# collect and process whatever DNS responses have already arrived,
# don't waste time waiting for more, don't poll too often.
# don't abort any queries even if overdue, 
sub harvest_completed_queries {
  my ($self) = @_;

  # don't bother collecting responses too often
  my $last_poll_time = $self->{async}->last_poll_responses_time();
  return if defined $last_poll_time && time - $last_poll_time < 0.1;

  my ($alldone,$anydone) = $self->{async}->complete_lookups(0, 0);
  if ($anydone) {
    dbg("dns: harvested completed queries");
#   $self->{main}->call_plugins ("check_tick", { permsgstatus => $self });
  }
}

sub set_rbl_tag_data {
  my ($self) = @_;

  return if !$self->{dnsuri};

  # DNS URIs
  my $rbl_tag = $self->{tag_data}->{RBL};  # just in case, should be empty
  $rbl_tag = ''  if !defined $rbl_tag;
  while (my ($dnsuri, $answers) = each %{$self->{dnsuri}}) {
    # when parsing, look for elements of \".*?\" or \S+ with ", " as separator
    $rbl_tag .= "<$dnsuri>" . " [" . join(", ", keys %$answers) . "]\n";
  }
  if (defined $rbl_tag && $rbl_tag ne '') {
    chomp $rbl_tag;
    $self->set_tag('RBL', $rbl_tag);
  }
}

###########################################################################

sub rbl_finish {
  my ($self) = @_;

  $self->set_rbl_tag_data();

  delete $self->{rbl_subs};
  delete $self->{dnsuri};
}

###########################################################################

sub load_resolver {
  my ($self) = @_;
  $self->{resolver} = $self->{main}->{resolver};
  return $self->{resolver}->load_resolver();
}

sub clear_resolver {
  my ($self) = @_;
  dbg("dns: clear_resolver");
  $self->{main}->{resolver}->{res} = undef;
  return 0;
}

# Deprecated since 4.0.0
sub lookup_ns {
  warn "dns: deprecated lookup_ns called, query ignored\n";
  return;
}

sub test_dns_a_aaaa {
  my ($self, $dom) = @_;

  return if ($self->server_failed_to_respond_for_domain ($dom));

  my ($a, $aaaa) = (0, 0);

  if ($self->{conf}->{dns_options}->{v4}) {
    eval {
      my $query = $self->{resolver}->send($dom, 'A');
      if ($query) {
        foreach my $rr ($query->answer) {
          if ($rr->type eq 'A') { $a = 1; last; }
        }
      }
      1;
    } or do {
      my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
      dbg("dns: test A lookup failed horribly, perhaps bad resolv.conf setting? (%s)", $eval_stat);
      return (undef, undef);
    };
    if (!$a) {
      dbg("dns: test A lookup returned no results, use \"dns_options nov4\" if resolver doesn't support A queries");
    }
  } else {
    $a = 1;
  }

  if ($self->{conf}->{dns_options}->{v6}) {
    eval {
      my $query = $self->{resolver}->send($dom, 'AAAA');
      if ($query) {
        foreach my $rr ($query->answer) {
          if ($rr->type eq 'AAAA') { $aaaa = 1; last; }
        }
      }
      1;
    } or do {
      my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
      dbg("dns: test AAAA lookup failed horribly, perhaps bad resolv.conf setting? (%s)", $eval_stat);
      return (undef, undef);
    };
    if (!$aaaa) {
      dbg("dns: test AAAA lookup returned no results, use \"dns_options nov6\" if resolver doesn't support AAAA queries");
    }
  } else {
    $aaaa = 1;
  }

  return ($a, $aaaa);
}

sub is_dns_available {
  my ($self) = @_;
  my $dnsopt = $self->{conf}->{dns_available};

  # Fast response for the most common cases
  return 1 if $IS_DNS_AVAILABLE && $dnsopt eq "yes";
  return 0 if defined $IS_DNS_AVAILABLE && $dnsopt eq "no";

  # croak on misconfigured flags
  if (!$self->{conf}->{dns_options}->{v4} &&
      !$self->{conf}->{dns_options}->{v6})
  {
    warn 'dns: error: dns_options "nov4" and "nov6" are both set, '.
         ' only use either, or use "dns_available no" to really disable DNS'.
         "\n";
    $IS_DNS_AVAILABLE = 0;
    $self->{conf}->{dns_available} = "no";
    return 0;
  }

  # undef $IS_DNS_AVAILABLE if we should be testing for
  # working DNS and our check interval time has passed
  if ($dnsopt eq "test") {
    my $diff = time - $LAST_DNS_CHECK;
    if ($diff > ($self->{conf}->{dns_test_interval}||600)) {
      $IS_DNS_AVAILABLE = undef;
      if ($LAST_DNS_CHECK) {
        dbg("dns: is_dns_available() last checked %.1f seconds ago; re-checking", $diff);
      } else {
        dbg("dns: is_dns_available() initial check");
      }
    }
    $LAST_DNS_CHECK = time;
  }

  return $IS_DNS_AVAILABLE if defined $IS_DNS_AVAILABLE;

  $IS_DNS_AVAILABLE = 0;

  if ($dnsopt eq "no") {
    dbg("dns: dns_available set to no in config file, skipping test");
    return $IS_DNS_AVAILABLE;
  }

  # Even if "dns_available" is explicitly set to "yes", we want to ignore
  # DNS if we're only supposed to be looking at local tests.
  if ($self->{main}->{local_tests_only}) {
    dbg("dns: using local tests only, DNS not available");
    return $IS_DNS_AVAILABLE;
  }

  #$self->clear_resolver();
  if (!$self->load_resolver()) {
    dbg("dns: could not load resolver, DNS not available");
    return $IS_DNS_AVAILABLE;
  }

  if ($dnsopt eq "yes") {
    # optionally shuffle the list of nameservers to distribute the load
    if ($self->{conf}->{dns_options}->{rotate}) {
      my @nameservers = $self->{resolver}->available_nameservers();
      Mail::SpamAssassin::Util::fisher_yates_shuffle(\@nameservers);
      dbg("dns: shuffled NS list: " . join(", ", @nameservers));
      $self->{resolver}->available_nameservers(@nameservers);
    }
    $IS_DNS_AVAILABLE = 1;
    dbg("dns: dns_available set to yes in config file, skipping test");
    return $IS_DNS_AVAILABLE;
  }

  my @domains;
  my @rtypes;
  push @rtypes, 'A' if $self->{main}->{conf}->{dns_options}->{v4};
  push @rtypes, 'AAAA' if $self->{main}->{conf}->{dns_options}->{v6};
  if ($dnsopt =~ /^test:\s*(\S.*)$/) {
    @domains = split (/\s+/, $1);
    dbg("dns: testing %s records for user specified domains: %s",
        join("/", @rtypes), join(", ", @domains));
  } else {
    @domains = @EXISTING_DOMAINS;
    dbg("dns: testing %s records for built-in domains: %s",
        join("/", @rtypes), join(", ", @domains));
  }

  # do the test with a full set of configured nameservers
  my @nameservers = $self->{resolver}->configured_nameservers();

  # optionally shuffle the list of nameservers to distribute the load
  if ($self->{conf}->{dns_options}->{rotate}) {
    Mail::SpamAssassin::Util::fisher_yates_shuffle(\@nameservers);
    dbg("dns: shuffled NS list, testing: " . join(", ", @nameservers));
  } else {
    dbg("dns: testing resolver nameservers: " . join(", ", @nameservers));
  }

  # Try the different nameservers here and collect a list of working servers
  my @good_nameservers;
  foreach my $ns (@nameservers) {
    $self->{resolver}->available_nameservers($ns);  # try just this one
    for (my $retry = 0; $retry < 3 && @domains; $retry++) {
      my $domain = splice(@domains, rand(@domains), 1);
      dbg("dns: trying $domain, server $ns ..." .
          ($retry ? " (retry $retry)" : ""));
      my ($ok_a, $ok_aaaa) = $self->test_dns_a_aaaa($domain);
      $self->{resolver}->finish_socket();
      if (!defined $ok_a || !defined $ok_aaaa) {
        # error printed already
        last;
      } elsif (!$ok_a && !$ok_aaaa) {
        dbg("dns: lookup of $domain using $ns failed, no results found");
      } else {
        dbg("dns: lookup of $domain using $ns succeeded => DNS available".
            " (set dns_available to override)");
        push(@good_nameservers, $ns);
        last;
      }
    }
  }

  if (!@good_nameservers) {
    dbg("dns: all NS queries failed => DNS unavailable ".
        "(set dns_available to override)");
  } else {
    $IS_DNS_AVAILABLE = 1;
    dbg("dns: NS list: ".join(", ", @good_nameservers));
    $self->{resolver}->available_nameservers(@good_nameservers);
  }

  dbg("dns: is DNS available? " . $IS_DNS_AVAILABLE);
  return $IS_DNS_AVAILABLE;
}

###########################################################################

sub server_failed_to_respond_for_domain {
  my ($self, $dom) = @_;
  if ($self->{dns_server_too_slow}->{$dom}) {
    dbg("dns: server for '$dom' failed to reply previously, not asking again");
    return 1;
  }
  return 0;
}

sub set_server_failed_to_respond_for_domain {
  my ($self, $dom) = @_;
  dbg("dns: server for '$dom' failed to reply, marking as bad");
  $self->{dns_server_too_slow}->{$dom} = 1;
}

###########################################################################

sub enter_helper_run_mode {
  my ($self) = @_;

  dbg("dns: entering helper-app run mode");
  $self->{old_slash} = $/;              # Razor pollutes this
  %{$self->{old_env}} = ();
  if ( %ENV ) {
    # undefined values in %ENV can result due to autovivification elsewhere,
    # this prevents later possible warnings when we restore %ENV
    while (my ($key, $value) = each %ENV) {
      $self->{old_env}->{$key} = $value if defined $value;
    }
  }

  Mail::SpamAssassin::Util::clean_path_in_taint_mode();

  my $newhome;
  if ($self->{main}->{home_dir_for_helpers}) {
    $newhome = $self->{main}->{home_dir_for_helpers};
  } else {
    # use spamd -u user's home dir
    $newhome = (Mail::SpamAssassin::Util::portable_getpwuid ($>))[7];
  }

  if ($newhome) {
    $ENV{'HOME'} = Mail::SpamAssassin::Util::untaint_file_path ($newhome);
  }

  # enforce SIGCHLD as DEFAULT; IGNORE causes spurious kernel warnings
  # on Red Hat NPTL kernels (bug 1536), and some users of the
  # Mail::SpamAssassin modules set SIGCHLD to be a fatal signal
  # for some reason! (bug 3507)
  $self->{old_sigchld_handler} = $SIG{CHLD};
  $SIG{CHLD} = 'DEFAULT';
}

sub leave_helper_run_mode {
  my ($self) = @_;

  dbg("dns: leaving helper-app run mode");
  $/ = $self->{old_slash};
  %ENV = %{$self->{old_env}};

  if (defined $self->{old_sigchld_handler}) {
    $SIG{CHLD} = $self->{old_sigchld_handler};
  } else {
    # if SIGCHLD has never been explicitly set, it's returned as undef.
    # however, when *setting* SIGCHLD, using undef(%) or assigning to an
    # undef value produces annoying 'Use of uninitialized value in scalar
    # assignment' warnings.  That's silly.  workaround:
    $SIG{CHLD} = 'DEFAULT';
  }
}

# note: this must be called before leave_helper_run_mode() is called,
# as the SIGCHLD signal must be set to DEFAULT for it to work.
sub cleanup_kids {
  my ($self, $pid) = @_;
  
  if ($SIG{CHLD} && $SIG{CHLD} ne 'IGNORE') {	# running from spamd
    waitpid ($pid, 0);
  }
}

###########################################################################

# Deprecated async functions, everything is handled automatically
# now by bgsend .. $self->{async}->{pending_rules}
sub register_async_rule_start {}
sub register_async_rule_finish {}
sub mark_all_async_rules_complete {}
sub is_rule_complete {}

# Return number of pending DNS lookups for a rule,
# or list all of rules still pending
sub get_async_pending_rules {
  my ($self, $rule) = @_;
  if (defined $rule) {
    return 0 if !exists $self->{async}->{pending_rules}{$rule};
    return scalar keys %{$self->{async}->{pending_rules}{$rule}};
  } else {
    return grep { %{$self->{async}->{pending_rules}{$_}} }
             keys %{$self->{async}->{pending_rules}};
  }
}

###########################################################################

1;
