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

package Mail::SpamAssassin::Dns;
1;

package Mail::SpamAssassin::PerMsgStatus;

use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::PerMsgStatus;
use Mail::SpamAssassin::AsyncLoop;
use Mail::SpamAssassin::Constants qw(:ip);
use File::Spec;
use IO::Socket;
use POSIX ":sys_wait_h";

use strict;
use warnings;
use bytes;

use vars qw{
  $KNOWN_BAD_DIALUP_RANGES @EXISTING_DOMAINS $IS_DNS_AVAILABLE $LAST_DNS_CHECK $VERSION
};

# use very well-connected domains (fast DNS response, many DNS servers,
# geographical distribution is a plus, TTL of at least 3600s)
@EXISTING_DOMAINS = qw{
  adelphia.net
  akamai.com
  apache.org
  cingular.com
  colorado.edu
  comcast.net
  doubleclick.com
  ebay.com
  gmx.net
  google.com
  intel.com
  kernel.org
  linux.org
  mit.edu
  motorola.com
  msn.com
  sourceforge.net
  sun.com
  w3.org
  yahoo.com
};

$IS_DNS_AVAILABLE = undef;

$VERSION = 'bogus';     # avoid CPAN.pm picking up razor ver

###########################################################################

BEGIN {
  # some trickery. Load these modules right here, if possible; that way, if
  # the module exists, we'll get it loaded now.  Very useful to avoid attempted
  # loads later (which will happen).  If we do a fork(), we could wind up
  # attempting to load these modules in *every* subprocess.
  #
  # We turn off strict and warnings, because Net::DNS and Razor both contain
  # crud that -w complains about (perl 5.6.0).  Not that this seems to work,
  # mind ;)

  no strict;
  local ($^W) = 0;

  eval {
    require Net::DNS;
    require Net::DNS::Resolver;
  };
  eval {
    require MIME::Base64;
  };
  eval {
    require IO::Socket::UNIX;
  };
};

###########################################################################

# TODO: $server is currently unused
sub do_rbl_lookup {
  my ($self, $rule, $set, $type, $server, $host, $subtest) = @_;

  my $key = "dns:$type:$host";
  my $existing = $self->{async}->get_lookup($key);

  # only make a specific query once
  if (!$existing) {
    dbg("dns: launching DNS $type query for $host in background");

    my $ent = {
      key => $key,
      type => "DNSBL-".$type,
      sets => [ ],  # filled in below
      rules => [ ], # filled in below
      # id is filled in after we send the query below
    };

    my $id = $self->{resolver}->bgsend($host, $type, undef, sub {
        my $pkt = shift;
        my $id = shift;
        $self->process_dnsbl_result($ent, $pkt);
        $self->{async}->report_id_complete($id);
      });

    $ent->{id} = $id;     # tie up the loose end
    $existing = $self->{async}->start_lookup($ent);
  }

  # always add set
  push @{$existing->{sets}}, $set;

  # sometimes match or always match
  if (defined $subtest) {
    $self->{dnspost}->{$set}->{$subtest} = $rule;
  }
  else {
    push @{$existing->{rules}}, $rule;
  }

  $self->{rule_to_rblkey}->{$rule} = $key;
}

# TODO: these are constant so they should only be added once at startup
sub register_rbl_subtest {
  my ($self, $rule, $set, $subtest) = @_;
  $self->{dnspost}->{$set}->{$subtest} = $rule;
}

sub do_dns_lookup {
  my ($self, $rule, $type, $host) = @_;

  my $key = "dns:$type:$host";

  # only make a specific query once
  return if $self->{async}->get_lookup($key);

  dbg("dns: launching DNS $type query for $host in background");

  my $ent = {
    key => $key,
    type => "DNSBL-".$type,
    rules => [ $rule ],
    # id is filled in after we send the query below
  };

  my $id = $self->{resolver}->bgsend($host, $type, undef, sub {
      my $pkt = shift;
      my $id = shift;
      $self->process_dnsbl_result($ent, $pkt);
      $self->{async}->report_id_complete($id);
    });

  $ent->{id} = $id;     # tie up the loose end
  $self->{async}->start_lookup($ent);
}

###########################################################################

sub dnsbl_hit {
  my ($self, $rule, $question, $answer) = @_;

  my $log = "";
  if (substr($rule, 0, 2) ne "__") {
    if ($answer->type eq 'TXT') {
      $log = $answer->rdatastr;
      $log =~ s/^"(.*)"$/$1/;
      $log =~ s/(http:\/\/\S+)/<$1>/g;
    }
    elsif ($question->string =~ m/^(\d+)\.(\d+)\.(\d+)\.(\d+)\.(\S+\w)/) {
      $log = "$4.$3.$2.$1 listed in $5";
    }
  }

  # TODO: this may result in some log messages appearing under the
  # wrong rules, since we could see this sequence: { test one hits,
  # test one's message is logged, test two hits, test one fires again
  # on another IP, test one's message is logged for that other IP --
  # but under test two's heading }.   Right now though it's better
  # than just not logging at all.

  $self->{already_logged} ||= { };
  if ($log && !$self->{already_logged}->{$log}) {
    $self->test_log($log);
    $self->{already_logged}->{$log} = 1;
  }

  if (!$self->{tests_already_hit}->{$rule}) {
    $self->got_hit($rule, "RBL: ", ruletype => "dnsbl");
  }
}

sub dnsbl_uri {
  my ($self, $question, $answer) = @_;

  my $qname = $question->qname;
  my $rdatastr = $answer->rdatastr;

  if (defined $qname && defined $rdatastr) {
    my $qclass = $question->qclass;
    my $qtype = $question->qtype;
    my @vals;
    push(@vals, "class=$qclass") if $qclass ne "IN";
    push(@vals, "type=$qtype") if $qtype ne "A";
    my $uri = "dns:$qname" . (@vals ? "?" . join(";", @vals) : "");
    push @{ $self->{dnsuri}->{$uri} }, $rdatastr;

    dbg ("dns: hit <$uri> $rdatastr");
  }
}

# returns 1 on successful packet processing
sub process_dnsbl_result {
  my ($self, $query, $packet) = @_;

  my $question = ($packet->question)[0];
  return if !defined $question;

  my $sets = $query->{sets} || [];
  my $rules = $query->{rules};

  # NO_DNS_FOR_FROM
  if ($self->{sender_host} &&
      $question->qname eq $self->{sender_host} &&
      $question->qtype =~ /^(?:A|MX)$/ &&
      $packet->header->rcode =~ /^(?:NXDOMAIN|SERVFAIL)$/ &&
      ++$self->{sender_host_fail} == 2)
  {
    for my $rule (@{$rules}) {
      $self->got_hit($rule, "DNS: ", ruletype => "dns");
    }
  }

  # DNSBL tests are here
  foreach my $answer ($packet->answer) {
    next if !defined $answer;
    # track all responses
    $self->dnsbl_uri($question, $answer);
    # TODO: there are some CNAME returns that might be useful
    next if ($answer->type ne 'A' && $answer->type ne 'TXT');
    # skip any A record that isn't on 127/8
    next if ($answer->type eq 'A' && $answer->rdatastr !~ /^127\./);
    for my $rule (@{$rules}) {
      $self->dnsbl_hit($rule, $question, $answer);
    }
    for my $set (@{$sets}) {
      if ($self->{dnspost}->{$set}) {
	$self->process_dnsbl_set($set, $question, $answer);
      }
    }
  }
  return 1;
}

sub process_dnsbl_set {
  my ($self, $set, $question, $answer) = @_;

  my $rdatastr = $answer->rdatastr;
  while (my ($subtest, $rule) = each %{ $self->{dnspost}->{$set} }) {
    next if $self->{tests_already_hit}->{$rule};

    # exact substr (usually IP address)
    if ($subtest eq $rdatastr) {
      $self->dnsbl_hit($rule, $question, $answer);
    }
    # senderbase
    elsif ($subtest =~ s/^sb://) {
      # SB rules are not available to users
      if ($self->{conf}->{user_defined_rules}->{$rule}) {
        dbg("dns: skipping rule '$rule': not supported when user-defined");
        next;
      }

      $rdatastr =~ s/^"?\d+-//;
      $rdatastr =~ s/"$//;
      my %sb = ($rdatastr =~ m/(?:^|\|)(\d+)=([^|]+)/g);
      my $undef = 0;
      while ($subtest =~ m/\bS(\d+)\b/g) {
	if (!defined $sb{$1}) {
	  $undef = 1;
	  last;
	}
	$subtest =~ s/\bS(\d+)\b/\$sb{$1}/;
      }

      # untaint. doing the usual $subtest=$1 doesn't work! (bug 3325)
      $subtest =~ /^(.*)$/;
      my $untainted = $1;
      $subtest = $untainted;

      $self->got_hit($rule, "SenderBase: ", ruletype => "dnsbl") if !$undef && eval $subtest;
    }
    # bitmask
    elsif ($subtest =~ /^\d+$/) {
      if ($rdatastr =~ m/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/ &&
	  Mail::SpamAssassin::Util::my_inet_aton($rdatastr) & $subtest)
      {
	$self->dnsbl_hit($rule, $question, $answer);
      }
    }
    # regular expression
    else {
      my $test = qr/$subtest/;
      if ($rdatastr =~ /$test/) {
	$self->dnsbl_hit($rule, $question, $answer);
      }
    }
  }
}

sub harvest_until_rule_completes {
  my ($self, $rule) = @_;

  return if !defined $self->{async}->get_last_start_lookup_time();

  my $deadline = $self->{conf}->{rbl_timeout} + $self->{async}->get_last_start_lookup_time();
  my $now = time;

  my @left = $self->{async}->get_pending_lookups();
  my $total = scalar @left;

  while (($now < $deadline) && !$self->{async}->complete_lookups(1))
  {
    if ($self->is_rule_complete($rule)) {
      return 1;
    }

    $self->{main}->call_plugins ("check_tick", { permsgstatus => $self });
    @left = $self->{async}->get_pending_lookups();

    # dynamic timeout
    my $dynamic = (int($self->{conf}->{rbl_timeout}
                      * (1 - (($total - scalar @left) / $total) ** 2) + 0.5)
                  + $self->{async}->get_last_start_lookup_time());
    $deadline = $dynamic if ($dynamic < $deadline);
    $now = time;
  }
}

sub harvest_dnsbl_queries {
  my ($self) = @_;

  return if !defined $self->{async}->get_last_start_lookup_time();

  my $deadline = $self->{conf}->{rbl_timeout} + $self->{async}->get_last_start_lookup_time();
  my $now = time;

  my @left = $self->{async}->get_pending_lookups();
  my $total = scalar @left;

  while (($now < $deadline) && !$self->{async}->complete_lookups(1))
  {
    $self->{main}->call_plugins ("check_tick", { permsgstatus => $self });
    @left = $self->{async}->get_pending_lookups();

    # dynamic timeout
    my $dynamic = (int($self->{conf}->{rbl_timeout}
                      * (1 - (($total - scalar @left) / $total) ** 2) + 0.5)
                  + $self->{async}->get_last_start_lookup_time());
    $deadline = $dynamic if ($dynamic < $deadline);
    $now = time;    # and loop again
  }

  dbg("dns: success for " . ($total - @left) . " of $total queries");

  # timeouts
  @left = $self->{async}->get_pending_lookups();
  for my $query (@left) {
    my $string = '';
    if (defined @{$query->{sets}}) {
      $string = join(",", grep defined, @{$query->{sets}});
    }
    elsif (defined @{$query->{rules}}) {
      $string = join(",", grep defined, @{$query->{rules}});
    }
    my $delay = time - $self->{async}->get_last_start_lookup_time();
    dbg("dns: timeout for $string after $delay seconds");
  }

  # and explicitly abort anything left
  $self->{async}->abort_remaining_lookups();
  $self->mark_all_async_rules_complete();
}

sub set_rbl_tag_data {
  my ($self) = @_;

  # DNS URIs
  while (my ($dnsuri, $answers) = each %{ $self->{dnsuri} }) {
    # when parsing, look for elements of \".*?\" or \S+ with ", " as separator
    $self->{tag_data}->{RBL} .= "<$dnsuri>" .
	" [" . join(", ", @{ $answers }) . "]\n";
  }

  chomp $self->{tag_data}->{RBL} if defined $self->{tag_data}->{RBL};
}

###########################################################################

sub rbl_finish {
  my ($self) = @_;

  $self->set_rbl_tag_data();

  delete $self->{dnscache};
  delete $self->{dnspost};
  delete $self->{dnsuri};
}

###########################################################################

sub load_resolver {
  my ($self) = @_;
  $self->{resolver} = $self->{main}->{resolver};
  return $self->{resolver}->load_resolver();
}

sub lookup_ns {
  my ($self, $dom) = @_;

  return unless $self->load_resolver();
  return if ($self->server_failed_to_respond_for_domain ($dom));

  my $nsrecords;
  dbg("dns: looking up NS for '$dom'");

  if (exists $self->{dnscache}->{NS}->{$dom}) {
    $nsrecords = $self->{dnscache}->{NS}->{$dom};

  } else {
    eval {
      my $query = $self->{resolver}->send($dom, 'NS');
      my @nses = ();
      if ($query) {
	foreach my $rr ($query->answer) {
	  if ($rr->type eq "NS") { push (@nses, $rr->nsdname); }
	}
      }
      $nsrecords = $self->{dnscache}->{NS}->{$dom} = [ @nses ];
    };
    if ($@) {
      dbg("dns: NS lookup failed horribly, perhaps bad resolv.conf setting? ($@)");
      return undef;
    }
  }

  $nsrecords;
}

sub lookup_mx {
  my ($self, $dom) = @_;

  return unless $self->load_resolver();
  return if ($self->server_failed_to_respond_for_domain ($dom));

  my $mxrecords;
  dbg("dns: looking up MX for '$dom'");

  if (exists $self->{dnscache}->{MX}->{$dom}) {
    $mxrecords = $self->{dnscache}->{MX}->{$dom};

  } else {
    eval {
      my $query = $self->{resolver}->send($dom, 'MX');
      my @ips = ();
      if ($query) {
	foreach my $rr ($query->answer) {
          # just keep the IPs, drop the preferences.
	  if ($rr->type eq "MX") { push (@ips, $rr->exchange); }
	}
      }

      $mxrecords = $self->{dnscache}->{MX}->{$dom} = [ @ips ];
    };
    if ($@) {
      dbg("dns: MX lookup failed horribly, perhaps bad resolv.conf setting? ($@)");
      return undef;
    }
  }

  $mxrecords;
}

sub lookup_mx_exists {
  my ($self, $dom) = @_;

  my $ret = 0;
  my $recs = $self->lookup_mx ($dom);
  if (!defined $recs) { return undef; }
  if (scalar @{$recs}) { $ret = 1; }

  dbg("dns: MX for '$dom' exists? $ret");
  return $ret;
}

sub lookup_ptr {
  my ($self, $dom) = @_;

  return undef unless $self->load_resolver();
  if ($self->{main}->{local_tests_only}) {
    dbg("dns: local tests only, not looking up PTR");
    return undef;
  }

  my $IP_PRIVATE = IP_PRIVATE;

  if ($dom =~ /${IP_PRIVATE}/) {
    dbg("dns: IP is private, not looking up PTR: $dom");
    return undef;
  }

  return if ($self->server_failed_to_respond_for_domain ($dom));

  dbg("dns: looking up PTR record for '$dom'");
  my $name = '';

  if (exists $self->{dnscache}->{PTR}->{$dom}) {
    $name = $self->{dnscache}->{PTR}->{$dom};

  } else {
    eval {
      my $query = $self->{resolver}->send($dom);
      if ($query) {
	foreach my $rr ($query->answer) {
	  if ($rr->type eq "PTR") {
	    $name = $rr->ptrdname; last;
	  }
	}
      }

      $name = $self->{dnscache}->{PTR}->{$dom} = $name;
    };

    if ($@) {
      dbg("dns: PTR lookup failed horribly, perhaps bad resolv.conf setting? ($@)");
      return undef;
    }
  }
  dbg("dns: PTR for '$dom': '$name'");

  # note: undef is never returned, unless DNS is unavailable.
  return $name;
}

sub lookup_a {
  my ($self, $name) = @_;

  return undef unless $self->load_resolver();
  if ($self->{main}->{local_tests_only}) {
    dbg("dns: local tests only, not looking up A records");
    return undef;
  }

  return if ($self->server_failed_to_respond_for_domain ($name));

  dbg("dns: looking up A records for '$name'");
  my @addrs = ();

  if (exists $self->{dnscache}->{A}->{$name}) {
    my $addrptr = $self->{dnscache}->{A}->{$name};
    @addrs = @{$addrptr};

  } else {
    eval {
      my $query = $self->{resolver}->send($name);
      if ($query) {
	foreach my $rr ($query->answer) {
	  if ($rr->type eq "A") {
	    push (@addrs, $rr->address);
	  }
	}
      }
      $self->{dnscache}->{A}->{$name} = [ @addrs ];
    };

    if ($@) {
      dbg("dns: A lookup failed horribly, perhaps bad resolv.conf setting? ($@)");
      return undef;
    }
  }

  dbg("dns: A records for '$name': ".join (' ', @addrs));
  return @addrs;
}

sub is_dns_available {
  my ($self) = @_;
  my $dnsopt = $self->{conf}->{dns_available};
  my $dnsint = $self->{conf}->{dns_test_interval} || 600;
  my @domains;

  $LAST_DNS_CHECK ||= 0;
  my $diff = time() - $LAST_DNS_CHECK;

  # undef $IS_DNS_AVAILABLE if we should be testing for
  # working DNS and our check interval time has passed
  if ($dnsopt eq "test" && $diff > $dnsint) {
    $IS_DNS_AVAILABLE = undef;
    dbg("dns: is_dns_available() last checked $diff seconds ago; re-checking");
  }

  return $IS_DNS_AVAILABLE if (defined $IS_DNS_AVAILABLE);
  $LAST_DNS_CHECK = time();

  $IS_DNS_AVAILABLE = 0;
  if ($dnsopt eq "no") {
    dbg("dns: dns_available set to no in config file, skipping test");
    return $IS_DNS_AVAILABLE;
  }

  # Even if "dns_available" is explicitly set to "yes", we want to ignore
  # DNS if we're only supposed to be looking at local tests.
  goto done if ($self->{main}->{local_tests_only});

  if ($dnsopt eq "yes") {
    $IS_DNS_AVAILABLE = 1;
    dbg("dns: dns_available set to yes in config file, skipping test");
    return $IS_DNS_AVAILABLE;
  }

  # Check version numbers - runtime check only
  if (defined $Net::DNS::VERSION) {
    if (Mail::SpamAssassin::Util::am_running_on_windows()) {
      if ($Net::DNS::VERSION < 0.46) {
	warn("dns: Net::DNS version is $Net::DNS::VERSION, but need 0.46 for Win32");
	return $IS_DNS_AVAILABLE;
      }
    }
    else {
      if ($Net::DNS::VERSION < 0.34) {
	warn("dns: Net::DNS version is $Net::DNS::VERSION, but need 0.34");
	return $IS_DNS_AVAILABLE;
      }
    }
  }

  goto done unless $self->load_resolver();

  if ($dnsopt =~ /test:\s+(.+)$/) {
    my $servers=$1;
    dbg("dns: servers: $servers");
    @domains = split (/\s+/, $servers);
    dbg("dns: looking up NS records for user specified servers: ".join(", ", @domains));
  } else {
    @domains = @EXISTING_DOMAINS;
  }

  # TODO: retry every now and again if we get this far, but the
  # next test fails?  could be because the ethernet cable has
  # simply fallen out ;)

  # Net::DNS::Resolver scans a list of nameservers when it does a foreground query
  # but only uses the first in a background query like we use.
  # Try the different nameservers here in case the first one is not woorking
  
  my @nameservers = $self->{resolver}->nameservers();
  dbg("dns: testing resolver nameservers: ".join(", ", @nameservers));
  my $ns;
  while( $ns  = shift(@nameservers)) {
    for(my $retry = 3; $retry > 0 and $#domains>-1; $retry--) {
      my $domain = splice(@domains, rand(@domains), 1);
      dbg("dns: trying ($retry) $domain...");
      my $result = $self->lookup_ns($domain);
      if(defined $result) {
        if (scalar @$result > 0) {
          dbg("dns: NS lookup of $domain using $ns succeeded => DNS available (set dns_available to override)");
          $IS_DNS_AVAILABLE = 1;
          last;
        }
        else {
          dbg("dns: NS lookup of $domain using $ns failed, no results found");
          next;
        }
      }
      else {
        dbg("dns: NS lookup of $domain using $ns failed horribly, may not be a valid nameserver");
        $IS_DNS_AVAILABLE = 0; # should already be 0, but let's be sure.
        last; 
      }
    }
    last if $IS_DNS_AVAILABLE;
    dbg("dns: NS lookups failed, removing nameserver $ns from list");
    $self->{resolver}->nameservers(@nameservers);
    $self->{resolver}->connect_sock(); # reconnect socket to new nameserver
  }

  dbg("dns: all NS queries failed => DNS unavailable (set dns_available to override)") if ($IS_DNS_AVAILABLE == 0);

done:
  # jm: leaving this in!
  dbg("dns: is DNS available? $IS_DNS_AVAILABLE");
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

  dbg("info: entering helper-app run mode");
  $self->{old_slash} = $/;              # Razor pollutes this
  %{$self->{old_env}} = ();
  if ( defined %ENV ) {
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

  dbg("info: leaving helper-app run mode");
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

sub register_async_rule_start {
  my ($self, $rule) = @_;
  dbg ("dns: $rule lookup start");
  $self->{rule_to_rblkey}->{$rule} = '*ASYNC_START';
}

sub register_async_rule_finish {
  my ($self, $rule) = @_;
  dbg ("dns: $rule lookup finished");
  delete $self->{rule_to_rblkey}->{$rule};
}

sub mark_all_async_rules_complete {
  my ($self) = @_;
  $self->{rule_to_rblkey} = { };
}

sub is_rule_complete {
  my ($self, $rule) = @_;

  my $key = $self->{rule_to_rblkey}->{$rule};
  if (!defined $key) {
    # dbg("dns: $rule lookup complete, not in list");
    return 1;
  }

  if ($key eq '*ASYNC_START') {
    dbg("dns: $rule lookup not yet complete");
    return 0;       # not yet complete
  }

  my $obj = $self->{async}->get_lookup($key);
  if (!defined $obj) {
    dbg("dns: $rule lookup complete, $key no longer pending");
    return 1;
  }

  dbg("dns: $rule lookup not yet complete");
  return 0;         # not yet complete
}

###########################################################################

# interface called by SPF plugin
sub check_for_from_dns {
  my ($self, $pms) = @_;
  if (defined $pms->{sender_host_fail}) {
    return ($pms->{sender_host_fail} == 2); # both MX and A need to fail
  }
}

1;
