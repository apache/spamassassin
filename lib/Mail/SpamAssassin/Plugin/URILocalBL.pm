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

=head1 NAME

URILocalBL - blocklist URIs using local information (ISP names, address lists, and country codes)

=head1 SYNOPSIS

This plugin creates some new rule test types, such as "uri_block_cc",
"uri_block_cidr", and "uri_block_isp".  These rules apply to the URIs
found in the HTML portion of a message, i.e. E<lt>a href=...E<gt> markup.

  loadplugin    Mail::SpamAssassin::Plugin::URILocalBL

Why local blocklisting? There are a few excellent, effective, and
well-maintained DNSBL's out there. But they have several drawbacks:

=over 2

=item * blocklists can cover tens of thousands of entries, and you can't select which ones you use;

=item * verifying that it's correctly configured can be non-trivial;

=item * new blocklisting entries may take a while to be detected and entered, so it's not instantaneous.

=back

Sometimes all you want is a quick, easy, and very surgical blocklisting of
a particular site or a particular ISP. This plugin is defined for that
exact usage case.

=head1 RULE DEFINITIONS AND PRIVILEGED SETTINGS

The format for defining a rule is as follows:

  uri_block_cc SYMBOLIC_TEST_NAME cc1 cc2 cc3 cc4 ..
  uri_block_cc SYMBOLIC_TEST_NAME !cc1 !cc2 ..

or:

  uri_block_cont SYMBOLIC_TEST_NAME co1 co2 co3 co4 ..
  uri_block_cont SYMBOLIC_TEST_NAME !co1 !co2 ..

or:

  uri_block_cidr SYMBOLIC_TEST_NAME a.a.a.a b.b.b.b/cc

or:

  uri_block_isp SYMBOLIC_TEST_NAME "Data Rancid" McCarrier Phishers-r-Us

Example rule for matching a URI in China:

  uri_block_cc TEST1 cn

If you specify list of negations, such rule will match ANY country except
the listed ones (Finland, Sweden):

  uri_block_cc TEST1 !fi !se

Continents uri_block_cont works exactly the same as uri_block_cc.

This would block the URL http://www.baidu.com/index.htm.  Similarly, to
match a Spam-haven netblock:

  uri_block_cidr TEST2 65.181.64.0/18

would match a netblock where several phishing sites were recently hosted.

And to block all CIDR blocks registered to an ISP, one might use:

  uri_block_isp TEST3 "Data Rancid" ColoCrossing

Quote ISP names containing spaces.

Lastly, if there's a country that you want to block but there's an explicit
host you wish to exempt from that blocklist, you can use:

  uri_block_exclude TEST1 www.baidu.com

if you wish to exempt URL's referring to this host. The same syntax is
applicable to CIDR and ISP blocks as well.

=head1 DEPENDENCIES

The Country-Code based filtering can use any Mail::SpamAssassin::GeoDB
supported module like MaxMind::DB::Reader (GeoIP2) or Geo::IP.  ISP based
filtering might require a paid subscription database like GeoIPISP.

=cut

package Mail::SpamAssassin::Plugin::URILocalBL;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Constants qw(:ip :sa);
use Mail::SpamAssassin::Util qw(untaint_var idn_to_ascii);
use Mail::SpamAssassin::NetSet;

use Socket;

use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg { my $msg = shift; Mail::SpamAssassin::Plugin::dbg ("URILocalBL: $msg", @_); }

my $IP_ADDRESS = IP_ADDRESS;
my $RULENAME_RE = RULENAME_RE;

# constructor
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule("check_uri_local_bl");
  $self->set_config($mailsaobject->{conf});

  # we need GeoDB country/isp
  $self->{main}->{geodb_wanted}->{country} = 1;
  $self->{main}->{geodb_wanted}->{isp} = 1;

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

  push (@cmds, {
    setting => 'uri_block_cc',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      if ($value !~ /^(${RULENAME_RE})\s+(.+?)\s*$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $name = $1;
      my $args = $2;
      my @added;

      foreach my $cc (split(/\s+/, uc($args))) {
        # this should match all country codes including satellite providers
        if ($cc =~ /^((\!)?([a-z][a-z0-9]))$/i) {
          if (defined $2) {
            $self->{urilocalbl}->{$name}{countries_neg} = 1;
            $self->{urilocalbl}->{$name}{countries}{$3} = 0;
          } else {
            $self->{urilocalbl}->{$name}{countries}{$3} = 1;
          }
          push @added, $1;
        } else {
          return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }
      }

      my %checkneg = map { $_ => 1 } values %{$self->{urilocalbl}->{$name}{countries}};
      if (scalar keys %checkneg > 1) {
        dbg("config: uri_block_cc $name failed: trying to combine negations and non-negations");
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      dbg("config: uri_block_cc $name added: ".join(' ', @added));
      $self->{parser}->add_test($name, 'check_uri_local_bl()',
        $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
      $self->{parser}->{conf}->{priority}->{$name} = -100;
    }
  });

  push (@cmds, {
    setting => 'uri_block_cont',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      if ($value !~ /^(${RULENAME_RE})\s+(.+?)\s*$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $name = $1;
      my $args = $2;
      my @added;

      foreach my $cc (split(/\s+/, uc($args))) {
        # this should match all continent codes
        if ($cc =~ /^((\!)?([a-z]{2}))$/i) {
          if (defined $2) {
            $self->{urilocalbl}->{$name}{continents_neg} = 1;
            $self->{urilocalbl}->{$name}{continents}{$3} = 0;
          } else {
            $self->{urilocalbl}->{$name}{continents}{$3} = 1;
          }
          push @added, $1;
        } else {
          return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }
      }

      my %checkneg = map { $_ => 1 } values %{$self->{urilocalbl}->{$name}{continents}};
      if (scalar keys %checkneg > 1) {
        dbg("config: uri_block_cont $name failed: trying to combine negations and non-negations");
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      dbg("config: uri_block_cont $name added: ".join(' ', @added));
      $self->{parser}->add_test($name, 'check_uri_local_bl()',
        $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
      $self->{parser}->{conf}->{priority}->{$name} = -100;
    }
  });
  
  push (@cmds, {
    setting => 'uri_block_isp',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      if ($value !~ /^(${RULENAME_RE})\s+(.+?)\s*$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $name = $1;
      my $args = $2;
      my @added;

      # gather up possibly quoted strings
      while ($args =~ /("[^"]*"|(?<!")\S+(?!"))/g) {
        my $isp = $1;
        $isp =~ s/"//g;
        my $ispkey = uc($isp); $ispkey =~ s/\s+//gs;
        $self->{urilocalbl}->{$name}{isps}{$ispkey} = $isp;
        push @added, "\"$isp\"";
      }

      if (!defined $self->{urilocalbl}->{$name}{isps}) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      dbg("config: uri_block_isp $name added: ". join(', ', @added));
      $self->{parser}->add_test($name, 'check_uri_local_bl()',
        $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
      $self->{parser}->{conf}->{priority}->{$name} = -100;
    }
  });

  push (@cmds, {
    setting => 'uri_block_cidr',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      if ($value !~ /^(${RULENAME_RE})\s+(.+?)\s*$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $name = $1;
      my $args = $2;

      foreach my $addr (split(/\s+/, $args)) {
        if ($addr =~ m!^$IP_ADDRESS(?:/\d{1,3})?$!o) {
          $self->{urilocalbl}->{$name}{cidr}{$addr} = 1;
        } else {
          return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }
      }

      $self->{parser}->add_test($name, 'check_uri_local_bl()',
        $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
      $self->{parser}->{conf}->{priority}->{$name} = -100;
    }
  });

  push (@cmds, {
    setting => 'uri_block_exclude',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      if ($value !~ /^(${RULENAME_RE})\s+(.+?)\s*$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $name = $1;
      my $args = $2;

      foreach my $arg (split(/\s+/, $args)) {
        $self->{urilocalbl}->{$name}{exclusions}{lc($arg)} = 1;
      }

      $self->{parser}->add_test($name, 'check_uri_local_bl()',
        $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
      $self->{parser}->{conf}->{priority}->{$name} = -100;
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub finish_parsing_end {
  my ($self, $opts) = @_;

  my $conf = $opts->{conf};

  # compile cidrs now
  foreach my $rulename (keys %{$conf->{urilocalbl}}) {
    my $ruleconf = $conf->{urilocalbl}->{$rulename};
    next if defined $ruleconf->{netset};
    next if !defined $ruleconf->{cidr};
    my $netset = Mail::SpamAssassin::NetSet->new($rulename);
    foreach my $addr (keys %{$ruleconf->{cidr}}) {
      if ($netset->add_cidr($addr)) {
        dbg("config: uri_block_cidr $rulename added: $addr");
      } else {
        dbg("config: uri_block_cidr $rulename add failed: $addr");
      }
    }
    if ($netset->get_num_nets()) {
      $ruleconf->{netset} = $netset;
    }
  }
}

sub check_uri_local_bl {
  my ($self, $pms) = @_;

  return 0 if $self->{urilocalbl_disabled};

  if (!$self->{main}->{geodb} ||
        (!$self->{main}->{geodb}->can('country') &&
         !$self->{main}->{geodb}->can('isp'))) {
    dbg("plugin disabled, GeoDB country/isp not available");
    $self->{urilocalbl_disabled} = 1;
    return 0;
  }

  my $rulename = $pms->get_current_eval_rule_name();
  my $ruleconf = $pms->{conf}->{urilocalbl}->{$rulename};

  dbg("running $rulename");

  my %found_hosts;

  foreach my $info (values %{$pms->get_uri_detail_list()}) {
    next unless $info->{hosts};

    # look for W3 links only
    next unless defined $info->{types}->{a} || defined $info->{types}->{parsed};

    my %hosts = %{$info->{hosts}}; # evade hash reset by copy
    while (my($host, $domain) = each %hosts) {
      if (defined $ruleconf->{exclusions}{lc($domain)}) {
        dbg("excluded $host, domain $domain matches");
        next;
      }
      elsif ($host =~ IS_IP_ADDRESS) {
        if ($self->_check_host($pms, $rulename, $host, [$host])) {
          # if hit, rule is done
          return 0;
        }
      } else {
        # do host lookups only after all IPs are checked, since they
        # don't need resolving..
        $found_hosts{$host} = 1;
      }
    }
  }

  return 0 unless %found_hosts;

  # bail out now if dns not available
  return 0 if !$pms->is_dns_available();

  my $queries;
  foreach my $host (keys %found_hosts) {
    $host = idn_to_ascii($host);
    dbg("launching A/AAAA lookup for $host");
    # launch dns
    my $ret = $pms->{async}->bgsend_and_start_lookup($host, 'A', undef,
      { rulename => $rulename, host => $host, type => 'URILocalBL' },
      sub { my($ent, $pkt) = @_; $self->_finish_lookup($pms, $ent, $pkt); },
      master_deadline => $pms->{master_deadline}
    );
    $queries++ if defined $ret;
    # also IPv6 if database supports
    if ($self->{main}->{geodb}->can('country_v6')) {
      $ret = $pms->{async}->bgsend_and_start_lookup($host, 'AAAA', undef,
        { rulename => $rulename, host => $host, type => 'URILocalBL' },
        sub { my($ent, $pkt) = @_; $self->_finish_lookup($pms, $ent, $pkt); },
        master_deadline => $pms->{master_deadline}
      );
      $queries++ if defined $ret;
    }
  }

  return 0 if !$queries; # no query started
  return; # return undef for async status
}

sub _finish_lookup {
  my ($self, $pms, $ent, $pkt) = @_;

  my $rulename = $ent->{rulename};
  my $host = $ent->{host};

  # Skip duplicate A / AAAA matches
  return if $pms->{urilocalbl_finished}->{$rulename};

  if (!$pkt) {
      # $pkt will be undef if the DNS query was aborted (e.g. timed out)
      dbg("host lookup failed: $rulename $host");
      return;
  }

  $pms->rule_ready($rulename); # mark rule ready for metas

  my @answer = $pkt->answer;
  my @addrs;
  foreach my $rr (@answer) {
    if ($rr->type eq 'A' || $rr->type eq 'AAAA') {
      push @addrs, $rr->address;
    }
  }

  if (@addrs) {
    if ($self->_check_host($pms, $rulename, $host, \@addrs)) {
      $pms->{urilocalbl_finished}->{$rulename} = 1;
    }
  }
}

sub _check_host {
  my ($self, $pms, $rulename, $host, $addrs) = @_;

  my $ruleconf = $pms->{conf}->{urilocalbl}->{$rulename};
  my $geodb = $self->{main}->{geodb};

  if ($host ne $addrs->[0]) {
    dbg("resolved $host: ".join(', ', @$addrs));
  }

  foreach my $ip (@$addrs) {
    if (defined $ruleconf->{exclusions}{$ip}) {
      dbg("excluded $host, IP $ip matches");
      return 1;
    }
  }

  if (defined $ruleconf->{countries}) {
    my $neg = defined $ruleconf->{countries_neg};
    my $testcc = join(' ', sort keys %{$ruleconf->{countries}});
    if ($neg) {
      dbg("checking $host for any country except: $testcc");
    } else {
      dbg("checking $host for countries: $testcc");
    }
    foreach my $ip (@$addrs) {
      my $cc = $geodb->get_country($ip);
      if ( (!$neg && defined $ruleconf->{countries}{$cc}) ||
           ($neg && !defined $ruleconf->{countries}{$cc}) ) {
        dbg("$host ($ip) country $cc - HIT");
        $pms->test_log("Host: $host in country $cc", $rulename);
        $pms->got_hit($rulename, "");
        return 1;
      } else {
        dbg("$host ($ip) country $cc - ".($neg ? "excluded" : "no match"));
      }
    }
  }

  if (defined $ruleconf->{continents}) {
    my $neg = defined $ruleconf->{continents_neg};
    my $testcont = join(' ', sort keys %{$ruleconf->{continents}});
    if ($neg) {
      dbg("checking $host for any continent except: $testcont");
    } else {
      dbg("checking $host for continents: $testcont");
    }
    foreach my $ip (@$addrs) {
      my $cc = $geodb->get_continent($ip);
      if ( (!$neg && defined $ruleconf->{continents}{$cc}) ||
           ($neg && !defined $ruleconf->{continents}{$cc}) ) {
        dbg("$host ($ip) continent $cc - HIT");
        $pms->test_log("Host: $host in continent $cc", $rulename);
        $pms->got_hit($rulename, "");
        return 1;
      } else {
        dbg("$host ($ip) continent $cc - ".($neg ? "excluded" : "no match"));
      }
    }
  }

  if (defined $ruleconf->{isps}) {
    if ($geodb->can('isp')) {
      my $testisp = join(', ', map {"\"$_\""} sort values %{$ruleconf->{isps}});
      dbg("checking $host for isps: $testisp");

      foreach my $ip (@$addrs) {
        my $isp = $geodb->get_isp($ip);
        next unless defined $isp;
        my $ispkey = uc($isp); $ispkey =~ s/\s+//gs;
        if (defined $ruleconf->{isps}{$ispkey}) {
          dbg("$host ($ip) isp \"$isp\" - HIT");
          $pms->test_log("Host: $host in isp $isp", $rulename);
          $pms->got_hit($rulename, "");
          return 1;
        } else {
          dbg("$host ($ip) isp $isp - no match");
        }
      }
    } else {
      dbg("skipping ISP check, GeoDB database not loaded");
    }
  }

  if (defined $ruleconf->{netset}) {
    foreach my $ip (@$addrs) {
      if ($ruleconf->{netset}->contains_ip($ip)) {
        dbg("$host ($ip) matches cidr - HIT");
        $pms->test_log("Host: $host in cidr", $rulename);
        $pms->got_hit($rulename, "");
        return 1;
      } else {
        dbg("$host ($ip) not matching cidr");
      }
    }
  }

  return 0;
}

1;
