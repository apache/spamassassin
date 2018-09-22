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

URILocalBL - blacklist URIs using local information (ISP names, address lists, and country codes)

=head1 SYNOPSIS

This plugin creates some new rule test types, such as "uri_block_cc",
"uri_block_cidr", and "uri_block_isp".  These rules apply to the URIs
found in the HTML portion of a message, i.e. <a href=...> markup.

  loadplugin    Mail::SpamAssassin::Plugin::URILocalBL

Why local blacklisting? There are a few excellent, effective, and
well-maintained DNSBL's out there. But they have several drawbacks:

=over 2

=item * blacklists can cover tens of thousands of entries, and you can't select which ones you use;

=item * verifying that it's correctly configured can be non-trivial;

=item * new blacklisting entries may take a while to be detected and entered, so it's not instantaneous.

=back

Sometimes all you want is a quick, easy, and very surgical blacklisting of
a particular site or a particular ISP. This plugin is defined for that
exact usage case.

=head1 RULE DEFINITIONS AND PRIVILEGED SETTINGS

The format for defining a rule is as follows:

  uri_block_cc SYMBOLIC_TEST_NAME cc1 cc2 cc3 cc4

or:

  uri_block_cont SYMBOLIC_TEST_NAME co1 co2 co3 co4

or:

  uri_block_cidr SYMBOLIC_TEST_NAME a.a.a.a b.b.b.b/cc d.d.d.d-e.e.e.e

or:

  uri_block_isp SYMBOLIC_TEST_NAME "DataRancid" "McCarrier" "Phishers-r-Us"

Example rule for matching a URI in China:

  uri_block_cc TEST1 cn

This would block the URL http://www.baidu.com/index.htm.  Similarly, to
match a Spam-haven netblock:

  uri_block_cidr TEST2 65.181.64.0/18

would match a netblock where several phishing sites were recently hosted.

And to block all CIDR blocks registered to an ISP, one might use:

  uri_block_isp TEST3 "ColoCrossing"

if one didn't trust URL's pointing to that organization's clients.  Lastly,
if there's a country that you want to block but there's an explicit host
you wish to exempt from that blacklist, you can use:

  uri_block_exclude TEST1 www.baidu.com

if you wish to exempt URL's referring to this host. The same syntax is
applicable to CIDR and ISP blocks as well.

=head1 DEPENDENCIES

The Country-Code based filtering requires the Geo::IP or GeoIP2 module, 
which uses either the fremium GeoLiteCountry database, or the commercial 
version of it called GeoIP from MaxMind.com.

The ISP based filtering requires the same module, plus the GeoIPISP database.
There is no fremium version of this database, so commercial licensing is
required.

=cut

package Mail::SpamAssassin::Plugin::URILocalBL;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Constants qw(:ip);
use Mail::SpamAssassin::Util qw(untaint_var);
use Mail::SpamAssassin::GeoDB;

use Net::CIDR::Lite; #TODO: use SA internal NetSet or such
use Socket;
use Data::Dumper;

use strict;
use warnings;
# use bytes;
use re 'taint';
use version;

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg { Mail::SpamAssassin::Plugin::dbg ("URILocalBL: @_"); }

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

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

  push (@cmds, {
    setting => 'uri_block_cc',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      if ($value !~ /^(\S+)\s+(.+)$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $name = $1;
      my $def = $2;
      my $added_criteria = 0;

      $conf->{parser}->{conf}->{urilocalbl}->{$name}->{countries} = {};

      # this should match all country codes including satellite providers
      while ($def =~ m/^\s*([a-z][a-z0-9])(\s+(.*)|)$/) {
        my $cc = $1;
        my $rest = $2;

        #dbg("config: uri_block_cc adding $cc to $name");
        $conf->{parser}->{conf}->{urilocalbl}->{$name}->{countries}->{uc($cc)} = 1;
        $added_criteria = 1;

        $def = $rest;
      }

      if ($added_criteria == 0) {
        warn "config: no arguments";
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      } elsif ($def ne '') {
        warn "config: failed to add invalid rule $name";
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      dbg("config: uri_block_cc added $name");

      $conf->{parser}->add_test($name, 'check_uri_local_bl()', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
    }
  });

  push (@cmds, {
    setting => 'uri_block_cont',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      if ($value !~ /^(\S+)\s+(.+)$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $name = $1;
      my $def = $2;
      my $added_criteria = 0;

      $conf->{parser}->{conf}->{urilocalbl}->{$name}->{continents} = {};

      # this should match all continent codes
      while ($def =~ m/^\s*([a-z]{2})(\s+(.*)|)$/) {
        my $cont = $1;
        my $rest = $2;

        # dbg("config: uri_block_cont adding $cont to $name");
        $conf->{parser}->{conf}->{urilocalbl}->{$name}->{continents}->{uc($cont)} = 1;
        $added_criteria = 1;

        $def = $rest;
      }

      if ($added_criteria == 0) {
        warn "config: no arguments";
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      } elsif ($def ne '') {
        warn "config: failed to add invalid rule $name";
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      dbg("config: uri_block_cont added $name");

      $conf->{parser}->add_test($name, 'check_uri_local_bl()', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
    }
  });
  
  push (@cmds, {
    setting => 'uri_block_isp',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      if ($value !~ /^(\S+)\s+(.+)$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $name = $1;
      my $def = $2;
      my $added_criteria = 0;

      $conf->{parser}->{conf}->{urilocalbl}->{$name}->{isps} = {};

      # gather up quoted strings
      while ($def =~ m/^\s*"([^"]*)"(\s+(.*)|)$/) {
        my $isp = $1;
        my $rest = $2;

        dbg("config: uri_block_isp adding \"$isp\" to $name");
        my $ispkey = uc($isp); $ispkey =~ s/\s+//gs;
        $conf->{parser}->{conf}->{urilocalbl}->{$name}->{isps}->{$ispkey} = $isp;
        $added_criteria = 1;

        $def = $rest;
      }

      if ($added_criteria == 0) {
        warn "config: no arguments";
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      } elsif ($def ne '') {
        warn "config: failed to add invalid rule $name";
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      $conf->{parser}->add_test($name, 'check_uri_local_bl()', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
    }
  });

  push (@cmds, {
    setting => 'uri_block_cidr',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      if ($value !~ /^(\S+)\s+(.+)$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $name = $1;
      my $def = $2;
      my $added_criteria = 0;

      $conf->{parser}->{conf}->{urilocalbl}->{$name}->{cidr} = new Net::CIDR::Lite;

      # match individual IP's, subnets, and ranges
      while ($def =~ m/^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2}|-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?)(\s+(.*)|)$/) {
        my $addr = $1;
        my $rest = $3;

        dbg("config: uri_block_cidr adding $addr to $name");

        eval { $conf->{parser}->{conf}->{urilocalbl}->{$name}->{cidr}->add_any($addr) };
        last if ($@);

        $added_criteria = 1;

        $def = $rest;
      }

      if ($added_criteria == 0) {
        warn "config: no arguments";
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      } elsif ($def ne '') {
        warn "config: failed to add invalid rule $name";
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      # optimize the ranges
      $conf->{parser}->{conf}->{urilocalbl}->{$name}->{cidr}->clean();

      $conf->{parser}->add_test($name, 'check_uri_local_bl()', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
    }
  });

  push (@cmds, {
    setting => 'uri_block_exclude',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      if ($value !~ /^(\S+)\s+(.+)$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $name = $1;
      my $def = $2;
      my $added_criteria = 0;

      $conf->{parser}->{conf}->{urilocalbl}->{$name}->{exclusions} = {};

      # match individual IP's, or domain names
      while ($def =~ m/^\s*((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(([a-z0-9][-a-z0-9]*[a-z0-9](\.[a-z0-9][-a-z0-9]*[a-z0-9]){1,})))(\s+(.*)|)$/) {
        my $addr = $1;
        my $rest = $6;

        dbg("config: uri_block_exclude adding $addr to $name");

        $conf->{parser}->{conf}->{urilocalbl}->{$name}->{exclusions}->{$addr} = 1;

        $added_criteria = 1;

        $def = $rest;
      }

      if ($added_criteria == 0) {
        warn "config: no arguments";
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      } elsif ($def ne '') {
        warn "config: failed to add invalid rule $name";
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      $conf->{parser}->add_test($name, 'check_uri_local_bl()', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub check_uri_local_bl {
  my ($self, $pms) = @_;

  return 0 if $self->{urilocalbl_disabled};

  if (!$self->{geodb}) {
    eval {
      $self->{geodb} = Mail::SpamAssassin::GeoDB->new({
        conf => $pms->{conf}->{geodb},
        wanted => { country => 1, city => 1, isp => 1 },
      });
    };
    if (!$self->{geodb}) {
      dbg("plugin disabled: $@");
      $self->{urilocalbl_disabled} = 1;
      return 0;
    }
  }
  my $geodb = $self->{geodb};

  my $test = $pms->get_current_eval_rule_name();
  my $rule = $pms->{conf}->{urilocalbl}->{$test};

  dbg("running $test");

  my @addrs;
  my $IP_ADDRESS = IP_ADDRESS;

  foreach my $info (values %{$pms->get_uri_detail_list()}) {
    next unless $info->{hosts};

    # look for W3 links only
    next unless defined $info->{types}->{a};

    my %hosts = %{$info->{hosts}}; # evade hash reset by copy
    HOST: while (my($host, $domain) = each %hosts) {
      if (defined $rule->{exclusions}->{$domain}) {
        dbg("excluded $host, domain $domain matches");
        next HOST;
      }

      if ($host !~ /^$IP_ADDRESS$/o) {
        # this would be best cached from prior lookups
        # TODO async extract_metadata lookup
        @addrs = gethostbyname($host);
        # convert to string values address list
        @addrs = map { inet_ntoa($_); } @addrs[4..$#addrs];
        if (@addrs) {
          dbg("$host IP-addresses: ".join(', ', @addrs));
        } else {
          dbg("$host failed to resolve IP-addresses");
        }
      } else {
        @addrs = ($host);
      }

      next HOST unless @addrs;

      foreach my $ip (@addrs) {
        if (defined $rule->{exclusions}->{$ip}) {
          dbg("excluded $host, ip $ip matches");
          next HOST;
        }
      }

      if (defined $rule->{countries}) {
        my $testcc = join(',', sort keys %{$rule->{countries}});
        dbg("checking $host for countries: $testcc");
        foreach my $ip (@addrs) {
          my $cc = $geodb->get_country($ip);
          if (defined $rule->{countries}->{$cc}) {
            dbg("$host ($ip) country $cc - HIT");
            $pms->test_log("Host: $host in country $cc");
            return 1; # hit
          } else {
            dbg("$host ($ip) country $cc - no match");
          }
        }
      }

      if (defined $rule->{continents}) {
        my $testcont = join(',', sort keys %{$rule->{continents}});
        dbg("checking $host for continents: $testcont");
        foreach my $ip (@addrs) {
          my $cc = $geodb->get_continent($ip);
          if (defined $rule->{continents}->{$cc}) {
            dbg("$host ($ip) continent $cc - HIT");
            $pms->test_log("Host: $host in continent $cc");
            return 1; # hit
          } else {
            dbg("$host ($ip) continent $cc - no match");
          }
        }
      }

      if (defined $rule->{isps}) {
        if ($geodb->can('isp')) {
          my $testisp = join(', ', map {"\"$_\""} sort values %{$rule->{isps}});
          dbg("checking $host for isps: $testisp");

          foreach my $ip (@addrs) {
            my $isp = $geodb->get_isp($ip);
            next unless defined $isp;
            my $ispkey = uc($isp); $ispkey =~ s/\s+//gs;
            if (defined $rule->{isps}->{$ispkey}) {
              dbg("$host ($ip) isp \"$isp\" - HIT");
              $pms->test_log("Host: $host in isp $isp");
              return 1; # hit
            } else {
              dbg("$host ($ip) isp $isp - no match");
            }
          }
        } else {
          dbg("skipping ISP check, GeoDB database not loaded");
        }
      }

      if (defined $rule->{cidr}) {
        my $testcidr = join(' ', $rule->{cidr}->list_range());
        dbg("checking $host for cidrs: $testcidr");

        foreach my $ip (@addrs) {
          if ($rule->{cidr}->find($ip)) {
            dbg("$host ($ip) matches cidr - HIT");
            $pms->test_log("Host: $host in cidr");
            return 1; # hit
          } else {
            dbg("$host ($ip) not matching cidr");
          }
        }
      }
    }
  }

  return 0;
}

1;
