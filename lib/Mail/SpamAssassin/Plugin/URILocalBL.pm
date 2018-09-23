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
host you wish to exempt from that blacklist, you can use:

  uri_block_exclude TEST1 www.baidu.com

if you wish to exempt URL's referring to this host. The same syntax is
applicable to CIDR and ISP blocks as well.

=head1 DEPENDENCIES

The Country-Code based filtering can use any Mail::SpamAssassin::GeoDB
supported module like GeoIP2::Database::Reader or Geo::IP.  ISP based
filtering might require a paid subscription database like GeoIPISP.

=cut

package Mail::SpamAssassin::Plugin::URILocalBL;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Constants qw(:ip);
use Mail::SpamAssassin::Util qw(untaint_var);
use Mail::SpamAssassin::GeoDB;
use Mail::SpamAssassin::NetSet;

use Socket;
use Data::Dumper;

use strict;
use warnings;
# use bytes;
use re 'taint';
use version;

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg { Mail::SpamAssassin::Plugin::dbg ("URILocalBL: @_"); }

my $IP_ADDRESS = IP_ADDRESS;

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

      if ($value !~ /^(\S+)\s+(.+?)\s*$/) {
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
    }
  });

  push (@cmds, {
    setting => 'uri_block_cont',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      if ($value !~ /^(\S+)\s+(.+?)\s*$/) {
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
    }
  });
  
  push (@cmds, {
    setting => 'uri_block_isp',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      if ($value !~ /^(\S+)\s+(.+?)\s*$/) {
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
    }
  });

  push (@cmds, {
    setting => 'uri_block_cidr',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      if ($value !~ /^(\S+)\s+(.+?)\s*$/) {
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
    }
  });

  push (@cmds, {
    setting => 'uri_block_exclude',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      if ($value !~ /^(\S+)\s+(.+?)\s*$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $name = $1;
      my $args = $2;

      foreach my $arg (split(/\s+/, $args)) {
        $self->{urilocalbl}->{$name}{exclusions}{lc($arg)} = 1;
      }

      $self->{parser}->add_test($name, 'check_uri_local_bl()',
        $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
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

  my $rulename = $pms->get_current_eval_rule_name();
  my $ruleconf = $pms->{conf}->{urilocalbl}->{$rulename};

  dbg("running $rulename");

  my @addrs;

  foreach my $info (values %{$pms->get_uri_detail_list()}) {
    next unless $info->{hosts};

    # look for W3 links only
    next unless defined $info->{types}->{a};

    my %hosts = %{$info->{hosts}}; # evade hash reset by copy
    HOST: while (my($host, $domain) = each %hosts) {
      if (defined $ruleconf->{exclusions}{lc($domain)}) {
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
        if (defined $ruleconf->{exclusions}{$ip}) {
          dbg("excluded $host, IP $ip matches");
          next HOST;
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
        foreach my $ip (@addrs) {
          my $cc = $geodb->get_country($ip);
          if ( (!$neg && defined $ruleconf->{countries}{$cc}) ||
               ($neg && !defined $ruleconf->{countries}{$cc}) ) {
            dbg("$host ($ip) country $cc - HIT");
            $pms->test_log("Host: $host in country $cc");
            return 1; # hit
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
        foreach my $ip (@addrs) {
          my $cc = $geodb->get_continent($ip);
          if ( (!$neg && defined $ruleconf->{continents}{$cc}) ||
               ($neg && !defined $ruleconf->{continents}{$cc}) ) {
            dbg("$host ($ip) continent $cc - HIT");
            $pms->test_log("Host: $host in continent $cc");
            return 1; # hit
          } else {
            dbg("$host ($ip) continent $cc - ".($neg ? "excluded" : "no match"));
          }
        }
      }

      if (defined $ruleconf->{isps}) {
        if ($geodb->can('isp')) {
          my $testisp = join(', ', map {"\"$_\""} sort values %{$ruleconf->{isps}});
          dbg("checking $host for isps: $testisp");

          foreach my $ip (@addrs) {
            my $isp = $geodb->get_isp($ip);
            next unless defined $isp;
            my $ispkey = uc($isp); $ispkey =~ s/\s+//gs;
            if (defined $ruleconf->{isps}{$ispkey}) {
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

      if (defined $ruleconf->{netset}) {
        foreach my $ip (@addrs) {
          if ($ruleconf->{netset}->contains_ip($ip)) {
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
