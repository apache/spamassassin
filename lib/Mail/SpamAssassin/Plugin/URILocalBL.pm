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


# TODO: where are the tests?

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

The Country-Code based filtering requires the Geo::IP module, which uses
either the fremium GeoLiteCountry database, or the commercial version of it
called GeoIP from MaxMind.com.

The ISP based filtering requires the same module, plus the GeoIPISP database.
There is no fremium version of this database, so commercial licensing is
required.

=cut

package Mail::SpamAssassin::Plugin::URILocalBL;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(untaint_var);

use Geo::IP;
use Net::CIDR::Lite;
use Socket;

use strict;
use warnings;
use bytes;
use re 'taint';
use version;

# need GeoIP C library 1.6.3 and GeoIP perl API 1.4.4 or later to avoid messages leaking - Bug 7153
my $gic_wanted = version->parse('v1.6.3');
my $gic_have = version->parse(Geo::IP->lib_version());
my $gip_wanted = version->parse('v1.4.4');
my $gip_have = version->parse($Geo::IP::VERSION);

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # how to handle failure to get the database handle?
  # and we don't really have a valid return value...
  # can we defer getting this handle until we actually see
  # a uri_block_cc rule?

  # this code burps an ugly message if it fails, but that's redirected elsewhere
  my $flags = 0;
  eval '$flags = Geo::IP::GEOIP_SILENCE' if ($gip_wanted >= $gip_have);

  if ($flags && $gic_wanted >= $gic_have) {
    $self->{geoip} = Geo::IP->new(GEOIP_MEMORY_CACHE | GEOIP_CHECK_CACHE | $flags);
    $self->{geoisp} = Geo::IP->open_type(GEOIP_ISP_EDITION, GEOIP_MEMORY_CACHE | GEOIP_CHECK_CACHE | $flags);
  } else {
    open(OLDERR, ">&STDERR");
    open(STDERR, ">", "/dev/null");
    $self->{geoip} = Geo::IP->new(GEOIP_MEMORY_CACHE | GEOIP_CHECK_CACHE);
    $self->{geoisp} = Geo::IP->open_type(GEOIP_ISP_EDITION, GEOIP_MEMORY_CACHE | GEOIP_CHECK_CACHE);
    open(STDERR, ">&OLDERR");
    close(OLDERR);
  }

  $self->register_eval_rule("check_uri_local_bl");

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

  my $pluginobj = $self;        # allow use inside the closure below

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

      $conf->{parser}->{conf}->{uri_local_bl}->{$name}->{countries} = {};

      # this should match all country codes including satellite providers
      while ($def =~ m/^\s*([a-z][a-z0-9])(\s+(.*)|)$/) {
	my $cc = $1;
	my $rest = $2;

	#dbg("config: uri_block_cc adding %s to %s\n", $cc, $name);
        $conf->{parser}->{conf}->{uri_local_bl}->{$name}->{countries}->{uc($cc)} = 1;
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

      dbg("config: uri_block_cc added %s\n", $name);

      $conf->{parser}->add_test($name, 'check_uri_local_bl()', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
    }
  }) if (defined $self->{geoip});

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

      $conf->{parser}->{conf}->{uri_local_bl}->{$name}->{isps} = {};

      # gather up quoted strings
      while ($def =~ m/^\s*"([^"]*)"(\s+(.*)|)$/) {
	my $isp = $1;
	my $rest = $2;

	dbg("config: uri_block_isp adding \"%s\" to %s\n", $isp, $name);
        $conf->{parser}->{conf}->{uri_local_bl}->{$name}->{isps}->{$isp} = 1;
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
  }) if (defined $self->{geoisp});

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

      $conf->{parser}->{conf}->{uri_local_bl}->{$name}->{cidr} = new Net::CIDR::Lite;

      # match individual IP's, subnets, and ranges
      while ($def =~ m/^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2}|-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?)(\s+(.*)|)$/) {
	my $addr = $1;
	my $rest = $3;

	dbg("config: uri_block_cidr adding %s to %s\n", $addr, $name);

        eval { $conf->{parser}->{conf}->{uri_local_bl}->{$name}->{cidr}->add_any($addr) };
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
      $conf->{parser}->{conf}->{uri_local_bl}->{$name}->{cidr}->clean();

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

      $conf->{parser}->{conf}->{uri_local_bl}->{$name}->{exclusions} = {};

      # match individual IP's, or domain names
      while ($def =~ m/^\s*((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(([a-z0-9][-a-z0-9]*[a-z0-9](\.[a-z0-9][-a-z0-9]*[a-z0-9]){1,})))(\s+(.*)|)$/) {
	my $addr = $1;
	my $rest = $6;

	dbg("config: uri_block_exclude adding %s to %s\n", $addr, $name);

        $conf->{parser}->{conf}->{uri_local_bl}->{$name}->{exclusions}->{$addr} = 1;

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
  my ($self, $permsg) = @_;

  my %uri_detail = %{ $permsg->get_uri_detail_list() };
  my $test = $permsg->{current_rule_name}; 
  my $rule = $permsg->{conf}->{uri_local_bl}->{$test};

  dbg("check: uri_local_bl evaluating rule %s\n", $test);

  while (my ($raw, $info) = each %uri_detail) {

    next unless $info->{hosts};

    # look for W3 links only
    next unless (defined $info->{types}->{a});

    while (my($host, $domain) = each $info->{hosts}) {

      # skip if the domain name was matched
      if (exists $rule->{exclusions} && exists $rule->{exclusions}->{$domain}) {
        dbg("check: uri_local_bl excludes %s as *.%s\n", $host, $domain);
        next;
      }

      # this would be best cached from prior lookups
      my @addrs = gethostbyname($host);

      # convert to string values address list
      @addrs = map { inet_ntoa($_); } @addrs[4..$#addrs];

      dbg("check: uri_local_bl %s addrs %s\n", $host, join(', ', @addrs));

      for my $ip (@addrs) {
        # skip if the address was matched
        if (exists $rule->{exclusions} && exists $rule->{exclusions}->{$ip}) {
          dbg("check: uri_local_bl excludes %s(%s)\n", $host, $ip);
          next;
        }

        if (exists $rule->{countries}) {
          dbg("check: uri_local_bl countries %s\n", join(' ', sort keys $rule->{countries}));

          my $cc = $self->{geoip}->country_code_by_addr($ip);

          dbg("check: uri_local_bl host %s(%s) maps to %s\n", $host, $ip, (defined $cc ? $cc : "(undef)"));

          # handle there being no associated country (yes, there are holes in
          # the database).
          next unless defined $cc;

          # not in blacklist
          next unless (exists $rule->{countries}->{$cc});

          dbg("check: uri_block_cc host %s(%s) matched\n", $host, $ip);

          if (would_log('dbg', 'rules') > 1) {
            dbg("check: uri_block_cc criteria for $test met");
          }
      
          $permsg->test_log("Host: $host in $cc");
          $permsg->got_hit($test);

          # reset hash
          keys %uri_detail;

          return 0;
        }

        if (exists $rule->{isps}) {
          dbg("check: uri_local_bl isps %s\n", join(' ', map { '"' . $_ . '"'; } sort keys $rule->{isps}));

          my $isp = $self->{geoisp}->isp_by_name($ip);

          dbg("check: uri_local_bl isp %s(%s) maps to %s\n", $host, $ip, (defined $isp ? '"' . $isp . '"' : "(undef)"));

          # handle there being no associated country
          next unless defined $isp;

          # not in blacklist
          next unless (exists $rule->{isps}->{$isp});

          dbg("check: uri_block_isp host %s(%s) matched\n", $host, $ip);

          if (would_log('dbg', 'rules') > 1) {
            dbg("check: uri_block_isp criteria for $test met");
          }
      
          $permsg->test_log("Host: $host in \"$isp\"");
          $permsg->got_hit($test);

          # reset hash
          keys %uri_detail;

          return 0;
        }

        if (exists $rule->{cidr}) {
          dbg("check: uri_block_cidr list %s\n", join(' ', $rule->{cidr}->list_range()));

          next unless ($rule->{cidr}->find($ip));

          dbg("check: uri_block_cidr host %s(%s) matched\n", $host, $ip);

          if (would_log('dbg', 'rules') > 1) {
            dbg("check: uri_block_cidr criteria for $test met");
          }

          $permsg->test_log("Host: $host as $ip");
          $permsg->got_hit($test);

          # reset hash
          keys %uri_detail;

          return 0;
        }
      }
    }
  }

  dbg("check: uri_local_bl %s no match\n", $test);

  return 0;
}

1;

