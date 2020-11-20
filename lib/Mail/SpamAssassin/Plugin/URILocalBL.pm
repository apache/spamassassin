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
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Constants qw(:ip);
use Mail::SpamAssassin::Util qw(untaint_var);

use Socket;

use strict;
use warnings;
# use bytes;
use re 'taint';
use version;

our @ISA = qw(Mail::SpamAssassin::Plugin);

use constant HAS_GEOIP => eval { require Geo::IP; };
use constant HAS_GEOIP2 => eval { require GeoIP2::Database::Reader; };
use constant HAS_CIDR => eval { require Net::CIDR::Lite; };

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
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
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
  });

  push (@cmds, {
    setting => 'uri_block_cont',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      if ($value !~ /^(\S+)\s+(.+)$/) {
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $name = $1;
      my $def = $2;
      my $added_criteria = 0;

      $conf->{parser}->{conf}->{uri_local_bl}->{$name}->{continents} = {};

      # this should match all continent codes
      while ($def =~ m/^\s*([a-z]{2})(\s+(.*)|)$/) {
	my $cont = $1;
	my $rest = $2;

	# dbg("config: uri_block_cont adding %s to %s\n", $cont, $name);
        $conf->{parser}->{conf}->{uri_local_bl}->{$name}->{continents}->{uc($cont)} = 1;
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

      dbg("config: uri_block_cont added %s\n", $name);

      $conf->{parser}->add_test($name, 'check_uri_local_bl()', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
    }
  });
  
  push (@cmds, {
    setting => 'uri_block_isp',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
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
  });

  push (@cmds, {
    setting => 'uri_block_cidr',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      if (!HAS_CIDR) {
        warn "config: uri_block_cidr not supported, required module Net::CIDR::Lite missing\n";
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

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
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
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

=over 2  

=item uri_country_db_path STRING

This option tells SpamAssassin where to find the MaxMind country GeoIP2 
database. Country or City database are both supported.

=back

=cut

  push (@cmds, {
    setting => 'uri_country_db_path',
    is_priv => 1,
    default => undef,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || !length $value) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      if (!-f $value) {
        info("config: uri_country_db_path \"$value\" is not accessible");
        $self->{uri_country_db_path} = $value;
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      $self->{uri_country_db_path} = $value;
    }
  });

=over 2

=item uri_country_db_isp_path STRING

This option tells SpamAssassin where to find the MaxMind isp GeoIP2 database.

=back

=cut

  push (@cmds, {
    setting => 'uri_country_db_isp_path',
    is_priv => 1,
    default => undef,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || !length $value) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      if (!-f $value) {
        info("config: uri_country_db_isp_path \"$value\" is not accessible");
        $self->{uri_country_db_isp_path} = $value;
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      $self->{uri_country_db_isp_path} = $value;
    }
  });  
 
  $conf->{parser}->register_commands(\@cmds);
}  

sub check_uri_local_bl {
  my ($self, $permsg) = @_;

  my $cc;
  my $cont;
  my $db_info;
  my $isp;
 
  my $conf_country_db_path = $self->{'main'}{'resolver'}{'conf'}->{uri_country_db_path};
  my $conf_country_db_isp_path = $self->{'main'}{'resolver'}{'conf'}->{uri_country_db_isp_path};
  # If country_db_path is set I am using GeoIP2 api
  if ( HAS_GEOIP2 and ( ( defined $conf_country_db_path ) or ( defined $conf_country_db_isp_path ) ) ) {

   eval {
    $self->{geoip} = GeoIP2::Database::Reader->new(
  		file	=> $conf_country_db_path,
  		locales	=> [ 'en' ]
    ) if (( defined $conf_country_db_path ) && ( -f $conf_country_db_path));
    if ( defined ($conf_country_db_path) ) {
      $db_info = sub { return "GeoIP2 " . ($self->{geoip}->metadata()->description()->{en} || '?') };
      warn "$conf_country_db_path not found" unless $self->{geoip};
    }

    $self->{geoisp} = GeoIP2::Database::Reader->new(
  		file	=> $conf_country_db_isp_path,
  		locales	=> [ 'en' ]
    ) if (( defined $conf_country_db_isp_path ) && ( -f $conf_country_db_isp_path));
    if ( defined ($conf_country_db_isp_path) ) {
      warn "$conf_country_db_isp_path not found" unless $self->{geoisp};
    }
    $self->{use_geoip2} = 1;
   };
   if ($@ || !($self->{geoip} || $self->{geoisp})) {
     $@ =~ s/\s+Trace begun.*//s;
     warn "URILocalBL: GeoIP2 load failed: $@\n";
     return 0;
   }

  } elsif ( HAS_GEOIP ) {
    BEGIN {
      Geo::IP->import( qw(GEOIP_MEMORY_CACHE GEOIP_CHECK_CACHE GEOIP_ISP_EDITION) );
    }
    $self->{use_geoip2} = 0;
    # need GeoIP C library 1.6.3 and GeoIP perl API 1.4.4 or later to avoid messages leaking - Bug 7153
    my $gic_wanted = version->parse('v1.6.3');
    my $gic_have = version->parse(Geo::IP->lib_version());
    my $gip_wanted = version->parse('v1.4.4');
    my $gip_have = version->parse($Geo::IP::VERSION);

    # this code burps an ugly message if it fails, but that's redirected elsewhere
    my $flags = 0;
    my $flag_isp = 0;
    my $flag_silent = 0;
    eval '$flags = GEOIP_MEMORY_CACHE | GEOIP_CHECK_CACHE' if ($gip_have >= $gip_wanted);
    eval '$flag_silent = GEOIP_SILENCE' if ($gip_have >= $gip_wanted);
    eval '$flag_isp = GEOIP_ISP_EDITION' if ($gip_have >= $gip_wanted);

   eval {
    if ($flag_silent && $gic_have >= $gic_wanted) {
      $self->{geoip} = Geo::IP->new($flags | $flag_silent);
      $self->{geoisp} = Geo::IP->open_type($flag_isp, $flag_silent | $flags);
    } else {
      open(OLDERR, ">&STDERR");
      open(STDERR, ">", "/dev/null");
      $self->{geoip} = Geo::IP->new($flags);
      $self->{geoisp} = Geo::IP->open_type($flag_isp);
      open(STDERR, ">&OLDERR");
      close(OLDERR);
    }
   };
    if ($@ || !($self->{geoip} || $self->{geoisp})) {
      $@ =~ s/\s+Trace begun.*//s;
      warn "URILocalBL: GeoIP load failed: $@\n";
      return 0;
    }

    $db_info = sub { return "Geo::IP " . ($self->{geoip}->database_info || '?') };
  } else {
    dbg("No GeoIP module available");
    return 0;
  }

  my %uri_detail = %{ $permsg->get_uri_detail_list() };
  my $test = $permsg->{current_rule_name}; 
  my $rule = $permsg->{conf}->{uri_local_bl}->{$test};

  my %hit_tests;
  my $got_hit = 0;
  my @addrs;
  my $IP_ADDRESS = IP_ADDRESS;
  
  if ( defined $self->{geoip} ) {
    dbg("check: uri_local_bl evaluating rule %s using database %s\n", $test, $db_info->());
  } else {
    dbg("check: uri_local_bl evaluating rule %s\n", $test);
  }

  my $dns_available = $permsg->is_dns_available();

  while (my ($raw, $info) = each %uri_detail) {

    next unless $info->{hosts};

    # look for W3 links only
    next unless (defined $info->{types}->{a} || defined $info->{types}->{parsed});

    while (my($host, $domain) = each %{$info->{hosts}}) {

      # skip if the domain name was matched
      if (exists $rule->{exclusions} && exists $rule->{exclusions}->{$domain}) {
        dbg("check: uri_local_bl excludes %s as *.%s\n", $host, $domain);
        next;
      }

      if($host !~ /^$IP_ADDRESS$/) {
       if (!$dns_available) {
         dbg("check: uri_local_bl skipping $host, dns not available");
         next;
       }
       # this would be best cached from prior lookups
       @addrs = gethostbyname($host);
       # convert to string values address list
       @addrs = map { inet_ntoa($_); } @addrs[4..$#addrs];
      } else {
       @addrs = ($host);
      }

      dbg("check: uri_local_bl %s addrs %s\n", $host, join(', ', @addrs));

      for my $ip (@addrs) {
        # skip if the address was matched
        if (exists $rule->{exclusions} && exists $rule->{exclusions}->{$ip}) {
          dbg("check: uri_local_bl excludes %s(%s)\n", $host, $ip);
          next;
        }

        if (exists $rule->{countries}) {
          dbg("check: uri_local_bl countries %s\n", join(' ', sort keys %{$rule->{countries}}));

          if ( $self->{use_geoip2} == 1 ) {
            my $country;
            if (index($self->{geoip}->metadata()->description()->{en}, 'City') != -1) {
              $country = $self->{geoip}->city( ip => $ip );
            } else {
              $country = $self->{geoip}->country( ip => $ip );
            }
            my $country_rec = $country->country();
            $cc = $country_rec->iso_code();
          } else {
            $cc = $self->{geoip}->country_code_by_addr($ip);
          }

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
          $hit_tests{$test} = 1;

          # reset hash
          keys %uri_detail;
        }

        if (exists $rule->{continents}) {
          dbg("check: uri_local_bl continents %s\n", join(' ', sort keys %{$rule->{continents}}));

          if ( $self->{use_geoip2} == 1 ) {
            my $country = $self->{geoip}->country( ip => $ip );
            my $cont_rec = $country->continent();
            $cont = $cont_rec->{code};
          } else {
            $cc = $self->{geoip}->country_code_by_addr($ip);
            $cont = $self->{geoip}->continent_code_by_country_code($cc);
          }
          
          dbg("check: uri_local_bl host %s(%s) maps to %s\n", $host, $ip, (defined $cont ? $cont : "(undef)"));

          # handle there being no associated continent (yes, there are holes in
          # the database).
          next unless defined $cont;

          # not in blacklist
          next unless (exists $rule->{continents}->{$cont});

          dbg("check: uri_block_cont host %s(%s) matched\n", $host, $ip);

          if (would_log('dbg', 'rules') > 1) {
            dbg("check: uri_block_cont criteria for $test met");
          }

          $permsg->test_log("Host: $host in $cont");
          $hit_tests{$test} = 1;

          # reset hash
          keys %uri_detail;
        }

        if (exists $rule->{isps}) {
          dbg("check: uri_local_bl isps %s\n", join(' ', map { '"' . $_ . '"'; } sort keys %{$rule->{isps}}));

          if ( $self->{use_geoip2} == 1 ) {
            $isp = $self->{geoisp}->isp(ip => $ip);
          } else {
            $isp = $self->{geoisp}->isp_by_name($ip);
          }

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
          $hit_tests{$test} = 1;

          # reset hash
          keys %uri_detail;
        }

        if (exists $rule->{cidr}) {
          dbg("check: uri_block_cidr list %s\n", join(' ', $rule->{cidr}->list_range()));

          next unless ($rule->{cidr}->find($ip));

          dbg("check: uri_block_cidr host %s(%s) matched\n", $host, $ip);

          if (would_log('dbg', 'rules') > 1) {
            dbg("check: uri_block_cidr criteria for $test met");
          }

          $permsg->test_log("Host: $host as $ip");
          $hit_tests{$test} = 1;

          # reset hash
          keys %uri_detail;
        }
      }
    }
    # cycle through all tests hitted by the uri
    while((my $test_ok) = each %hit_tests) {
      $permsg->got_hit($test_ok);
      $got_hit = 1;
    }
    if($got_hit == 1) {
      return 1;
    } else {
      keys %hit_tests;
    }
  }

  dbg("check: uri_local_bl %s no match\n", $test);

  return 0;
}

1;

