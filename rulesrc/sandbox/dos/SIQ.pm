=head1 NAME

Mail::SpamAssassin::Plugin::SIQ				version: 20060305

=head1 SYNOPSIS

 loadplugin Mail::SpamAssassin::Plugin::SIQ [/path/to/SIQ.pm]

 siq_server		db.outboundindex.net:6264

 siq_server_ttl		db.outboundindex.net:6264  300

 siq_oi_workaround	0

 siq_query_timeout	5

 siq_skip_domain	example.com

 siq_skip_ip		1.2.3.4

 header    SIQ_OI_00  eval:siq_score('db.outboundindex.net',0,0)
 score     SIQ_OI_00  1.5
 describe  SIQ_OI_00  Outbound Index Reputation: http://outboundindex.org/
 tflags    SIQ_OI_00  net
 priority  SIQ_OI_00  900

 header    SIQ_OI_IP_01  eval:siq_ip_score('db.outboundindex.net',1,1)
 score     SIQ_OI_IP_01  1.0
 describe  SIQ_OI_IP_01  Outbound Index IP Reputation: http://outboundindex.org/
 tflags    SIQ_OI_IP_01  net
 priority  SIQ_OI_IP_01  900

 header    SIQ_OI_DOM_50  eval:siq_domain_score('db.outboundindex.net',50,59)
 score     SIQ_OI_DOM_50  0.1
 describe  SIQ_OI_DOM_50  Outbound Index Domain Reputation: http://outboundindex.org/
 tflags    SIQ_OI_DOM_50  net
 priority  SIQ_OI_DOM_50  900

 header    SIQ_OI_REL_01  eval:siq_relative_score('db.outboundindex.net',1,1)
 score     SIQ_OI_REL_01  1.0
 describe  SIQ_OI_REL_01  Outbound Index Relative Reputation: http://outboundindex.org/
 tflags    SIQ_OI_REL_01  net
 priority  SIQ_OI_REL_01  900

 header    SIQ_OI_CONF_01  eval:siq_confidence('db.outboundindex.net',1,1)
 score     SIQ_OI_CONF_01  1.0
 describe  SIQ_OI_CONF_01  Outbound Index Confidence: http://outboundindex.org/
 tflags    SIQ_OI_CONF_01  net
 priority  SIQ_OI_CONF_01  900

 header    SIQ_OI_STAB_1  db.outboundindex.net:6264 =~ /stability=1\./
 score     SIQ_OI_STAB_1  0.5
 describe  SIQ_OI_STAB_1  Outbound Index stability value of 1
 tflags    SIQ_OI_STAB_1  net
 priority  SIQ_OI_STAB_1  901

=head1 DESCRIPTION

This plugin queries for reputation data, based on domain & IP pairs, from a
reputation service provider using the IETF ASRG draft SIQ protocol:

http://www.ietf.org/internet-drafts/draft-irtf-asrg-iar-howe-siq-02.txt

A number of eval functions are provided for writing eval-type rules against
the reputation data returned by the reputation service queried.

A pseudo-header is also provided for testing of the optional text area in an
SIQ response.

=head1 AUTHOR

Daryl C. W. O'Shea, DOS Technologies <spamassassin@dostech.ca>

=head1 COPYRIGHT

Copyright (c) 2006 Daryl C. W. O'Shea, DOS Technologies. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

=head1 NOTICE

Built-in caching is used, so queries against the same domain and IP pair will
not incur the expense (both time and reputation service provider charges) of
an additional query.  Note that each SpamAssassin child process maintains its
own idependent cache which is not shared with other children and lasts only
for the lifetime of the current child.  The cache life time is configurable.

=head1 PRIVACY CONCERNS

As with any third-party data service used to classify email, use of services
utilizing the SIQ protocol has inherent privacy implications.  Many/most
reputation services use aggregated data from their query logs as a part of
their reputation calculations.  With the data provided (domain and IP pairs)
by a query client, such as this plugin, a reputation service provider could
estimate your email volume, a breakdown of email domains sending mail to your
systems, and etc.

Depending on your DNS setup, use of services using the SIQ protocol might not
impose privacy concerns greater than those already imposed by the use of DNS
based IP and/or URI blacklists (or whitelists).

=cut

package Mail::SpamAssassin::Plugin::SIQ;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use strict;
use warnings;
use bytes;

use Socket;
use IO::Socket;
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);


sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  if ($mailsaobject->{local_tests_only}) {
    $self->{disabled} = 1;
  } else {
    $self->{disabled} = 0;
  }

  $self->register_eval_rule("siq_score");
  $self->register_eval_rule("siq_ip_score");
  $self->register_eval_rule("siq_domain_score");
  $self->register_eval_rule("siq_relative_score");
  $self->register_eval_rule("siq_confidence");

  $self->set_config($mailsaobject->{conf});

  return $self;
}


sub set_config {
  my($self, $conf) = @_;
  my @cmds = ();

=head1 USER PREFERENCES

=over 4

=item siq_skip_domain	example.com	(default: none)

A list of domain name patterns to exclude from SIQ queries.  Normal shell
wild cards may be used, similar to those used in <C>whilelist_from entries.

Multiple domain name patterns per line are permitted, as are multiple lines.

 Example:
	siq_skip_domain		example.com *.example.com
	siq_skip_domain		*.apache.org

=cut

  push (@cmds, {
    setting => 'siq_skip_domain',
    default => {},
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      if ($value !~ /^[-.*?\w\s]+$/) {
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      foreach my $domain (split(/\s+/, $value)) {
	my $pattern = $domain;
	$domain =~ s/\./\\\./g;
	$domain =~ s/\?/\./g;
	$domain =~ s/\*/\.\*/g;
        $self->{siq_skip_domain}->{lc $domain} = $pattern;
      }
    }
  });

=item siq_skip_ip	192.168.123.*		(default: none)

A list of ip patterns to exclude from SIQ queries.  Normal shell wild cards
may be used, similar to those used in <C>whilelist_from entries.

Multiple ip patterns per line are permitted, as are multiple lines.

 Example:
	siq_skip_ip	192.168.123.* 127.*
	siq_skip_ip	10.1.*

<b>Note: Currently only file-glob style wildcards are supported.  CIDR
notation, nor any other format, is <b> NOT supported.

=cut

  push (@cmds, {
    setting => 'siq_skip_ip',
    default => {},
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      if ($value !~ /^[\.\*\?0-9\s]+$/) {
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      foreach my $ip (split(/\s+/, $value)) {
	my $pattern = $ip;
	$ip =~ s/\./\\\./g;
	$ip =~ s/\?/\./g;
	$ip =~ s/\*/\.\*/g;
        $self->{siq_skip_ip}->{$ip} = $pattern;
      }
    }
  });

=head1 RULE DEFINITIONS AND PRIVILEGED SETTINGS

There are no privileged settings provided.

=over 4

=head1 ADMINISTRATOR SETTINGS

These settings differ from the ones above, in that they are considered 'more
privileged' -- even more than the ones in the B<PRIVILEGED SETTINGS> section.
No matter what C<allow_user_rules> is set to, these can never be set from a
user's C<user_prefs> file when spamc/spamd is being used.  However, all
settings can be used by local programs run directly by the user.

=over 4

=item siq_server	db.example.net:6264

An SIQ server hostname to query.  An optional :port number may be included.  If
no port is specified, port 6264 will be used by default.  Multiple servers per
line are permitted, as are multiple lines.

Examples:

  siq_server	db.example.net:6264
  siq_server	db.example.org
  siq_server	db.example.com db.example.org:1234
  siq_server	db.example.net:6264 db.example.org:1234

=cut

  push (@cmds, {
    setting => 'siq_server',
    default => {},
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      if ($value !~ /^[-.\w\d]+(?::\d{1,5})?(?:\s+[-.\w\d]+(?::\d{1,5})?)*$/) {
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      foreach my $server (split(/\s+/, $value)) {
	$server =~ /^(.*?)(?::(.*))?$/;
	my $host = lc $1;
	my $port = (defined $2 ? $2 : "6264");
	$self->{siq_servers}->{lc $1}->{$port} = 1;
	dbg("config: added SIQ server host: $1 port: $port");
      }
    }
  });

=item siq_server_ttl	db.example.net:6264 300

The amount of time in seconds to keep cached SIQ query responses from a
particular server.  Note that domain and IP pairs may be cached more often
than this value as caches are not shared between children and expire when a
child expires (after 200 messages by default).

This option overrides the TTL returned in an SIQ response by the specified SIQ
server hostname.  An optional :port number may be included.  If no port is
specified, port 6264 will be used by default.  Only one server, with optional
port, and TTL value per line is permitted.  Multiple lines are permitted.

Examples:

  siq_server_ttl   db.example.net:6264   300
  siq_server_ttl   db.example.org        500

Note: To prevent abuse of services, the longer of the TTL provided with this
option and the TTL provided in the SIQ response will be used.

=cut

  push (@cmds, {
    setting => 'siq_server_ttl',
    default => {},
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      if ($value !~ /^([-.\w\d]+)(?::(\d{1,5}))?\s+(\d+)$/) {
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $host = lc $1;
      my $port = (defined $2 ? $2 : "6264");
      my $ttl = $3;
      $self->{siq_server_ttls}->{lc $1}->{$port} = $3;
      dbg("config: added SIQ response TTL: $3 for server host: $1 port: $port");
    }
  });

=item siq_oi_workaround		(0|1)		(default: 0)

As of March 5, 2006, Oubtbound Index does not yet include octets 8-11 (TTL,
Confidence and Extra-Length values) as specified by the draft in their
responses.

Outbound Index plans on updating their software to include these octets in the
near future.  Set this option to 1 to enable correct parsing of Outbound Index
responses in the interim.

<B>Note: Enabling this option will affect parsing of ALL SIQ servers'
responses.  Therefore you cannot use Outbound Index and another service
together until Outbound Index updates their service so that this option
is not required.  This shouldn't be a problem since there aren't any other
public services using SIQ yet.

=cut

  push(@cmds, {
    setting => 'siq_oi_workaround',
    default => 0,
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });

=item siq_query_timeout		n		(default: 5)

The amount of time in seconds to wait for an SIQ query to complete.

=cut

  push(@cmds, {
    setting => 'siq_query_timeout',
    default => 5,
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

  $conf->{parser}->register_commands(\@cmds);
}


=item eval:siq_score('host:port',min,max)

This eval function is provided for writing eval-type rules against the
reputation score returned by the reputation service queried.

<i>min and <i>max define a range of scores to match against.

Example:

  header    SIQ_OI_00  eval:siq_score('db.outboundindex.net',0,0)
  score     SIQ_OI_00  1.5
  describe  SIQ_OI_00  Outbound Index Reputation: http://outboundindex.org/
  tflags    SIQ_OI_00  net
  priority  SIQ_OI_00  900

Note: The priority value gives SIQ responses more time to arrive before
SpamAssassin pauses to wait for responses for the amount of time specified by
<I>siq_query_timeout.  Changing the priority value is not recommended.  Adjust
the <I>siq_query_timeout value to shorten or lengthen the time SpamAssassin
will wait for SIQ responses.  Set <I>siq_query_timeout to <I>0 if you do not
want SpamAssassin to wait at all for SIQ responses.

=cut 

sub siq_score {
  my ($self, $pms, $server, $min, $max) = @_;
  return 0 if $self->{disabled};
  return 0 unless $pms->{siq_checking};

  my $rule_name = $pms->get_current_eval_rule_name();

  my ($config_ok, $host, $port)
    = $self->_parse_eval_call($pms, "siq_score", $rule_name, $server, $min, $max);

  return 0 if (!$config_ok);

  # this comes after $self->_parse_eval_call to avoid being called earlier
  # than necessary by an incorrect eval call
  $self->_get_results($pms) unless $pms->{siq_got_results};

  # log the hit (if any) and return 0, otherwise hits will appear twice
  my @results = $self->_get_results_from_cache($pms->{siq_time}, $host,
				$port, $pms->{siq_domain}, $pms->{siq_ip});

  if (defined $results[1] &&
	$min <= $results[1] && $results[1] <= $max) {
    $self->_log_hit($pms, $rule_name, "SIQ: score: $results[1] queried: ".
				      "$pms->{siq_domain}/$pms->{siq_ip}");
  }
  return 0;
}


=item eval:siq_ip_score('host:port',min,max)

This eval function is provided for writing eval-type rules against the
IP reputation score returned by the reputation service queried.

<i>min and <i>max define a range of scores to match against.

Example:

  header    SIQ_OI_IP_01  eval:siq_ip_score('db.outboundindex.net',1,1)
  score     SIQ_OI_IP_01  1.0
  describe  SIQ_OI_IP_01  Outbound Index IP Reputation: http://outboundindex.org/
  tflags    SIQ_OI_IP_01  net
  priority  SIQ_OI_IP_01  900

Note: See the note above for <I>eval:siq_score regarding the priority value.

=cut 

sub siq_ip_score {
  my ($self, $pms, $server, $min, $max) = @_;
  return 0 if $self->{disabled};
  return 0 unless $pms->{siq_checking};

  my $rule_name = $pms->get_current_eval_rule_name();

  my ($config_ok, $host, $port)
    = $self->_parse_eval_call($pms, "siq_ip_score", $rule_name, $server, $min, $max);

  return 0 if (!$config_ok);

  # this comes after $self->_parse_eval_call to avoid being called earlier
  # than necessary by an incorrect eval call
  $self->_get_results($pms) unless $pms->{siq_got_results};

  # log the hit (if any) and return 0, otherwise hits will appear twice
  my @results = $self->_get_results_from_cache($pms->{siq_time}, $host,
				$port, $pms->{siq_domain}, $pms->{siq_ip});

  if (defined $results[3] &&
	$min <= $results[3] && $results[3] <= $max) {
    $self->_log_hit($pms, $rule_name, "SIQ: score: $results[3] queried: ".
				      "$pms->{siq_domain}/$pms->{siq_ip}");
  }
  return 0;
}


=item eval:siq_domain_score('host:port',min,max)

This eval function is provided for writing eval-type rules against the
domain reputation score returned by the reputation service queried.

<i>min and <i>max define a range of scores to match against.

Example:

  header    SIQ_OI_DOM_50  eval:siq_domain_score('db.outboundindex.net',50,59)
  score     SIQ_OI_DOM_50  0.1
  describe  SIQ_OI_DOM_50  Outbound Index Domain Reputation: http://outboundindex.org/
  tflags    SIQ_OI_DOM_50  net
  priority  SIQ_OI_DOM_50  900

Note: See the note above for <I>eval:siq_score regarding the priority value.

=cut 

sub siq_domain_score {
  my ($self, $pms, $server, $min, $max) = @_;
  return 0 if $self->{disabled};
  return 0 unless $pms->{siq_checking};

  my $rule_name = $pms->get_current_eval_rule_name();

  my ($config_ok, $host, $port)
    = $self->_parse_eval_call($pms, "siq_domain_score", $rule_name, $server, $min, $max);

  return 0 if (!$config_ok);

  # this comes after $self->_parse_eval_call to avoid being called earlier
  # than necessary by an incorrect eval call
  $self->_get_results($pms) unless $pms->{siq_got_results};

  # log the hit (if any) and return 0, otherwise hits will appear twice
  my @results = $self->_get_results_from_cache($pms->{siq_time}, $host,
				$port, $pms->{siq_domain}, $pms->{siq_ip});

  if (defined $results[4] &&
	$min <= $results[4] && $results[4] <= $max) {
    $self->_log_hit($pms, $rule_name, "SIQ: score: $results[4] queried: ".
				      "$pms->{siq_domain}/$pms->{siq_ip}");
  }
  return 0;
}


=item eval:siq_relative_score('host:port',min,max)

This eval function is provided for writing eval-type rules against the
relative reputation score returned by the reputation service queried.

<i>min and <i>max define a range of scores to match against.

Example:

  header    SIQ_OI_REL_01  eval:siq_relative_score('db.outboundindex.net',1,1)
  score     SIQ_OI_REL_01  1.0
  describe  SIQ_OI_REL_01  Outbound Index Relative Reputation: http://outboundindex.org/
  tflags    SIQ_OI_REL_01  net
  priority  SIQ_OI_REL_01  900

Note: See the note above for <I>eval:siq_score regarding the priority value.

=cut 

sub siq_relative_score {
  my ($self, $pms, $server, $min, $max) = @_;
  return 0 if $self->{disabled};
  return 0 unless $pms->{siq_checking};

  my $rule_name = $pms->get_current_eval_rule_name();

  my ($config_ok, $host, $port)
    = $self->_parse_eval_call($pms, "siq_relative_score", $rule_name, $server, $min, $max);

  return 0 if (!$config_ok);

  # this comes after $self->_parse_eval_call to avoid being called earlier
  # than necessary by an incorrect eval call
  $self->_get_results($pms) unless $pms->{siq_got_results};

  # log the hit (if any) and return 0, otherwise hits will appear twice
  my @results = $self->_get_results_from_cache($pms->{siq_time}, $host,
				$port, $pms->{siq_domain}, $pms->{siq_ip});

  if (defined $results[5] &&
	$min <= $results[5] && $results[5] <= $max) {
    $self->_log_hit($pms, $rule_name, "SIQ: score: $results[5] queried: ".
				      "$pms->{siq_domain}/$pms->{siq_ip}");
  }
  return 0;
}


=item eval:siq_confidence('host:port',min,max)

This eval function is provided for writing eval-type rules against the
confidence value returned by the reputation service queried.

<i>min and <i>max define a range of values to match against.

Example:

  header    SIQ_OI_CONF_01  eval:siq_confidence('db.outboundindex.net',1,1)
  score     SIQ_OI_CONF_01  1.0
  describe  SIQ_OI_CONF_01  Outbound Index Confidence: http://outboundindex.org/
  tflags    SIQ_OI_CONF_01  net
  priority  SIQ_OI_CONF_01  900

Note: See the note above for <I>eval:siq_score regarding the priority value.

=cut 

sub siq_confidence {
  my ($self, $pms, $server, $min, $max) = @_;
  return 0 if $self->{disabled};
  return 0 unless $pms->{siq_checking};

  my $rule_name = $pms->get_current_eval_rule_name();

  my ($config_ok, $host, $port)
    = $self->_parse_eval_call($pms, "siq_confidence", $rule_name, $server, $min, $max);

  return 0 if (!$config_ok);

  # this comes after $self->_parse_eval_call to avoid being called earlier
  # than necessary by an incorrect eval call
  $self->_get_results($pms) unless $pms->{siq_got_results};

  # log the hit (if any) and return 0, otherwise hits will appear twice
  my @results = $self->_get_results_from_cache($pms->{siq_time}, $host,
				$port, $pms->{siq_domain}, $pms->{siq_ip});

  if (defined $results[8] &&
	$min <= $results[8] && $results[8] <= $max) {
    $self->_log_hit($pms, $rule_name, "SIQ: value: $results[8] queried: ".
				      "$pms->{siq_domain}/$pms->{siq_ip}");
  }
  return 0;
}


=item header siqhost[:port] =~ /pattern/modifiers

A pseudo-header containing the text portion of the SIQ result is
provided for each SIQ server that you have called at least one of
the above eval tests on one of more times.

Example:

  header    SIQ_OI_STAB_1  db.outboundindex.net =~ /stability=1\./
  score     SIQ_OI_STAB_1  0.5
  describe  SIQ_OI_STAB_1  Outbound Index stability value of 1
  tflags    SIQ_OI_STAB_1  net
  priority  SIQ_OI_STAB_1  901

  header    SIQ_EX_STAB_20  db.example.org:1234 =~ /stability=2[0-9]\./
  score     SIQ_EX_STAB_20  0.1
  describe  SIQ_EX_STAB_20  Example Service stability value of 20 to 29
  tflags    SIQ_EX_STAB_20  net
  priority  SIQ_EX_STAB_20  9

Notes:

You <b>MUST call at least one of the above eval tests on each of the servers
that you want to test the text portion of the response, otherwise the
pseudo-header will not be present.

You <B>MUST include the port number in the psuedo-header if the default port
6264 is not used, otherwise it is optional.

You <B>MUST include a priority for the rule that is greater in value than the
priority of the required pre-requisite eval test.  The pseudo-header will not
yet be present if this rule's priority is less than (higher) than the above
eval tests.

=cut 

sub _parse_eval_call {
  my ($self, $pms, $eval_name, $rule_name, $server, $min, $max) = @_;

  my ($host, $port);

  # validate the eval call and complain if it was done wrong
  unless (defined $server && $server =~ /^([-.\w\d]+)(?::(\d{1,5}))?$/) {
    warn("siq: eval rule: $rule_name ".
	 "requires an SIQ server parameter (host with optional :port) ".
	 "as the first parameter");

    dbg("config: eval rule: $rule_name ".
	"requires an SIQ server parameter such as: header $rule_name ".
	"eval:$eval_name\('db.example.com:6264',20,30\)");

    $pms->{rule_errors}++; # flag to --lint that there was an error ...
    return 0;
  } else {
    $host = $1;
    $port = (defined $2 ? $2 : "6264");
  }
  
  unless (exists $pms->{conf}->{siq_servers}->{$host}->{$port}) {
    warn("siq: the SIQ server specified in eval rule: $rule_name ".
	 "has not been added to the list of SIQ servers to query");

    dbg("config: you must add \'siq_server $host:$port\' to your configuration ".
	"if you want to be able to test SIQ results from this server");

    $pms->{rule_errors}++; # flag to --lint that there was an error ...
    return 0;
  }

  unless (defined $min && $min =~ /^-?\d+(?:\.\d+)?$/ && 
	  defined $max && $max =~ /^-?\d+(?:\.\d+)?$/) {
    warn("siq: eval rule: $rule_name requires a minimum and maximum value");

    dbg("config: eval rule: $rule_name ".
	"requires minimum and maximum parameters such as: header ".
	"$rule_name eval:$eval_name\('db.example.com',20,30\)");

    $pms->{rule_errors}++; # flag to --lint that there was an error ...
    return 0;
  }

  return (1, $host, $port);
}


sub _log_hit {
  my ($self, $pms, $rulename, $text) = @_;

  $pms->test_log ($text);
  $pms->got_hit ($rulename, "");
}


sub parsed_metadata {
  my ($self, $opts) = @_;
  my $pms = $opts->{permsgstatus};

  return if $self->{disabled};

  $pms->{siq_queries_remaining} = 0;
  $pms->{siq_queries_sent} = 0;
  $pms->{siq_time} = time;
  $pms->{siq_got_results} = 0;
  $pms->{siq_checking} = 0;

  # get an appropriate relay to test against
  my $lasthop = $self->_get_relay($pms);
  if (!defined $lasthop) {
    dbg("siq: no suitable relay for siq use found, skipping SIQ query");
    return;
  }

  $pms->{siq_ip} = $lasthop->{ip};
  $pms->{siq_domain} = $self->_get_sender($pms);

  # we already dbg'd if we couldn't get a sender, just return
  return unless (defined $pms->{siq_domain});
  $pms->{siq_domain} =~ s/^.*\@//;

  # check to see if the domain is in the list of domains to skip
  my $skip_it = 0;
  while (my ($regexp, $simple) = each (%{$pms->{conf}->{siq_skip_domain}})) {
    if ($pms->{siq_domain} =~ /^$regexp$/) { # both already lc
      dbg("siq: domain: $pms->{siq_domain} matches skip pattern: $simple");
      $skip_it = 1;
    }
  }
  return if $skip_it;
  
  # check to see if the domain is in the list of domains to skip
  while (my ($regexp, $simple) = each (%{$pms->{conf}->{siq_skip_ip}})) {
    if ($pms->{siq_ip} =~ /^$regexp$/) { # both already lc
      dbg("siq: ip: $pms->{siq_ip} matches skip pattern: $simple");
      $skip_it = 1;
    }
  }
  return if $skip_it;

  # signal to the evals that we're doing checks this time around
  $pms->{siq_checking} = 1;

  # do queries
  foreach my $host (keys %{$pms->{conf}->{siq_servers}}) {
    foreach my $port (keys %{$pms->{conf}->{siq_servers}->{$host}}) {
      next if $self->_check_for_cached_results($pms, $pms->{siq_time}, $host,
				$port, $pms->{siq_domain}, $pms->{siq_ip});
      dbg("siq: querying $host:$port");
      $self->_send_siq_query($pms, $pms->{siq_domain}, $pms->{siq_ip},
				$host, $port);
    }
  }

  return;
}


sub _cache_results {
  my ($self, $time, $host, $port, $domain, $ip, @results) = @_;

  # set cache item expiry time
  # don't allow TTLs shorter than the TTL specified in the response
  if (exists $self->{main}->{conf}->{siq_server_ttls}->{$host}->{$port} &&
   $self->{main}->{conf}->{siq_server_ttls}->{$host}->{$port} > $results[7]) {
    $time += $self->{main}->{conf}->{siq_server_ttls}->{$host}->{$port};
  } else {
    $time += $results[7] if ($results[7] > 0); # unknown OI TTL is set to -999
  }

  $self->{siq_cache} = {} unless (exists $self->{siq_cache});

  $self->{siq_cache}->{$host} = {}
    unless (exists $self->{siq_cache}->{$host});

  $self->{siq_cache}->{$host}->{$port} = {}
    unless (exists $self->{siq_cache}->{$host}->{$port});

  $self->{siq_cache}->{$host}->{$port}->{$domain} = {}
    unless (exists $self->{siq_cache}->{$host}->{$port}->{$domain});

  $self->{siq_cache}->{$host}->{$port}->{$domain}->{$ip} = [$time, @results];

  dbg("siq: saved results to cache: $host:$port/$domain/$ip");

  return;
}


sub _check_for_cached_results {
  my ($self, $pms, $time, $host, $port, $domain, $ip) = @_;

  if (exists $self->{siq_cache}->{$host}->{$port}->{$domain}->{$ip}) {
    if ($self->{siq_cache}->{$host}->{$port}->{$domain}->{$ip}->[0] > $time) {
      dbg("siq: found results in cache: $host:$port/$domain/$ip");

      # make the cached text portion available for testing
      # the port number is optional if the default 6264 is used
      $pms->{msg}->put_metadata("$host:$port",
	$self->{siq_cache}->{$host}->{$port}->{$domain}->{$ip}->[10]);
      if ($port == 6264) {
	$pms->{msg}->put_metadata($host,
	  $self->{siq_cache}->{$host}->{$port}->{$domain}->{$ip}->[10]);
      }
      return 1;
    } else {
      dbg("siq: found expired result in cache, doing new query");
    }
  } else {
    dbg("siq: no results found in cache for $host:$port");
  }
  return 0;
}


sub _get_results_from_cache {
  my ($self, $time, $host, $port, $domain, $ip) = @_;

  if (exists $self->{siq_cache}->{$host}->{$port}->{$domain}->{$ip}) {
    if ($self->{siq_cache}->{$host}->{$port}->{$domain}->{$ip}->[0] > $time) {
      my @results = @{$self->{siq_cache}->{$host}->{$port}->{$domain}->{$ip}};
      shift @results;
      return @results;
    }
  }
  return undef;
}


sub _generate_query_id {
  return int(rand(65535));
}


sub _send_siq_query {
  my ($self, $pms, $domain, $ip, $host, $port) = @_;

  unless (defined $ip &&
	  $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/) {
    warn("siq: invalid (non-IPv4) IP passed to _send_siq_query\n");
    return 0;
  }

  unless (defined $domain) {
    warn("siq: missing domain in call to _send_siq_query\n");
    return 0;
  }

  # the query ID identifies the query and is used in the response packet
  # since we send multiple queries out on the same socket, we have to
  # create a new packet with a random query ID for each query
  my $query_id = $self->_generate_query_id();
  $pms->{siq_query_ids}->{$host}->{$port} = $query_id;

  # build request packet
  my $payload = pack("B8", "00000001");			# version
  $payload   .= pack("B8");				# QT
  $payload   .= substr(pack("N", $query_id), 2);  	# ID
  $payload   .= pack("B96");				# IPv6 zero-padding
  $payload   .= inet_aton($ip);				# IPv4 in IPv6
  $payload   .= substr(pack("N", length($domain)), 3);	# QD-length in octets
  $payload   .= pack("B8");				# extra length (octets)
  $payload   .= $domain;				# domain

  # save socket handle on $pms, we'll check for a response later
  unless (exists $pms->{siq_handle} && $pms->{siq_handle}) {
    dbg("siq: opening socket for SIQ queries");
    unless ($pms->{siq_handle} = IO::Socket::INET->new(Proto => 'udp')) {
      dbg("siq: socket creation failed: $@");
      return 0;
    } else {
      # try to prevent unwanted blocking
      my $flags = fcntl($pms->{siq_handle}, F_GETFL, 0)
	or warn "siq: Can't get flags for the socket: $!\n";
      if ($flags) {
	fcntl($pms->{siq_handle}, F_SETFL, $flags | O_NONBLOCK)
	  or warn "siq: Can't set flags for the socket: $!\n";
      }
    }
  } else {
    dbg("siq: using existing socket for SIQ queries");
  }

  my $ipaddr = inet_aton($host);
  my $portaddr = sockaddr_in($port, $ipaddr);

  unless (send($pms->{siq_handle}, $payload, 0, $portaddr)
	== length($payload)) {
    dbg("siq: cannot send query: $!");
    return 0;
  } else {
    dbg("siq: sent query ID $query_id to $host:$port");
    $pms->{siq_queries_remaining}++;
    $pms->{siq_queries_sent}++;
  }
  return 1;
}


sub _get_results {
  my ($self, $pms) = @_;

  $pms->{siq_got_results} = 1;
  $self->_harvest_siq_responses($pms);

  dbg("siq: sent ". $pms->{siq_queries_sent} ." queries, received ".
	($pms->{siq_queries_sent} - $pms->{siq_queries_remaining})
	." responses");
  return;
}


sub _harvest_siq_responses {
  my ($self, $pms) = @_;

  return unless $pms->{siq_queries_sent};

  my $rout;
  my $rin = '';

  vec($rin,fileno($pms->{siq_handle}),1) = 1;

  my $timeout = $pms->{conf}->{siq_query_timeout};

  my $nfound = 0;
  my $wait_time = 0.05;

  while ($timeout > 0) {
    $nfound = select($rout=$rin, undef, undef, $wait_time);

    if (!defined $nfound || $nfound < 1) {
      $timeout -= $wait_time;
    } else {
      # read results
      READRESULT: for (my $i = 0; $i < $nfound; $i++) {
	my ($response, $portaddr);
	unless ($portaddr = recv($pms->{siq_handle}, $response, 512, 0)) {
	  dbg ("siq: recv failed: $!");
	  return 0;
	}

	# parse response
	# returns: ($version, $score, $id, $ipscore, $dscore, $rscore, $textlen, $ttl,
	#	    $confidence, $text)
	my (@results) = $self->_parse_response($response, $pms->{conf}->{siq_oi_workaround});
	next READRESULT unless @results;

	foreach my $host (keys %{$pms->{siq_query_ids}}) {
	  foreach my $port (keys %{$pms->{siq_query_ids}->{$host}}) {
	    my $query_id = $pms->{siq_query_ids}->{$host}->{$port};

	    if ($results[2] == $query_id) {
	      dbg("siq: response ID $query_id matches query to $host:$port");
	      $pms->{siq_queries_remaining}--;

	      dbg("siq: response: ". join("/", @results));

              $self->_cache_results($pms->{siq_time}, $host, $port,
				$pms->{siq_domain}, $pms->{siq_ip}, @results);

	      # we store the text section as metadata so people can write
	      # rules against it
	      # the port number is optional if the default 6264 is used
	      $pms->{msg}->put_metadata("$host:$port", $results[9]);
	      if ($port == 6264) {
		$pms->{msg}->put_metadata($host, $results[9]);
	      }

	      unless ($pms->{siq_queries_remaining}) {
		dbg("siq: received responses to all queries after waiting ".
		   (sprintf "%.2f", ($pms->{conf}->{siq_query_timeout} - $timeout))
		   ." seconds, closing socket");
		close $pms->{siq_handle};
		return 1;
	      }
	      next READRESULT;
	    }
	  }
	}
        dbg("siq: response ID $results[2] does not match any queries sent ".
	    "for this message, discarding");
      }
      dbg("siq: waiting up to $timeout seconds for more responses");
    }
  }

  dbg("siq: query response timeout, closing socket");
  close $pms->{siq_handle};
  return 0;
}


sub _parse_response {
  my ($self, $response, $enable_oi_workaround) = @_;

  my $min_response_length = 12;
  if ($enable_oi_workaround) {
    dbg("siq: using Outbound Index response missing octets workaround");
    $min_response_length = 8;
  }

  if (length($response) < $min_response_length) {
    dbg("siq: packet shorter than minimum response length, ignoring packet");
    return;
  }

  my $version	= unpack("c8", substr($response, 0, 1));
  my $score	= unpack("c8", substr($response, 1, 1));
  my $id = unpack("N", pack("x2B16", unpack("B16", substr($response, 2, 2))));
  my $ipscore	= unpack("c8", substr($response, 4, 1));
  my $dscore	= unpack("c8", substr($response, 5, 1));
  my $rscore	= unpack("c8", substr($response, 6, 1));
  my $textlen	= unpack("c8", substr($response, 7, 1));

  # ensure we've got the entire packet
  if (length($response) < ($min_response_length + $textlen)) {
    dbg("siq: packet length shorter than minimum length plus reported TEXT ".
	"section length, ignoring packet");
    return;
  }

  # workaround Outbound Index not using the current draft yet
  # (they don't include draft response octets 8-11)
  my ($ttl, $confidence, $text);
  if ($enable_oi_workaround) {
    $ttl	= -999;
    $confidence	= -999;
    $text	= unpack("A*", substr($response, 8, $textlen));
  } else {
    $ttl = unpack("N", pack("x2B16", unpack("B16", substr($response, 8, 2))));
    $confidence	= unpack("c8", substr($response, 10, 1));
    my $xtralen	= unpack("c8", substr($response, 11, 1));
    $text	= unpack("A*", substr($response, 12, $textlen));

    # the 'EXTRA' data is server/client dependent, we can't reasonably parse
    # ever implementations EXTRA section, so don't parse any -- they can
    # always use the TEXT section which we do support
    dbg("siq: plugin does not support parsing of the $xtralen octets of ".
	"'EXTRA' data provided in the SIQ response, not using 'EXTRA' data")
      if $xtralen;
  }

  return ($version, $score, $id, $ipscore, $dscore, $rscore, $textlen, $ttl,
	  $confidence, $text);
}


# dos: copied (with s/SPF/SIQ/) from my patch for SA bug 4661 -- the current
# SPF code does it wrong for non-trivial cases
# http://issues.apache.org/SpamAssassin/attachment.cgi?id=3241&action=view
# this really needs to get into Received.pm itself
sub _get_relay {
  my ($self, $scanner) = @_;

  # return relay if already determined
  return $scanner->{siq_relay} if exists $scanner->{siq_relay};

  # DOS: For SIQ checks we want to use the relay that passed the message to
  # the internal network.  This relay can be any of the trusted relays or the
  # first untrusted relay.  No matter which it is, the next (newer) relay has
  # to be an internal relay.  If there are no trusted relays, the first
  # untrusted relay is the one we want.  If internal_networks aren't set we
  # have to assume all trusted relays are internal.

  my $relay = undef;
  my $relays_trusted = $scanner->{relays_trusted};

  # no trusted relays, use first untrusted
  if (scalar @{$relays_trusted} == 0) {
    $relay = $scanner->{relays_untrusted}->[0];
    dbg("siq: no trusted relays found, using first (untrusted) relay (if present) for SIQ checks");
  }

  # last trusted relay is internal (or internal_networks not set), use first untrusted
  elsif ($relays_trusted->[-1]->{internal} || !($scanner->{conf}->{internal_networks}->get_num_nets() > 0)) {
    $relay = $scanner->{relays_untrusted}->[0];
    dbg("siq: last trusted relay is internal, using first untrusted relay (parsed relay #". (scalar @{$relays_trusted}+1) ." if present) for SIQ checks");
  }

  # find external relay that passed the message to the last internal relay
  else {

    # found an internal relay?
    my $found = 0;

    # start at the end; don't check for an internal relay before the first one
    for (my $i = scalar @{$relays_trusted} - 1; $i > 0 && !$found; $i--) {
      # if the next relay is internal, we can use the current external one
      if ($relays_trusted->[$i-1]->{internal}) {
	$relay = $relays_trusted->[$i];
	$found = 1;
	dbg("siq: using first external trusted relay (parsed relay #". ($i+1) .") for SIQ checks");
      }
    }

    # if none of the trusted relays were internal, internal_networks isn't set
    # correctly -- dbg about it
    if (!$found) {
      dbg("siq: none of the trusted relays are internal, please check your internal_networks configuration");
    }	
  }

  $scanner->{siq_relay} = $relay;
  return $relay;
}


# copied with modifications from patched (bug 4661) SPF.pm
# this also needs to get into Received.pm or elsewhere
sub _get_sender {
  my ($self, $scanner) = @_;
  my $sender;

  my $relay = $self->_get_relay($scanner);
  if (defined $relay) {
    $sender = $relay->{envfrom};
  }

  if ($sender) {
    dbg("siq: found Envelope-From in first external Received header");
  }
  else {
    # We cannot use the env-from data, since it went through 1 or more relays
    # since the untrusted sender and they may have rewritten it.
    if ($scanner->{num_relays_trusted} > 0 && !$scanner->{conf}->{always_trust_envelope_sender}) {
      dbg("siq: relayed through one or more trusted relays, cannot use header-based Envelope-From, skipping");
      return;
    }

    # we can (apparently) use whatever the current Envelope-From was,
    # from the Return-Path, X-Envelope-From, or whatever header.
    # it's better to get it from Received though, as that is updated
    # hop-by-hop.
    $sender = $scanner->get ("EnvelopeFrom");
  }

  if (!$sender) {
    dbg("siq: cannot get Envelope-From, cannot use SIQ");
    return;  # avoid setting $scanner->{sender} to undef
  }

  return lc $sender;
}


1;
