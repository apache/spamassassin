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

Mail::SpamAssassin::Plugin::SPF - perform SPF verification tests

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::SPF

=head1 DESCRIPTION

This plugin checks a message against Sender Policy Framework (SPF)
records published by the domain owners in DNS to fight email address
forgery and make it easier to identify spams.

It's recommended to use MTA filter (pypolicyd-spf / spf-engine etc), so this
plugin can reuse the Received-SPF and/or Authentication-Results header results as is.
Otherwise throughput could suffer, DNS lookups done by this plugin are not
asynchronous.
Those headers will also help when SpamAssassin is not able to correctly detect EnvelopeFrom.

=cut

package Mail::SpamAssassin::Plugin::SPF;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;
use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule ("check_for_spf_pass", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule ("check_for_spf_neutral", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule ("check_for_spf_none", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule ("check_for_spf_fail", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule ("check_for_spf_softfail", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule ("check_for_spf_permerror", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule ("check_for_spf_temperror", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule ("check_for_spf_helo_pass", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule ("check_for_spf_helo_neutral", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule ("check_for_spf_helo_none", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule ("check_for_spf_helo_fail", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule ("check_for_spf_helo_softfail", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule ("check_for_spf_helo_permerror", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule ("check_for_spf_helo_temperror", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule ("check_for_spf_welcomelist_from", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule ("check_for_spf_whitelist_from", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS); # removed in 4.1
  $self->register_eval_rule ("check_for_def_spf_welcomelist_from", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule ("check_for_def_spf_whitelist_from", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS); # removed in 4.1
  $self->register_eval_rule ("check_spf_skipped_noenvfrom", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);

  $self->set_config($mailsaobject->{conf});

  return $self;
}

###########################################################################

sub set_config {
  my($self, $conf) = @_;
  my @cmds;

=head1 USER SETTINGS

=over 4

=item welcomelist_from_spf user@example.com

Previously whitelist_from_spf which will work interchangeably until 4.1.

Works similarly to welcomelist_from, except that in addition to matching a
sender address, a check against the domain's SPF record must pass.  The
first parameter is an address to welcomelist, and the second is a string to
match the relay's rDNS.

Just like welcomelist_from, multiple addresses per line, separated by
spaces, are OK.  Multiple C<welcomelist_from_spf> lines are also OK.

The headers checked for welcomelist_from_spf addresses are the same headers
used for SPF checks (Envelope-From, Return-Path, X-Envelope-From, etc).

Since this welcomelist requires an SPF check to be made, network tests must be
enabled. It is also required that your trust path be correctly configured.
See the section on C<trusted_networks> for more info on trust paths.

e.g.

  welcomelist_from_spf joe@example.com fred@example.com
  welcomelist_from_spf *@example.com

=item def_welcomelist_from_spf user@example.com

Previously def_whitelist_from_spf which will work interchangeably until 4.1.

Same as C<welcomelist_from_spf>, but used for the default welcomelist entries
in the SpamAssassin distribution.  The welcomelist score is lower, because
these are often targets for spammer spoofing.

=item unwelcomelist_from_spf user@example.com

Previously unwhitelist_from_spf which will work interchangeably until 4.1.

Used to remove a C<welcomelist_from_spf> or C<def_welcomelist_from_spf> entry. 
The specified email address has to match exactly the address previously used.

Useful for removing undesired default entries from a distributed configuration
by a local or site-specific configuration or by C<user_prefs>.

=cut

  push (@cmds, {
    setting => 'welcomelist_from_spf',
    aliases => ['whitelist_from_spf'], # removed in 4.1
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST
  });

  push (@cmds, {
    setting => 'def_welcomelist_from_spf',
    aliases => ['def_whitelist_from_spf'], # removed in 4.1
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST
  });

  push (@cmds, {
    setting => 'unwelcomelist_from_spf',
    aliases => ['unwhitelist_from_spf'], # removed in 4.1
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^(?:\S+(?:\s+\S+)*)$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{parser}->remove_from_addrlist('welcomelist_from_spf',
                                        split (/\s+/, $value));
      $self->{parser}->remove_from_addrlist('def_welcomelist_from_spf',
                                        split (/\s+/, $value));
    }
  });

=back

=head1 ADMINISTRATOR SETTINGS

=over 4

=item spf_timeout n		(default: 5)

How many seconds to wait for an SPF query to complete, before scanning
continues without the SPF result. A numeric value is optionally suffixed
by a time unit (s, m, h, d, w, indicating seconds (default), minutes, hours,
days, weeks).

=cut

  push (@cmds, {
    setting => 'spf_timeout',
    is_admin => 1,
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_DURATION
  });

=item ignore_received_spf_header (0|1)	(default: 0)

By default, to avoid unnecessary DNS lookups, the plugin will try to use the
SPF results found in any C<Received-SPF> headers it finds in the message that
could only have been added by an internal relay.

Set this option to 1 to ignore any C<Received-SPF> headers present and to have
the plugin perform the SPF check itself.

Note that unless the plugin finds an C<identity=helo>, or some unsupported
identity, it will assume that the result is a mfrom SPF check result.  The
only identities supported are C<mfrom>, C<mailfrom> and C<helo>.

=cut

  push(@cmds, {
    setting => 'ignore_received_spf_header',
    is_admin => 1,
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });

=item use_newest_received_spf_header (0|1)	(default: 0)

By default, when using C<Received-SPF> headers, the plugin will attempt to use
the oldest (bottom most) C<Received-SPF> headers, that were added by internal
relays, that it can parse results from since they are the most likely to be
accurate.  This is done so that if you have an incoming mail setup where one
of your primary MXes doesn't know about a secondary MX (or your MXes don't
know about some sort of forwarding relay that SA considers trusted+internal)
but SA is aware of the actual domain boundary (internal_networks setting) SA
will use the results that are most accurate.

Use this option to start with the newest (top most) C<Received-SPF> headers,
working downwards until results are successfully parsed.

=cut

  push(@cmds, {
    setting => 'use_newest_received_spf_header',
    is_admin => 1,
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });

  # Deprecated since 4.0.0, leave for backwards compatibility
  push(@cmds, {
    setting => 'do_not_use_mail_spf',
    is_admin => 1,
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });
  push(@cmds, {
    setting => 'do_not_use_mail_spf_query',
    is_admin => 1,
    default => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });

  $conf->{parser}->register_commands(\@cmds);
}

=item has_check_for_spf_errors

Adds capability check for "if can()" for check_for_spf_permerror, check_for_spf_temperror, check_for_spf_helo_permerror and check_for_spf_helo_permerror

=cut

sub has_check_for_spf_errors { 1 }

=item has_check_spf_skipped_noenvfrom

Adds capability check for "if can()" for check_spf_skipped_noenvfrom

=cut

sub has_check_spf_skipped_noenvfrom { 1 }

sub parsed_metadata {
  my ($self, $opts) = @_;

  $self->_get_sender($opts->{permsgstatus});

  return 1;
}

# SPF support
sub check_for_spf_pass {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  return $scanner->{spf_pass} ? 1 : 0;
}

sub check_for_spf_neutral {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  return $scanner->{spf_neutral} ? 1 : 0;
}

sub check_for_spf_none {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  return $scanner->{spf_none} ? 1 : 0;
}

sub check_for_spf_fail {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  if ($scanner->{spf_failure_comment}) {
    $scanner->test_log ($scanner->{spf_failure_comment});
  }
  return $scanner->{spf_fail} ? 1 : 0;
}

sub check_for_spf_softfail {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  return $scanner->{spf_softfail} ? 1 : 0;
}

sub check_for_spf_permerror {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  return $scanner->{spf_permerror} ? 1 : 0;
}

sub check_for_spf_temperror {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  return $scanner->{spf_temperror} ? 1 : 0;
}

sub check_for_spf_helo_pass {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  return $scanner->{spf_helo_pass} ? 1 : 0;
}

sub check_for_spf_helo_neutral {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  return $scanner->{spf_helo_neutral} ? 1 : 0;
}

sub check_for_spf_helo_none {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  return $scanner->{spf_helo_none} ? 1 : 0;
}

sub check_for_spf_helo_fail {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  if ($scanner->{spf_helo_failure_comment}) {
    $scanner->test_log ($scanner->{spf_helo_failure_comment});
  }
  return $scanner->{spf_helo_fail} ? 1 : 0;
}

sub check_for_spf_helo_softfail {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  return $scanner->{spf_helo_softfail} ? 1 : 0;
}

sub check_for_spf_helo_permerror {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  return $scanner->{spf_helo_permerror} ? 1 : 0;
}

sub check_for_spf_helo_temperror {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  return $scanner->{spf_helo_temperror} ? 1 : 0;
}

=over 4

=item check_spf_skipped_noenvfrom

Checks if SPF checks have been skipped because EnvelopeFrom cannot be determined.

=back

=cut

sub check_spf_skipped_noenvfrom {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  if (!exists $scanner->{spf_sender}) {
    return 1;
  } else {
    return 0;
  }
}

sub check_for_spf_welcomelist_from {
  my ($self, $scanner) = @_;
  $self->_check_spf_welcomelist($scanner) unless $scanner->{spf_welcomelist_from_checked};
  return $scanner->{spf_welcomelist_from} ? 1 : 0;
}
*check_for_spf_whitelist_from = \&check_for_spf_welcomelist_from; # removed in 4.1

sub check_for_def_spf_welcomelist_from {
  my ($self, $scanner) = @_;
  $self->_check_def_spf_welcomelist($scanner) unless $scanner->{def_spf_welcomelist_from_checked};
  return $scanner->{def_spf_welcomelist_from} ? 1 : 0;
}
*check_for_def_spf_whitelist_from = \&check_for_def_spf_welcomelist_from; # removed in 4.1

sub _check_spf {
  my ($self, $scanner, $ishelo) = @_;

  my $timer = $self->{main}->time_method("check_spf");

  # we can re-use results from any *INTERNAL* Received-SPF header in the message...
  # we can't use results from trusted but external hosts since (i) spf checks are
  # supposed to be done "on the domain boundary", (ii) even if an external header 
  # has a result that matches what we would get, the check was probably done on a
  # different envelope (like the apache.org list servers checking the ORCPT and
  # then using a new envelope to send the mail from the list) and (iii) if the
  # checks are being done right and the envelope isn't being changed it's 99%
  # likely that the trusted+external host really should be defined as part of your
  # internal network
  if ($scanner->{conf}->{ignore_received_spf_header}) {
    dbg("spf: ignoring any Received-SPF headers from internal hosts, by admin setting");
  } elsif ($scanner->{checked_for_received_spf_header}) {
    dbg("spf: already checked for Received-SPF headers, proceeding with DNS based checks");
  } else {
    $scanner->{checked_for_received_spf_header} = 1;
    dbg("spf: checking to see if the message has a Received-SPF header that we can use");

    my @internal_hdrs = $scanner->get('ALL-INTERNAL');
    unless ($scanner->{conf}->{use_newest_received_spf_header}) {
      # look for the LAST (earliest in time) header, it'll be the most accurate
      @internal_hdrs = reverse(@internal_hdrs);
    } else {
      dbg("spf: starting with the newest Received-SPF headers first");
    }

    foreach my $hdr (@internal_hdrs) {
      local($1,$2);
      if ($hdr =~ /^received-spf:/i) {
	dbg("spf: found a Received-SPF header added by an internal host: $hdr");

	# old version:
	# Received-SPF: pass (herse.apache.org: domain of spamassassin@dostech.ca
	# 	designates 69.61.78.188 as permitted sender)

	# new version:
	# Received-SPF: pass (dostech.ca: 69.61.78.188 is authorized to use
	# 	'spamassassin@dostech.ca' in 'mfrom' identity (mechanism 'mx' matched))
	# 	receiver=FC5-VPC; identity=mfrom; envelope-from="spamassassin@dostech.ca";
	# 	helo=smtp.dostech.net; client-ip=69.61.78.188

	# Received-SPF: pass (dostech.ca: 69.61.78.188 is authorized to use 'dostech.ca'
	# 	in 'helo' identity (mechanism 'mx' matched)) receiver=FC5-VPC; identity=helo;
	# 	helo=dostech.ca; client-ip=69.61.78.188

	# http://www.openspf.org/RFC_4408#header-field
	# wtf - for some reason something is sticking an extra space between the header name and field value
	if ($hdr =~ /^received-spf:\s*(pass|neutral|(?:soft)?fail|(?:temp|perm)error|none)\b(?:.*\bidentity=(\S+?);?\b)?/i) {
	  my $result = lc($1);

	  my $identity = '';	# we assume it's a mfrom check if we can't tell otherwise
	  if (defined $2) {
	    $identity = lc($2);
	    if ($identity eq 'mfrom' || $identity eq 'mailfrom') {
	      next if $scanner->{spf_checked};
	      $identity = '';
	    } elsif ($identity eq 'helo') {
	      next if $scanner->{spf_helo_checked};
	      $identity = 'helo_';
	    } else {
	      dbg("spf: found unknown identity value, cannot use: $identity");
	      next;	# try the next Received-SPF header, if any
	    }
	  } else {
	    next if $scanner->{spf_checked};
	  }

	  # we'd set these if we actually did the check
	  $scanner->{"spf_${identity}checked"} = 1;
	  $scanner->{"spf_${identity}pass"} = 0;
	  $scanner->{"spf_${identity}neutral"} = 0;
	  $scanner->{"spf_${identity}none"} = 0;
	  $scanner->{"spf_${identity}fail"} = 0;
	  $scanner->{"spf_${identity}softfail"} = 0;
	  $scanner->{"spf_${identity}temperror"} = 0;
	  $scanner->{"spf_${identity}permerror"} = 0;
	  $scanner->{"spf_${identity}failure_comment"} = undef;

	  # and the result
	  $scanner->{"spf_${identity}${result}"} = 1;
	  dbg("spf: re-using %s result from Received-SPF header: %s",
              ($identity ? 'helo' : 'mfrom'), $result);

	  # if we've got *both* the mfrom and helo results we're done
	  return if ($scanner->{spf_checked} && $scanner->{spf_helo_checked});

	} else {
	  dbg("spf: could not parse result from existing Received-SPF header");
	}

      } elsif ($hdr =~ /^(?:Arc\-)?Authentication-Results:.*;\s*SPF\s*=\s*([^;]*)/i) {
        dbg("spf: found an Authentication-Results header added by an internal host: $hdr");

        # RFC 5451 header parser - added by D. Stussy 2010-09-09:
        # Authentication-Results: mail.example.com; SPF=none smtp.mailfrom=example.org (comment)

        my $tmphdr = $1;
        if ($tmphdr =~ /^(pass|neutral|(?:hard|soft)?fail|(?:temp|perm)error|none)(?:[^;]*?\bsmtp\.(\S+)\s*=[^;]+)?/i) {
          my $result = lc($1);
          $result = 'fail'  if $result eq 'hardfail';  # RFC5451 permits this

          my $identity = '';    # we assume it's a mfrom check if we can't tell otherwise
          if (defined $2) {
            $identity = lc($2);
            if ($identity eq 'mfrom' || $identity eq 'mailfrom') {
              next if $scanner->{spf_checked};
              $identity = '';
            } elsif ($identity eq 'helo') {
              next if $scanner->{spf_helo_checked};
              $identity = 'helo_';
            } else {
              dbg("spf: found unknown identity value, cannot use: $identity");
              next;     # try the next Authentication-Results header, if any
            }
          } else {
            next if $scanner->{spf_checked};
          }

          # we'd set these if we actually did the check
          $scanner->{"spf_${identity}checked"} = 1;
          $scanner->{"spf_${identity}pass"} = 0;
          $scanner->{"spf_${identity}neutral"} = 0;
          $scanner->{"spf_${identity}none"} = 0;
          $scanner->{"spf_${identity}fail"} = 0;
          $scanner->{"spf_${identity}softfail"} = 0;
          $scanner->{"spf_${identity}temperror"} = 0;
          $scanner->{"spf_${identity}permerror"} = 0;
          $scanner->{"spf_${identity}failure_comment"} = undef;

          # and the result
          $scanner->{"spf_${identity}${result}"} = 1;
          dbg("spf: re-using %s result from Authentication-Results header: %s",
               ($identity ? 'helo' : 'mfrom'), $result);

          # if we've got *both* the mfrom and helo results we're done
          return if ($scanner->{spf_checked} && $scanner->{spf_helo_checked});

        } else {
          dbg("spf: could not parse result from existing Authentication-Results header");
        }
      }
    }
    # we can return if we've found the one we're being asked to get
    return if ( ($ishelo && $scanner->{spf_helo_checked}) ||
		(!$ishelo && $scanner->{spf_checked}) );
  }

  # abort if dns or an spf module isn't available
  return unless $scanner->is_dns_available();
  return if $self->{no_spf_module};

  # select the SPF module we're going to use
  unless (defined $self->{has_mail_spf}) {
    my $eval_stat;
    eval {
      require Mail::SPF;
      if (!defined $Mail::SPF::VERSION || $Mail::SPF::VERSION < 2.001) {
	die "Mail::SPF 2.001 or later required, this is ".
	  (defined $Mail::SPF::VERSION ? $Mail::SPF::VERSION : 'unknown')."\n";
      }
      # Mail::SPF::Server can be re-used, and we get to use our own resolver object!
      $self->{spf_server} = Mail::SPF::Server->new(
				hostname     => $scanner->get_tag('HOSTNAME'),
				dns_resolver => $self->{main}->{resolver},
				max_dns_interactive_terms => 20);
      # Bug 7112: max_dns_interactive_terms defaults to 10, but even 14 is
      # not enough for ebay.com, setting it to 15 NOTE: raising to 20 per bug 7182
      1;
    } or do {
      $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    };

    if (!defined($eval_stat)) {
      dbg("spf: using Mail::SPF for SPF checks");
      $self->{has_mail_spf} = 1;
    } else {
      dbg("spf: cannot load Mail::SPF: module: $eval_stat");
      dbg("spf: Mail::SPF is required for SPF checks, SPF checks disabled");
      $self->{no_spf_module} = 1;
      return;
    }
  }

  # skip SPF checks if the A/MX records are nonexistent for the From
  # domain, anyway, to avoid crappy messages from slowing us down
  # (bug 3016)
  # TODO: this will only work if the queries are ready before SPF, so never?
  return if $scanner->{sender_host_fail} && $scanner->{sender_host_fail} == 2;

  if ($ishelo) {
    # SPF HELO-checking variant
    $scanner->{spf_helo_checked} = 1;
    $scanner->{spf_helo_pass} = 0;
    $scanner->{spf_helo_neutral} = 0;
    $scanner->{spf_helo_none} = 0;
    $scanner->{spf_helo_fail} = 0;
    $scanner->{spf_helo_softfail} = 0;
    $scanner->{spf_helo_permerror} = 0;
    $scanner->{spf_helo_temperror} = 0;
    $scanner->{spf_helo_failure_comment} = undef;
  } else {
    # SPF on envelope sender (where possible)
    $scanner->{spf_checked} = 1;
    $scanner->{spf_pass} = 0;
    $scanner->{spf_neutral} = 0;
    $scanner->{spf_none} = 0;
    $scanner->{spf_fail} = 0;
    $scanner->{spf_softfail} = 0;
    $scanner->{spf_permerror} = 0;
    $scanner->{spf_temperror} = 0;
    $scanner->{spf_failure_comment} = undef;
  }

  my $lasthop = $scanner->{relays_external}->[0];
  if (!defined $lasthop) {
    dbg("spf: no suitable relay for spf use found, skipping SPF%s check",
        $ishelo ? '-helo' : '');
    return;
  }

  my $ip = $lasthop->{ip};	# always present
  my $helo = $lasthop->{helo};	# could be missing

  if ($ishelo) {
    unless ($helo) {
      dbg("spf: cannot check HELO, HELO value unknown");
      return;
    }
    dbg("spf: checking HELO (helo=$helo, ip=$ip)");
  } else {
    # TODO: we're supposed to use the helo domain as the sender identity (for
    # mfrom checks) if the sender is the null sender, however determining that
    # it's the null sender, and not just a failure to get the envelope isn't
    # exactly trivial... so for now we'll just skip the check

    if (!$scanner->{spf_sender}) {
      # we already dbg'd that we couldn't get an Envelope-From and can't do SPF
      return;
    }
    dbg("spf: checking EnvelopeFrom (helo=%s, ip=%s, envfrom=%s)",
        ($helo ? $helo : ''), $ip, $scanner->{spf_sender});
  }

  # this test could probably stand to be more strict, but try to test
  # any invalid HELO hostname formats with a header rule
  if ($ishelo && ($helo =~ /^[\[!]?\d+\.\d+\.\d+\.\d+[\]!]?$/ || $helo =~ /^[^.]+$/)) {
    dbg("spf: cannot check HELO of '$helo', skipping");
    return;
  }

  if ($helo && $scanner->server_failed_to_respond_for_domain($helo)) {
    dbg("spf: we had a previous timeout on '$helo', skipping");
    return;
  }


  my ($result, $comment, $text, $err);

  # TODO: currently we won't get to here for a mfrom check with a null sender
  my $identity = $ishelo ? $helo : ($scanner->{spf_sender}); # || $helo);

  unless ($identity) {
    dbg("spf: cannot determine %s identity, skipping %s SPF check",
        ($ishelo ? 'helo' : 'mfrom'),  ($ishelo ? 'helo' : 'mfrom') );
    return;
  }
  $helo ||= 'unknown';  # only used for macro expansion in the mfrom explanation

  my $request;
  eval {
    $request = Mail::SPF::Request->new( scope => $ishelo ? 'helo' : 'mfrom',
			  identity      => $identity,
			  ip_address    => $ip,
			  helo_identity => $helo );
    1;
  } or do {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    dbg("spf: cannot create Mail::SPF::Request object: $eval_stat");
    return;
  };

  my $timeout = $scanner->{conf}->{spf_timeout};

  my $timer_spf = Mail::SpamAssassin::Timeout->new(
              { secs => $timeout, deadline => $scanner->{master_deadline} });
  $err = $timer_spf->run_and_catch(sub {
    my $query = $self->{spf_server}->process($request);
    $result = $query->code;
    $comment = $query->authority_explanation if $query->can("authority_explanation");
    $text = $query->text;
  });

  if ($err) {
    chomp $err;
    warn("spf: lookup failed: $err\n");
    return 0;
  }

  $result ||= 'timeout';	# bug 5077
  $comment ||= '';
  $comment =~ s/\s+/ /gs;	# no newlines please
  $text ||= '';
  $text =~ s/\s+/ /gs;		# no newlines please

  if ($ishelo) {
    if ($result eq 'pass') { $scanner->{spf_helo_pass} = 1; }
    elsif ($result eq 'neutral') { $scanner->{spf_helo_neutral} = 1; }
    elsif ($result eq 'none') { $scanner->{spf_helo_none} = 1; }
    elsif ($result eq 'fail') { $scanner->{spf_helo_fail} = 1; }
    elsif ($result eq 'softfail') { $scanner->{spf_helo_softfail} = 1; }
    elsif ($result eq 'permerror') { $scanner->{spf_helo_permerror} = 1; }
    elsif ($result eq 'temperror') { $scanner->{spf_helo_temperror} = 1; }
    elsif ($result eq 'error') { $scanner->{spf_helo_temperror} = 1; }

    if ($result eq 'fail') {	# RFC 7208 6.2
      $scanner->{spf_helo_failure_comment} = "SPF failed: $comment";
    }
  } else {
    if ($result eq 'pass') { $scanner->{spf_pass} = 1; }
    elsif ($result eq 'neutral') { $scanner->{spf_neutral} = 1; }
    elsif ($result eq 'none') { $scanner->{spf_none} = 1; }
    elsif ($result eq 'fail') { $scanner->{spf_fail} = 1; }
    elsif ($result eq 'softfail') { $scanner->{spf_softfail} = 1; }
    elsif ($result eq 'permerror') { $scanner->{spf_permerror} = 1; }
    elsif ($result eq 'temperror') { $scanner->{spf_temperror} = 1; }
    elsif ($result eq 'error') { $scanner->{spf_temperror} = 1; }

    if ($result eq 'fail') {	# RFC 7208 6.2
      $scanner->{spf_failure_comment} = "SPF failed: $comment";
    }
  }

  if ($ishelo) {
    dbg("spf: query for $ip/$helo: result: $result, comment: $comment, text: $text");
  } else {
    dbg("spf: query for $scanner->{spf_sender}/$ip/$helo: result: $result, comment: $comment, text: $text");
  }
}

sub _get_sender {
  my ($self, $scanner) = @_;

  my $relay = $scanner->{relays_external}->[0];
  if (defined $relay) {
    my $sender = $relay->{envfrom};
    if (defined $sender) {
      dbg("spf: found EnvelopeFrom '$sender' in first external Received header");	
      $scanner->{spf_sender} = lc $sender;
    } else {
      dbg("spf: EnvelopeFrom not found in first external Received header");
    }
  }

  if (!exists $scanner->{spf_sender}) {
    # We cannot use the env-from data, since it went through 1 or more relays 
    # since the untrusted sender and they may have rewritten it.
    if ($scanner->{num_relays_trusted} > 0 &&
          !$scanner->{conf}->{always_trust_envelope_sender}) {
      dbg("spf: relayed through one or more trusted relays, ".
            "cannot use header-based EnvelopeFrom");
    } else {
      # we can (apparently) use whatever the current EnvelopeFrom was,
      # from the Return-Path, X-Envelope-From, or whatever header.
      # it's better to get it from Received though, as that is updated
      # hop-by-hop.
      my $sender = ($scanner->get("EnvelopeFrom:addr"))[0];
      if (defined $sender) {
        dbg("spf: found EnvelopeFrom '$sender' from header");
        $scanner->{spf_sender} = lc $sender;
      } else {
        dbg("spf: EnvelopeFrom header not found");
      }
    }
  }

  if (!exists $scanner->{spf_sender}) {
    dbg("spf: cannot get EnvelopeFrom, cannot use SPF by DNS");
  }
}

sub _check_spf_welcomelist {
  my ($self, $scanner) = @_;

  $scanner->{spf_welcomelist_from_checked} = 1;
  $scanner->{spf_welcomelist_from} = 0;

  # if we've already checked for an SPF PASS and didn't get it don't waste time
  # checking to see if the sender address is in the spf welcomelist
  if ($scanner->{spf_checked} && !$scanner->{spf_pass}) {
    dbg("spf: welcomelist_from_spf: already checked spf and didn't get pass, skipping welcomelist check");
    return;
  }

  if (!$scanner->{spf_sender}) {
    dbg("spf: spf_welcomelist_from: no EnvelopeFrom available for welcomelist check");
    return;
  }

  $scanner->{spf_welcomelist_from} =
    $self->_wlcheck($scanner, 'welcomelist_from_spf') ||
    $self->_wlcheck($scanner, 'welcomelist_auth');

  # if the message doesn't pass SPF validation, it can't pass an SPF welcomelist
  if ($scanner->{spf_welcomelist_from}) {
    if ($self->check_for_spf_pass($scanner)) {
      dbg("spf: welcomelist_from_spf: $scanner->{spf_sender} is in user's WELCOMELIST_FROM_SPF and passed SPF check");
    } else {
      dbg("spf: welcomelist_from_spf: $scanner->{spf_sender} is in user's WELCOMELIST_FROM_SPF but failed SPF check");
      $scanner->{spf_welcomelist_from} = 0;
    }
  } else {
    dbg("spf: welcomelist_from_spf: $scanner->{spf_sender} is not in user's WELCOMELIST_FROM_SPF");
  }
}

sub _check_def_spf_welcomelist {
  my ($self, $scanner) = @_;

  $scanner->{def_spf_welcomelist_from_checked} = 1;
  $scanner->{def_spf_welcomelist_from} = 0;

  # if we've already checked for an SPF PASS and didn't get it don't waste time
  # checking to see if the sender address is in the spf welcomelist
  if ($scanner->{spf_checked} && !$scanner->{spf_pass}) {
    dbg("spf: def_spf_welcomelist_from: already checked spf and didn't get pass, skipping welcomelist check");
    return;
  }

  if (!$scanner->{spf_sender}) {
    dbg("spf: def_spf_welcomelist_from: could not find usable envelope sender");
    return;
  }

  $scanner->{def_spf_welcomelist_from} =
    $self->_wlcheck($scanner, 'def_welcomelist_from_spf') ||
    $self->_wlcheck($scanner, 'def_welcomelist_auth');

  # if the message doesn't pass SPF validation, it can't pass an SPF welcomelist
  if ($scanner->{def_spf_welcomelist_from}) {
    if ($self->check_for_spf_pass($scanner)) {
      dbg("spf: def_welcomelist_from_spf: $scanner->{spf_sender} is in DEF_WELCOMELIST_FROM_SPF and passed SPF check");
    } else {
      dbg("spf: def_welcomelist_from_spf: $scanner->{spf_sender} is in DEF_WELCOMELIST_FROM_SPF but failed SPF check");
      $scanner->{def_spf_welcomelist_from} = 0;
    }
  } else {
    dbg("spf: def_welcomelist_from_spf: $scanner->{spf_sender} is not in DEF_WELCOMELIST_FROM_SPF");
  }
}

sub _wlcheck {
  my ($self, $scanner, $param) = @_;
  if (defined ($scanner->{conf}->{$param}->{$scanner->{spf_sender}})) {
    return 1;
  } else {
    foreach my $regexp (values %{$scanner->{conf}->{$param}}) {
      if ($scanner->{spf_sender} =~ $regexp) {
        return 1;
      }
    }
  }
  return 0;
}

###########################################################################

1;

=back

=cut
