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

=cut

package Mail::SpamAssassin::Plugin::SPF;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;
use strict;
use warnings;
use bytes;
use re 'taint';

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule ("check_for_spf_pass");
  $self->register_eval_rule ("check_for_spf_neutral");
  $self->register_eval_rule ("check_for_spf_none");
  $self->register_eval_rule ("check_for_spf_fail");
  $self->register_eval_rule ("check_for_spf_softfail");
  $self->register_eval_rule ("check_for_spf_permerror");
  $self->register_eval_rule ("check_for_spf_temperror");
  $self->register_eval_rule ("check_for_spf_helo_pass");
  $self->register_eval_rule ("check_for_spf_helo_neutral");
  $self->register_eval_rule ("check_for_spf_helo_none");
  $self->register_eval_rule ("check_for_spf_helo_fail");
  $self->register_eval_rule ("check_for_spf_helo_softfail");
  $self->register_eval_rule ("check_for_spf_helo_permerror");
  $self->register_eval_rule ("check_for_spf_helo_temperror");
  $self->register_eval_rule ("check_for_spf_whitelist_from");
  $self->register_eval_rule ("check_for_def_spf_whitelist_from");

  $self->set_config($mailsaobject->{conf});

  return $self;
}

###########################################################################

sub set_config {
  my($self, $conf) = @_;
  my @cmds;

=head1 USER SETTINGS

=over 4

=item whitelist_from_spf user@example.com

Works similarly to whitelist_from, except that in addition to matching
a sender address, a check against the domain's SPF record must pass.
The first parameter is an address to whitelist, and the second is a string
to match the relay's rDNS.

Just like whitelist_from, multiple addresses per line, separated by spaces,
are OK. Multiple C<whitelist_from_spf> lines are also OK.

The headers checked for whitelist_from_spf addresses are the same headers
used for SPF checks (Envelope-From, Return-Path, X-Envelope-From, etc).

Since this whitelist requires an SPF check to be made, network tests must be
enabled. It is also required that your trust path be correctly configured.
See the section on C<trusted_networks> for more info on trust paths.

e.g.

  whitelist_from_spf joe@example.com fred@example.com
  whitelist_from_spf *@example.com

=item def_whitelist_from_spf user@example.com

Same as C<whitelist_from_spf>, but used for the default whitelist entries
in the SpamAssassin distribution.  The whitelist score is lower, because
these are often targets for spammer spoofing.

=cut

  push (@cmds, {
    setting => 'whitelist_from_spf',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST
  });

  push (@cmds, {
    setting => 'def_whitelist_from_spf',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST
  });

=back

=head1 ADMINISTRATOR OPTIONS

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

=item do_not_use_mail_spf (0|1)		(default: 0)

By default the plugin will try to use the Mail::SPF module for SPF checks if
it can be loaded.  If Mail::SPF cannot be used the plugin will fall back to
using the legacy Mail::SPF::Query module if it can be loaded.

Use this option to stop the plugin from using Mail::SPF and cause it to try to
use Mail::SPF::Query instead.

=cut

  push(@cmds, {
    setting => 'do_not_use_mail_spf',
    is_admin => 1,
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });

=item do_not_use_mail_spf_query (0|1)	(default: 0)

As above, but instead stop the plugin from trying to use Mail::SPF::Query and
cause it to only try to use Mail::SPF.

=cut

  push(@cmds, {
    setting => 'do_not_use_mail_spf_query',
    is_admin => 1,
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
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

  $conf->{parser}->register_commands(\@cmds);
}


=item has_check_for_spf_errors

Adds capability check for "if can()" for check_for_spf_permerror, check_for_spf_temperror, check_for_spf_helo_permerror and check_for_spf_helo_permerror
  
=cut 

sub has_check_for_spf_errors { 1 }

# SPF support
sub check_for_spf_pass {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  $scanner->{spf_pass};
}

sub check_for_spf_neutral {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  $scanner->{spf_neutral};
}

sub check_for_spf_none {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  $scanner->{spf_none};
}

sub check_for_spf_fail {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  if ($scanner->{spf_failure_comment}) {
    $scanner->test_log ($scanner->{spf_failure_comment});
  }
  $scanner->{spf_fail};
}

sub check_for_spf_softfail {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  $scanner->{spf_softfail};
}

sub check_for_spf_permerror {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  $scanner->{spf_permerror};
}

sub check_for_spf_temperror {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  $scanner->{spf_temperror};
}

sub check_for_spf_helo_pass {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  $scanner->{spf_helo_pass};
}

sub check_for_spf_helo_neutral {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  $scanner->{spf_helo_neutral};
}

sub check_for_spf_helo_none {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  $scanner->{spf_helo_none};
}

sub check_for_spf_helo_fail {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  if ($scanner->{spf_helo_failure_comment}) {
    $scanner->test_log ($scanner->{spf_helo_failure_comment});
  }
  $scanner->{spf_helo_fail};
}

sub check_for_spf_helo_softfail {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  $scanner->{spf_helo_softfail};
}

sub check_for_spf_helo_permerror {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  $scanner->{spf_helo_permerror};
}

sub check_for_spf_helo_temperror {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  $scanner->{spf_helo_temperror};
}

sub check_for_spf_whitelist_from {
  my ($self, $scanner) = @_;
  $self->_check_spf_whitelist($scanner) unless $scanner->{spf_whitelist_from_checked};
  $scanner->{spf_whitelist_from};
}

sub check_for_def_spf_whitelist_from {
  my ($self, $scanner) = @_;
  $self->_check_def_spf_whitelist($scanner) unless $scanner->{def_spf_whitelist_from_checked};
  $scanner->{def_spf_whitelist_from};
}

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

    my @internal_hdrs = split("\n", $scanner->get('ALL-INTERNAL'));
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
	if ($hdr =~ /^received-spf:\s*(pass|neutral|(?:soft)?fail|none)\b(?:.*\bidentity=(\S+?);?\b)?/i) {
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

      } elsif ($hdr =~ /^Authentication-Results:.*;\s*SPF\s*=\s*([^;]*)/i) {
        dbg("spf: found an Authentication-Results header added by an internal host: $hdr");

        # RFC 5451 header parser - added by D. Stussy 2010-09-09:
        # Authentication-Results: mail.example.com; SPF=none smtp.mailfrom=example.org (comment)

        my $tmphdr = $1;
        if ($tmphdr =~ /^(pass|neutral|(?:hard|soft)?fail|none)(?:[^;]*?\bsmtp\.(\S+)\s*=[^;]+)?/i) {
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
      die("Mail::SPF disabled by admin setting\n") if $scanner->{conf}->{do_not_use_mail_spf};

      require Mail::SPF;
      if (!defined $Mail::SPF::VERSION || $Mail::SPF::VERSION < 2.001) {
	die "Mail::SPF 2.001 or later required, this is ".
	  (defined $Mail::SPF::VERSION ? $Mail::SPF::VERSION : 'unknown')."\n";
      }
      # Mail::SPF::Server can be re-used, and we get to use our own resolver object!
      $self->{spf_server} = Mail::SPF::Server->new(
				hostname     => $scanner->get_tag('HOSTNAME'),
				dns_resolver => $self->{main}->{resolver},
				max_dns_interactive_terms => 15);
      # Bug 7112: max_dns_interactive_terms defaults to 10, but even 14 is
      # not enough for ebay.com, setting it to 15
      1;
    } or do {
      $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    };

    if (!defined($eval_stat)) {
      dbg("spf: using Mail::SPF for SPF checks");
      $self->{has_mail_spf} = 1;
    } else {
      # strip the @INC paths... users are going to see it and think there's a problem even though
      # we're going to fall back to Mail::SPF::Query (which will display the same paths if it fails)
      $eval_stat =~ s#^Can't locate Mail/SPFd.pm in \@INC .*#Can't locate Mail/SPFd.pm#;
      dbg("spf: cannot load Mail::SPF module or create Mail::SPF::Server object: $eval_stat");
      dbg("spf: attempting to use legacy Mail::SPF::Query module instead");

      undef $eval_stat;
      eval {
	die("Mail::SPF::Query disabled by admin setting\n") if $scanner->{conf}->{do_not_use_mail_spf_query};

	require Mail::SPF::Query;
	if (!defined $Mail::SPF::Query::VERSION || $Mail::SPF::Query::VERSION < 1.996) {
	  die "Mail::SPF::Query 1.996 or later required, this is ".
	    (defined $Mail::SPF::Query::VERSION ? $Mail::SPF::Query::VERSION : 'unknown')."\n";
	}
        1;
      } or do {
        $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
      };

      if (!defined($eval_stat)) {
	dbg("spf: using Mail::SPF::Query for SPF checks");
	$self->{has_mail_spf} = 0;
      } else {
	dbg("spf: cannot load Mail::SPF::Query module: $eval_stat");
	dbg("spf: one of Mail::SPF or Mail::SPF::Query is required for SPF checks, SPF checks disabled");
	$self->{no_spf_module} = 1;
	return;
      }
    }
  }


  # skip SPF checks if the A/MX records are nonexistent for the From
  # domain, anyway, to avoid crappy messages from slowing us down
  # (bug 3016)
  return if $scanner->check_for_from_dns();

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

  my $lasthop = $self->_get_relay($scanner);
  if (!defined $lasthop) {
    dbg("spf: no suitable relay for spf use found, skipping SPF%s check",
        $ishelo ? '-helo' : '');
    return;
  }

  my $ip = $lasthop->{ip};	# always present
  my $helo = $lasthop->{helo};	# could be missing
  $scanner->{sender} = '' unless $scanner->{sender_got};

  if ($ishelo) {
    unless ($helo) {
      dbg("spf: cannot check HELO, HELO value unknown");
      return;
    }
    dbg("spf: checking HELO (helo=$helo, ip=$ip)");
  } else {
    $self->_get_sender($scanner) unless $scanner->{sender_got};

    # TODO: we're supposed to use the helo domain as the sender identity (for
    # mfrom checks) if the sender is the null sender, however determining that
    # it's the null sender, and not just a failure to get the envelope isn't
    # exactly trivial... so for now we'll just skip the check

    if (!$scanner->{sender}) {
      # we already dbg'd that we couldn't get an Envelope-From and can't do SPF
      return;
    }
    dbg("spf: checking EnvelopeFrom (helo=%s, ip=%s, envfrom=%s)",
        ($helo ? $helo : ''), $ip, $scanner->{sender});
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

  # use Mail::SPF if it was available, otherwise use the legacy Mail::SPF::Query
  if ($self->{has_mail_spf}) {

    # TODO: currently we won't get to here for a mfrom check with a null sender
    my $identity = $ishelo ? $helo : ($scanner->{sender}); # || $helo);

    unless ($identity) {
      dbg("spf: cannot determine %s identity, skipping %s SPF check",
          ($ishelo ? 'helo' : 'mfrom'),  ($ishelo ? 'helo' : 'mfrom') );
      return;
    }
    $helo ||= 'unknown';  # only used for macro expansion in the mfrom explanation

    my $request;
    eval {
      $request = Mail::SPF::Request->new( scope         => $ishelo ? 'helo' : 'mfrom',
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

    my $timer = Mail::SpamAssassin::Timeout->new(
                { secs => $timeout, deadline => $scanner->{master_deadline} });
    $err = $timer->run_and_catch(sub {

      my $query = $self->{spf_server}->process($request);

      $result = $query->code;
      $comment = $query->authority_explanation if $query->can("authority_explanation");
      $text = $query->text;

    });


  } else {

    if (!$helo) {
      dbg("spf: cannot get HELO, cannot use Mail::SPF::Query, consider installing Mail::SPF");
      return;
    }

    # TODO: if we start doing checks on the null sender using the helo domain
    # be sure to fix this so that it uses the correct sender identity
    my $query;
    eval {
      $query = Mail::SPF::Query->new (ip => $ip,
				    sender => $scanner->{sender},
				    helo => $helo,
				    debug => 0,
				    trusted => 0);
      1;
    } or do {
      my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
      dbg("spf: cannot create Mail::SPF::Query object: $eval_stat");
      return;
    };

    my $timeout = $scanner->{conf}->{spf_timeout};

    my $timer = Mail::SpamAssassin::Timeout->new(
                { secs => $timeout, deadline => $scanner->{master_deadline} });
    $err = $timer->run_and_catch(sub {

      ($result, $comment) = $query->result();

    });

  } # end of differences between Mail::SPF and Mail::SPF::Query

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

    if ($result eq 'fail') {	# RFC 4408 6.2
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

    if ($result eq 'fail') {	# RCF 4408 6.2
      $scanner->{spf_failure_comment} = "SPF failed: $comment";
    }
  }

  dbg("spf: query for $scanner->{sender}/$ip/$helo: result: $result, comment: $comment, text: $text");
}

sub _get_relay {
  my ($self, $scanner) = @_;

  # dos: first external relay, not first untrusted
  return $scanner->{relays_external}->[0];
}

sub _get_sender {
  my ($self, $scanner) = @_;
  my $sender;

  $scanner->{sender_got} = 1;
  $scanner->{sender} = '';

  my $relay = $self->_get_relay($scanner);
  if (defined $relay) {
    $sender = $relay->{envfrom};
  }

  if ($sender) {
    dbg("spf: found Envelope-From in first external Received header");
  }
  else {
    # We cannot use the env-from data, since it went through 1 or more relays 
    # since the untrusted sender and they may have rewritten it.
    if ($scanner->{num_relays_trusted} > 0 && !$scanner->{conf}->{always_trust_envelope_sender}) {
      dbg("spf: relayed through one or more trusted relays, cannot use header-based Envelope-From, skipping");
      return;
    }

    # we can (apparently) use whatever the current Envelope-From was,
    # from the Return-Path, X-Envelope-From, or whatever header.
    # it's better to get it from Received though, as that is updated
    # hop-by-hop.
    $sender = $scanner->get("EnvelopeFrom:addr");
  }

  if (!$sender) {
    dbg("spf: cannot get Envelope-From, cannot use SPF");
    return;  # avoid setting $scanner->{sender} to undef
  }

  return $scanner->{sender} = lc $sender;
}

sub _check_spf_whitelist {
  my ($self, $scanner) = @_;

  $scanner->{spf_whitelist_from_checked} = 1;
  $scanner->{spf_whitelist_from} = 0;

  # if we've already checked for an SPF PASS and didn't get it don't waste time
  # checking to see if the sender address is in the spf whitelist
  if ($scanner->{spf_checked} && !$scanner->{spf_pass}) {
    dbg("spf: whitelist_from_spf: already checked spf and didn't get pass, skipping whitelist check");
    return;
  }

  $self->_get_sender($scanner) unless $scanner->{sender_got};

  unless ($scanner->{sender}) {
    dbg("spf: spf_whitelist_from: could not find useable envelope sender");
    return;
  }

  $scanner->{spf_whitelist_from} = $self->_wlcheck($scanner,'whitelist_from_spf');
  if (!$scanner->{spf_whitelist_from}) {
    $scanner->{spf_whitelist_from} = $self->_wlcheck($scanner, 'whitelist_auth');
  }

  # if the message doesn't pass SPF validation, it can't pass an SPF whitelist
  if ($scanner->{spf_whitelist_from}) {
    if ($self->check_for_spf_pass($scanner)) {
      dbg("spf: whitelist_from_spf: $scanner->{sender} is in user's WHITELIST_FROM_SPF and passed SPF check");
    } else {
      dbg("spf: whitelist_from_spf: $scanner->{sender} is in user's WHITELIST_FROM_SPF but failed SPF check");
      $scanner->{spf_whitelist_from} = 0;
    }
  } else {
    dbg("spf: whitelist_from_spf: $scanner->{sender} is not in user's WHITELIST_FROM_SPF");
  }
}

sub _check_def_spf_whitelist {
  my ($self, $scanner) = @_;

  $scanner->{def_spf_whitelist_from_checked} = 1;
  $scanner->{def_spf_whitelist_from} = 0;

  # if we've already checked for an SPF PASS and didn't get it don't waste time
  # checking to see if the sender address is in the spf whitelist
  if ($scanner->{spf_checked} && !$scanner->{spf_pass}) {
    dbg("spf: def_spf_whitelist_from: already checked spf and didn't get pass, skipping whitelist check");
    return;
  }

  $self->_get_sender($scanner) unless $scanner->{sender_got};

  unless ($scanner->{sender}) {
    dbg("spf: def_spf_whitelist_from: could not find useable envelope sender");
    return;
  }

  $scanner->{def_spf_whitelist_from} = $self->_wlcheck($scanner,'def_whitelist_from_spf');
  if (!$scanner->{def_spf_whitelist_from}) {
    $scanner->{def_spf_whitelist_from} = $self->_wlcheck($scanner, 'def_whitelist_auth');
  }

  # if the message doesn't pass SPF validation, it can't pass an SPF whitelist
  if ($scanner->{def_spf_whitelist_from}) {
    if ($self->check_for_spf_pass($scanner)) {
      dbg("spf: def_whitelist_from_spf: $scanner->{sender} is in DEF_WHITELIST_FROM_SPF and passed SPF check");
    } else {
      dbg("spf: def_whitelist_from_spf: $scanner->{sender} is in DEF_WHITELIST_FROM_SPF but failed SPF check");
      $scanner->{def_spf_whitelist_from} = 0;
    }
  } else {
    dbg("spf: def_whitelist_from_spf: $scanner->{sender} is not in DEF_WHITELIST_FROM_SPF");
  }
}

sub _wlcheck {
  my ($self, $scanner, $param) = @_;
  if (defined ($scanner->{conf}->{$param}->{$scanner->{sender}})) {
    return 1;
  } else {
    study $scanner->{sender};  # study is a no-op since perl 5.16.0
    foreach my $regexp (values %{$scanner->{conf}->{$param}}) {
      if ($scanner->{sender} =~ qr/$regexp/i) {
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
