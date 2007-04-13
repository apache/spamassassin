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

Mail::SpamAssassin::Plugin::DomainKeys - perform DomainKeys verification tests

=head1 SYNOPSIS

 loadplugin Mail::SpamAssassin::Plugin::DomainKeys [/path/to/DomainKeys.pm]

Signature:
 header DK_SIGNED                eval:check_domainkeys_signed()
 header DK_VERIFIED              eval:check_domainkeys_verified()

Policy:
   Note that DK policy record is only fetched if DK_VERIFIED is
   false to save a signing domain from unnecessary DNS queries,
   as recommended (SHOULD) by draft-delany-domainkeys-base.
   Rules DK_POLICY_* should preferably not be relied upon when
   DK_VERIFIED is true, although they will return false in current
   implementation when a policy record is not fetched, except for
   DK_POLICY_TESTING, which is true if t=y appears in a public key
   record OR in a policy record (when available).
 header DK_POLICY_TESTING        eval:check_domainkeys_testing()
 header DK_POLICY_SIGNSOME       eval:check_domainkeys_signsome()
 header DK_POLICY_SIGNALL        eval:check_domainkeys_signall()

Whitelisting based on verified signature:
 header USER_IN_DK_WHITELIST     eval:check_for_dk_whitelist_from()
 header USER_IN_DEF_DK_WL        eval:check_for_def_dk_whitelist_from()

=head1 DESCRIPTION

This is the DomainKeys plugin and it needs lots more documentation.

Note that if the C<Mail::SpamAssassin::Plugin::DKIM> plugin is installed with
C<Mail::DKIM> version 0.20 or later, that plugin will also perform Domain Key
lookups on DomainKey-Signature headers, in which case this plugin is redundant.


Here is author's note from module C<Mail::DomainKeys> version 1.0:

  THIS MODULE IS OFFICIALLY UNSUPPORTED.

  Please move on to DKIM like a responsible Internet user.  I have.

  I will leave this module here on CPAN for a while, just in case someone
  has grown to depend on it.  It is apparent that DK will not be the way
  of the future. Thus, it is time to put this module to ground before it
  causes any further harm.

  Thanks for your support,
  Anthony

=cut

package Mail::SpamAssassin::Plugin::DomainKeys;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;

use strict;
use warnings;
use bytes;

# Have to do this so that RPM doesn't find these as required perl modules
BEGIN { require Mail::DomainKeys::Message; require Mail::DomainKeys::Policy; }

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule ("check_domainkeys_signed");
  $self->register_eval_rule ("check_domainkeys_verified");
  $self->register_eval_rule ("check_domainkeys_signsome");
  $self->register_eval_rule ("check_domainkeys_testing");
  $self->register_eval_rule ("check_domainkeys_signall");
  $self->register_eval_rule ("check_for_dk_whitelist_from");
  $self->register_eval_rule ("check_for_def_dk_whitelist_from");

  $self->set_config($mailsaobject->{conf});

  return $self;
}

###########################################################################

sub set_config {
  my($self, $conf) = @_;
  my @cmds = ();

=head1 USER SETTINGS

=over 4

=item whitelist_from_dk add@ress.com [signing domain name]

Use this to supplement the whitelist_from addresses with a check to make sure
the message has been signed by a DomainKeys signature that can be verified
against the From: domain's DomainKeys public key.

In order to support signing domain names that differ from the address domain
name, only one whitelist entry is allowed per line, exactly like
C<whitelist_from_rcvd>.  Multiple C<whitelist_from_dk> lines are allowed.  
File-glob style meta characters are allowed for the From: address, just like
with C<whitelist_from_rcvd>.  The optional signing domain name parameter must
match from the right-most side, also like in C<whitelist_from_rcvd>.

If no signing domain name parameter is specified the domain of the address
parameter specified will be used instead.

The From: address is obtained from a signed part of the message (ie. the
"From:" header), not from envelope data that is possible to forge.

Since this whitelist requires a DomainKeys check to be made, network tests must
be enabled.

Examples:

  whitelist_from_dk joe@example.com
  whitelist_from_dk *@corp.example.com

  whitelist_from_dk bob@it.example.net  example.net
  whitelist_from_dk *@eng.example.net   example.net

=item def_whitelist_from_dk add@ress.com [signing domain name]

Same as C<whitelist_from_dk>, but used for the default whitelist entries
in the SpamAssassin distribution.  The whitelist score is lower, because
these are often targets for spammer spoofing.

=cut

  push (@cmds, {
    setting => 'whitelist_from_dk',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
	return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^(\S+)(?:\s+(\S+))?$/) {
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $address = $1;
      my $signer = (defined $2 ? $2 : $1);

      unless (defined $2) {
	$signer =~ s/^.*@(.*)$/$1/;
      }
      $self->{parser}->add_to_addrlist_rcvd ('whitelist_from_dk',
						$address, $signer);
    }
  });

  push (@cmds, {
    setting => 'def_whitelist_from_dk',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
	return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^(\S+)(?:\s+(\S+))?$/) {
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $address = $1;
      my $signer = (defined $2 ? $2 : $1);

      unless (defined $2) {
	$signer =~ s/^.*@(.*)$/$1/;
      }
      $self->{parser}->add_to_addrlist_rcvd ('def_whitelist_from_dk',
						$address, $signer);
    }
  });

=back

=head1 ADMINISTRATOR SETTINGS

=over 4

=item domainkeys_timeout n             (default: 5)

How many seconds to wait for a DomainKeys query to complete, before
scanning continues without the DomainKeys result.

=cut

  push (@cmds, {
    setting => 'domainkeys_timeout',
    is_admin => 1,
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

  $conf->{parser}->register_commands(\@cmds);
}


sub check_domainkeys_signed {
  my ($self, $scan) = @_;

  $self->_check_domainkeys($scan) unless $scan->{domainkeys_checked};
  
  return $scan->{domainkeys_signed};
}

sub check_domainkeys_verified {
  my ($self, $scan) = @_;

  $self->_check_domainkeys($scan) unless $scan->{domainkeys_checked};
  
  return $scan->{domainkeys_verified};
}

sub check_domainkeys_signsome {
  my ($self, $scan) = @_;

  $self->_check_domainkeys($scan) unless $scan->{domainkeys_checked};
  return $scan->{domainkeys_signsome};
}

sub check_domainkeys_testing {
  my ($self, $scan) = @_;

  $self->_check_domainkeys($scan) unless $scan->{domainkeys_checked};
  
  return $scan->{domainkeys_testing};
}

sub check_domainkeys_signall {
  my ($self, $scan) = @_;

  $self->_check_domainkeys($scan) unless $scan->{domainkeys_checked};
  
  return $scan->{domainkeys_signall};
}

sub check_for_dk_whitelist_from {
  my ($self, $scan) = @_;
  $self->_check_dk_whitelist($scan, 0) unless $scan->{dk_whitelist_from_checked};
  $scan->{dk_whitelist_from};
}

sub check_for_def_dk_whitelist_from {
  my ($self, $scan) = @_;
  $self->_check_dk_whitelist($scan, 1) unless $scan->{def_dk_whitelist_from_checked};
  $scan->{def_dk_whitelist_from};
}

# ---------------------------------------------------------------------------

sub _check_domainkeys {
  my ($self, $scan) = @_;

  $scan->{domainkeys_checked} = 0;
  $scan->{domainkeys_signed} = 0;
  $scan->{domainkeys_verified} = 0;
  $scan->{domainkeys_signsome} = 0;
  $scan->{domainkeys_testing} = 0;
  $scan->{domainkeys_signall} = 0;

  my $header = $scan->{msg}->get_pristine_header();
  my $body = $scan->{msg}->get_body();
  my $dksighdr = $scan->{msg}->get_header("DomainKey-Signature");
  dbg("dk: signature: $dksighdr")  if defined $dksighdr;

  $self->sanitize_header_for_dk(\$header)
    if defined $dksighdr && $dksighdr !~ /(?:^|;)[ \t]*h=/;  # case sensitive

  my $message = Mail::DomainKeys::Message->load(HeadString => $header,
						 BodyReference => $body);

  if (!$message) {
    dbg("dk: cannot load message using Mail::DomainKeys::Message");
    return;
  }

  $scan->{domainkeys_checked} = 1;

  # does a sender domain header exist?
  my $domain = $message->senderdomain();
  if (!$domain) {
    dbg("dk: no sender domain");
    return;
  }

  # get the sender address for whitelist checks
  if (defined $message->sender()) {
    $scan->{dk_address} = @{$message->sender()}[1];
    dbg("dk: sender: $scan->{dk_address}");
  } elsif (defined $message->from()) {
    $scan->{dk_address} ||= @{$message->from()}[1];
    dbg("dk: from: $scan->{dk_address}");
  } else {
    dbg("dk: could not determine sender: or from: identity");
  }

  # get the signing domain name for whitelist checks
  $scan->{dk_signing_domain} = $self->_dkmsg_signing_domain($scan, $message);
  dbg("dk: signing domain name: ".
    ($scan->{dk_signing_domain} ? $scan->{dk_signing_domain} : "not found"));

  my $timeout = $scan->{conf}->{domainkeys_timeout};

  my $timer = Mail::SpamAssassin::Timeout->new({ secs => $timeout });
  my $err = $timer->run_and_catch(sub {

    $self->_dk_lookup_trapped($scan, $message, $domain);

  });

  if ($timer->timed_out()) {
    dbg("dk: lookup timed out after $timeout seconds");
    return 0;
  }

  if ($err) {
    chomp $err;
    warn("dk: lookup failed: $err\n");
    return 0;
  }

  my $comment = $self->_dkmsg_hdr($message);
  $comment ||= '';
  $comment =~ s/\s+/ /gs;       # no newlines please

  $scan->{dk_comment} = "DomainKeys status: $comment";
}

# perform DK lookups.  This method is trapped within a timeout alarm() scope
sub _dk_lookup_trapped {
  my ($self, $scan, $message, $domain) = @_;

  # verified
  if ($message->signed()) {
    $scan->{domainkeys_signed} = 1;
    if ($message->verify()) {
      $scan->{domainkeys_verified} = 1;
    }
  }
  # testing flag in signature
  if ($message->testing()) {
    $scan->{domainkeys_testing} = 1;
  }
  my $policy;
  if (!$scan->{domainkeys_verified}) {
    # Recipient systems SHOULD not retrieve a policy TXT record
    # for email that successfully verifies.
    $policy = Mail::DomainKeys::Policy->fetch(Protocol => 'dns',
					      Domain => $domain);
    my($fetched_policy) = $policy ? $policy->as_string : 'NONE';
    $fetched_policy = ''  if !defined $fetched_policy;
    dbg ("dk: fetched policy for domain $domain: $fetched_policy");
  }
  return unless $policy;

  # not signed and domain doesn't sign all
  if ($policy->signsome()) {
    $scan->{domainkeys_signsome} = 1;
  }

  # testing flag in policy
  if ($policy->testing()) {
    $scan->{domainkeys_testing} = 1;
  }

  # does policy require all mail to be signed
  if ($policy->signall()) {
    $scan->{domainkeys_signall} = 1;
  }

  my $comment = $self->_dkmsg_hdr($message);
  dbg("dk: comment is '$comment'");
}

# get the DK status "header" from the Mail::DomainKeys::Message object
sub _dkmsg_hdr {
  my ($self, $message) = @_;
  # try to use the signature() API if it exists (post-0.80)
  if ($message->can("signature")) {
    my($sts,$msg);
    if (!$message->signed) {
      $sts = "no signature";
    } else {
      $sts = $message->signature->status;
      $msg = $message->signature->errorstr;
    }
    dbg("dk: $sts" . (defined $msg ? " ($msg)" : ''));
    return $sts;
  } else {
    return $message->header->value;
  }
}

# get the DK signing domain name from the Mail::DomainKeys::Message object
sub _dkmsg_signing_domain {
  my ($self, $scan, $message) = @_;
  # try to use the signature() API if it exists (post-0.80)
  if ($message->can("signature")) {
    if (!$message->signed) {
      return undef;
    }
    return $message->signature->domain;
  } else {
    # otherwise parse it ourself
    if ($scan->{msg}->get_header("DomainKey-Signature") =~
        /(?: ^|; ) [ \t]* d= [ \t]* ([^;]*?) [ \t]* (?: ;|$ )/x) {
      return $1;
    }
    return undef;
  }
}

sub sanitize_header_for_dk {
  my ($self, $ref) = @_;

  dbg("dk: sanitizing header, no \"h\" tag in signature");
  # remove folding, in a HTML-escape data-preserving style, so we can
  # strip headers easily
  $$ref =~ s/!/!ex;/gs;
  $$ref =~ s/\n([ \t])/!nl;$1/gs;
  my @hdrs = split(/^/m, $$ref);

  while (scalar @hdrs > 0) {
    my $last = pop @hdrs;
    next if ($last =~ /^\r?$/);

    # List all the known appended headers that may break a DK signature. Things
    # to note:
    # 
    # 1. only *appended* headers should be listed; prepended additions are fine.
    # 2. some virus-scanner headers may be better left out, since there are ISPs
    # who scan for viruses before the message leaves their SMTP relay; this is
    # not quite decided.
    #
    # TODO: there's probably loads more, and this should be user-configurable

    if ($last =~ /^ (?:
            # SpamAssassin additions, remove these so that mass-check works
            X-Spam-\S+

            # other spam filters
            |X-MailScanner(?:-SpamCheck)?
            |X-Pyzor |X-DCC-\S{2,25}-Metrics
            |X-Bogosity

            # post-delivery MUA additions
            |X-Evolution
            |X-MH-Thread-Markup

            # IMAP or POP additions
            |X-Keywords
            |(?:X-)?Status |X-Flags |Replied |Forwarded
            |Lines |Content-Length
            |X-UIDL? |X-IMAPbase

            # MTA delivery control headers
            |X-MDaemon-Deliver-To

            # other MUAs: VM and Gnus
            |X-VM-(?:Bookmark|(?:POP|IMAP)-Retrieved|Labels|Last-Modified
            |Summary-Format|VHeader|v\d-Data|Message-Order)
            |X-Gnus-Mail-Source
            |Xref
          ):/ix)
    {
      $last =~ /^([^:]+):/; dbg("dk: ignoring header '$1'");
      next;
    }

    push (@hdrs, $last); last;
  }

  $$ref = join("", @hdrs);

  # and return the remaining headers to pristine condition
  # $$ref =~ s/^\n//gs; $$ref =~ s/\n$//gs;
  $$ref =~ s/!nl;/\n/gs;
  $$ref =~ s/!ex;/!/gs;
}

sub _check_dk_whitelist {
  my ($self, $scan, $default) = @_;

  return unless $scan->is_dns_available();

  # trigger a DK check so we can get address/signer info
  # if verification failed only continue if we want the debug info
  unless ($self->check_domainkeys_verified($scan)) {
    unless (would_log("dbg", "dk")) {
      return;
    }
  }

  unless ($scan->{dk_address}) {
    dbg("dk: ". ($default ? "def_" : "") ."whitelist_from_dk: could not find sender or from address");
    return;
  }
  unless ($scan->{dk_signing_domain}) {
    dbg("dk: ". ($default ? "def_" : "") ."whitelist_from_dk: could not find signing domain name");
    return;
  }

  if ($default) {
    $scan->{def_dk_whitelist_from_checked} = 1;
    $scan->{def_dk_whitelist_from} =
                    $self->_wlcheck_domain($scan,'def_whitelist_from_dk');

    if (!$scan->{def_dk_whitelist_from}) {
      $scan->{def_dk_whitelist_from} =
                    $self->_wlcheck_no_domain($scan,'def_whitelist_auth');
    }
  } else {
    $scan->{dk_whitelist_from_checked} = 1;
    $scan->{dk_whitelist_from} =
                    $self->_wlcheck_domain($scan,'whitelist_from_dk');
    
    if (!$scan->{dk_whitelist_from}) {
      $scan->{dk_whitelist_from} =
                    $self->_wlcheck_no_domain($scan,'whitelist_auth');
    }
  }

  # if the message doesn't pass DK validation, it can't pass a DK whitelist
  if ($default) {
    if ($scan->{def_dk_whitelist_from}) {
      if ($self->check_domainkeys_verified($scan)) {
	dbg("dk: address: $scan->{dk_address} signing domain name: ".
	  "$scan->{dk_signing_domain} is in user's DEF_WHITELIST_FROM_DK and ".
	  "passed DK verification");
      } else {
	dbg("dk: address: $scan->{dk_address} signing domain name: ".
	  "$scan->{dk_signing_domain} is in user's DEF_WHITELIST_FROM_DK but ".
	  "failed DK verification");
	$scan->{def_dk_whitelist_from} = 0;
      }
    } else {
      dbg("dk: address: $scan->{dk_address} signing domain name: ".
	  "$scan->{dk_signing_domain} is not in user's DEF_WHITELIST_FROM_DK");
    }
  } else {
    if ($scan->{dk_whitelist_from}) {
      if ($self->check_domainkeys_verified($scan)) {
	dbg("dk: address: $scan->{dk_address} signing domain name: ".
	  "$scan->{dk_signing_domain} is in user's WHITELIST_FROM_DK and ".
	  "passed DK verification");
      } else {
	dbg("dk: address: $scan->{dk_address} signing domain name: ".
	  "$scan->{dk_signing_domain} is in user's WHITELIST_FROM_DK but ".
	  "failed DK verification");
	$scan->{dk_whitelist_from} = 0;
      }
    } else {
      dbg("dk: address: $scan->{dk_address} signing domain name: ".
	  "$scan->{dk_signing_domain} is not in user's WHITELIST_FROM_DK");
    }
  }
}

sub _wlcheck_domain {
  my ($self, $scan, $wl) = @_;

  foreach my $white_addr (keys %{$scan->{conf}->{$wl}}) {
    my $re = qr/$scan->{conf}->{$wl}->{$white_addr}{re}/i;
    foreach my $domain (@{$scan->{conf}->{$wl}->{$white_addr}{domain}}) {
      $self->_wlcheck_one_dom($scan, $wl, $white_addr, $domain, $re) and return 1;
    }
  }
  return 0;
}

sub _wlcheck_one_dom {
  my ($self, $scan, $wl, $white_addr, $domain, $re) = @_;

  if ($scan->{dk_address} =~ $re) {
    if ($scan->{dk_signing_domain} =~ /(?:^|\.)\Q${domain}\E$/i) {
      dbg("dk: address: $scan->{dk_address} matches $wl $re $domain");
      return 1;
    }
  }
  return 0;
}


# use a traditional whitelist_from-style addrlist, and infer the
# domain from each address on the fly.  Note: don't pre-parse and
# store the domains; that's inefficient memory-wise and only saves 1 m//
sub _wlcheck_no_domain {
  my ($self, $scan, $wl) = @_;

  foreach my $white_addr (keys %{$scan->{conf}->{$wl}}) {
    my $domain = ($white_addr =~ /\@(.*?)$/) ? $1 : $white_addr;
    my $re = $scan->{conf}->{$wl}->{$white_addr};
    $self->_wlcheck_one_dom($scan, $wl, $white_addr, $domain, $re) and return 1;
  }
  return 0;
}

1;
