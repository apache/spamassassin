# <@LICENSE>
# Copyright 2004 Apache Software Foundation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

package Mail::SpamAssassin::Plugin::WLBLEval;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;

use strict;
use warnings;
use bytes;

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

  # the important bit!
  $self->register_eval_rule("check_from_in_blacklist");
  $self->register_eval_rule("check_to_in_blacklist");
  $self->register_eval_rule("check_to_in_whitelist");
  $self->register_eval_rule("check_to_in_more_spam");
  $self->register_eval_rule("check_to_in_all_spam");
  $self->register_eval_rule("check_from_in_list");
  $self->register_eval_rule("check_to_in_list");
  $self->register_eval_rule("check_from_in_whitelist");
  $self->register_eval_rule("check_forged_in_whitelist");
  $self->register_eval_rule("check_from_in_default_whitelist");
  $self->register_eval_rule("check_forged_in_default_whitelist");

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds = ();

=head2 WHITELIST AND BLACKLIST OPTIONS

=over 4

=item whitelist_from add@ress.com

Used to specify addresses which send mail that is often tagged (incorrectly) as
spam. If you want to whitelist your own domain, be aware that spammers will
often impersonate the domain of the recipient.  The recommended solution is to
instead use C<whitelist_from_rcvd> as explained below.

Whitelist and blacklist addresses are now file-glob-style patterns, so
C<friend@somewhere.com>, C<*@isp.com>, or C<*.domain.net> will all work.
Specifically, C<*> and C<?> are allowed, but all other metacharacters are not.
Regular expressions are not used for security reasons.

Multiple addresses per line, separated by spaces, is OK.  Multiple
C<whitelist_from> lines is also OK.

The headers checked for whitelist addresses are as follows: if C<Resent-From>
is set, use that; otherwise check all addresses taken from the following
set of headers:

	Envelope-Sender
	Resent-Sender
	X-Envelope-From
	From

In addition, the "envelope sender" data, taken from the SMTP envelope
data where this is available, is looked up.

e.g.

  whitelist_from joe@example.com fred@example.com
  whitelist_from *@example.com

=cut

  push (@cmds, {
    setting => 'whitelist_from',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST
  });

=item unwhitelist_from add@ress.com

Used to override a default whitelist_from entry, so for example a distribution
whitelist_from can be overridden in a local.cf file, or an individual user can
override a whitelist_from entry in their own C<user_prefs> file.
The specified email address has to match exactly the address previously
used in a whitelist_from line.

e.g.

  unwhitelist_from joe@example.com fred@example.com
  unwhitelist_from *@example.com

=cut

  push (@cmds, {
    command => 'unwhitelist_from',
    setting => 'whitelist_from',
    code => \&Mail::SpamAssassin::Conf::Parser::remove_addrlist_value
  });

=item whitelist_from_rcvd addr@lists.sourceforge.net sourceforge.net

Use this to supplement the whitelist_from addresses with a check against the
Received headers. The first parameter is the address to whitelist, and the
second is a string to match the relay's rDNS.

This string is matched against the reverse DNS lookup used during the handover
from the internet to your internal network's mail exchangers.  It can
either be the full hostname, or the domain component of that hostname.  In
other words, if the host that connected to your MX had an IP address that
mapped to 'sendinghost.spamassassin.org', you should specify
C<sendinghost.spamassassin.org> or just C<spamassassin.org> here.

Note that this requires that C<internal_networks> be correct.  For simple cases,
it will be, but for a complex network, or running with DNS checks off
or with C<-L>, you may get better results by setting that parameter.

e.g.

  whitelist_from_rcvd joe@example.com  example.com
  whitelist_from_rcvd *@axkit.org      sergeant.org

=item def_whitelist_from_rcvd addr@lists.sourceforge.net sourceforge.net

Same as C<whitelist_from_rcvd>, but used for the default whitelist entries
in the SpamAssassin distribution.  The whitelist score is lower, because
these are often targets for spammer spoofing.

=cut

  push (@cmds, {
    setting => 'whitelist_from_rcvd',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
	return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^\S+\s+\S+$/) {
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{parser}->add_to_addrlist_rcvd ('whitelist_from_rcvd',
                                        split(/\s+/, $value));
    }
  });

  push (@cmds, {
    setting => 'def_whitelist_from_rcvd',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
	return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^\S+\s+\S+$/) {
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{parser}->add_to_addrlist_rcvd ('def_whitelist_from_rcvd',
                                        split(/\s+/, $value));
    }
  });

=item whitelist_allows_relays add@ress.com

Specify addresses which are in C<whitelist_from_rcvd> that sometimes
send through a mail relay other than the listed ones. By default mail
with a From address that is in C<whitelist_from_rcvd> that does not match
the relay will trigger a forgery rule. Including the address in
C<whitelist_allows_relay> prevents that.

Whitelist and blacklist addresses are now file-glob-style patterns, so
C<friend@somewhere.com>, C<*@isp.com>, or C<*.domain.net> will all work.
Specifically, C<*> and C<?> are allowed, but all other metacharacters are not.
Regular expressions are not used for security reasons.

Multiple addresses per line, separated by spaces, is OK.  Multiple
C<whitelist_allows_relays> lines is also OK.

The specified email address does not have to match exactly the address
previously used in a whitelist_from_rcvd line as it is compared to the
address in the header.

e.g.

  whitelist_allows_relays joe@example.com fred@example.com
  whitelist_allows_relays *@example.com

=cut

  push (@cmds, {
    setting => 'whitelist_allows_relays',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST
  });

=item unwhitelist_from_rcvd add@ress.com

Used to override a default whitelist_from_rcvd entry, so for example a
distribution whitelist_from_rcvd can be overridden in a local.cf file,
or an individual user can override a whitelist_from_rcvd entry in
their own C<user_prefs> file.

The specified email address has to match exactly the address previously
used in a whitelist_from_rcvd line.

e.g.

  unwhitelist_from_rcvd joe@example.com fred@example.com
  unwhitelist_from_rcvd *@axkit.org

=cut

  push (@cmds, {
    setting => 'unwhitelist_from_rcvd',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
	return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^(?:\S+(?:\s+\S+)*)$/) {
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{parser}->remove_from_addrlist_rcvd('whitelist_from_rcvd',
                                        split (/\s+/, $value));
      $self->{parser}->remove_from_addrlist_rcvd('def_whitelist_from_rcvd',
                                        split (/\s+/, $value));
    }
  });

=item blacklist_from add@ress.com

Used to specify addresses which send mail that is often tagged (incorrectly) as
non-spam, but which the user doesn't want.  Same format as C<whitelist_from>.

=cut

  push (@cmds, {
    setting => 'blacklist_from',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST
  });

=item unblacklist_from add@ress.com

Used to override a default blacklist_from entry, so for example a
distribution blacklist_from can be overridden in a local.cf file, or
an individual user can override a blacklist_from entry in their own
C<user_prefs> file. The specified email address has to match exactly
the address previously used in a blacklist_from line.


e.g.

  unblacklist_from joe@example.com fred@example.com
  unblacklist_from *@spammer.com

=cut


  push (@cmds, {
    command => 'unblacklist_from',
    setting => 'blacklist_from',
    code => \&Mail::SpamAssassin::Conf::Parser::remove_addrlist_value
  });


=item whitelist_to add@ress.com

If the given address appears as a recipient in the message headers
(Resent-To, To, Cc, obvious envelope recipient, etc.) the mail will
be whitelisted.  Useful if you're deploying SpamAssassin system-wide,
and don't want some users to have their mail filtered.  Same format
as C<whitelist_from>.

There are three levels of To-whitelisting, C<whitelist_to>, C<more_spam_to>
and C<all_spam_to>.  Users in the first level may still get some spammish
mails blocked, but users in C<all_spam_to> should never get mail blocked.

The headers checked for whitelist addresses are as follows: if C<Resent-To> or
C<Resent-Cc> are set, use those; otherwise check all addresses taken from the
following set of headers:

        To
        Cc
        Apparently-To
        Delivered-To
        Envelope-Recipients
        Apparently-Resent-To
        X-Envelope-To
        Envelope-To
        X-Delivered-To
        X-Original-To
        X-Rcpt-To
        X-Real-To

=item more_spam_to add@ress.com

See above.

=item all_spam_to add@ress.com

See above.

=cut

  push (@cmds, {
    setting => 'whitelist_to',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST
  });
  push (@cmds, {
    setting => 'more_spam_to',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST
  });
  push (@cmds, {
    setting => 'all_spam_to',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST
  });

=item blacklist_to add@ress.com

If the given address appears as a recipient in the message headers
(Resent-To, To, Cc, obvious envelope recipient, etc.) the mail will
be blacklisted.  Same format as C<blacklist_from>.

=cut

  push (@cmds, {
    setting => 'blacklist_to',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub check_from_in_blacklist {
  my ($self, $pms) = @_;
  local ($_);
  foreach $_ ($pms->all_from_addrs()) {
    if ($self->_check_whitelist ($self->{main}->{conf}->{blacklist_from}, $_)) {
      return 1;
    }
  }
}

sub check_to_in_blacklist {
  my ($self, $pms) = @_;
  local ($_);
  foreach $_ ($pms->all_to_addrs()) {
    if ($self->_check_whitelist ($self->{main}->{conf}->{blacklist_to}, $_)) {
      return 1;
    }
  }
}

sub check_to_in_whitelist {
  my ($self, $pms) = @_;
  local ($_);
  foreach $_ ($pms->all_to_addrs()) {
    if ($self->_check_whitelist ($self->{main}->{conf}->{whitelist_to}, $_)) {
      return 1;
    }
  }
}

sub check_to_in_more_spam {
  my ($self, $pms) = @_;
  local ($_);
  foreach $_ ($pms->all_to_addrs()) {
    if ($self->_check_whitelist ($self->{main}->{conf}->{more_spam_to}, $_)) {
      return 1;
    }
  }
}

sub check_to_in_all_spam {
  my ($self, $pms) = @_;
  local ($_);
  foreach $_ ($pms->all_to_addrs()) {
    if ($self->_check_whitelist ($self->{main}->{conf}->{all_spam_to}, $_)) {
      return 1;
    }
  }
}

sub check_from_in_list {
  my ($self, $pms, $list) = @_;
  my $list_ref = $self->{main}{conf}{$list};
  unless (defined $list_ref) {
    warn "eval: could not find list $list";
    return;
  }

  foreach my $addr ($pms->all_from_addrs()) {
    if ($self->_check_whitelist ($list_ref, $addr)) {
      return 1;
    }
  }

  return 0;
}

sub check_wb_list {
  my ($self, $params) = @_;

  return unless (defined $params->{permsgstatus});
  return unless (defined $params->{type});
  return unless (defined $params->{list});

  if (lc $params->{type} eq "to") {
    return $self->check_to_in_list($params->{permsgstatus}, $params->{list});
  }
  elsif (lc $params->{type} eq "from") {
    return $self->check_from_in_list($params->{permsgstatus}, $params->{list});
  }

  return;
}

sub check_to_in_list {
  my ($self,$pms,$list) = @_;
  my $list_ref = $self->{main}{conf}{$list};
  unless (defined $list_ref) {
    warn "eval: could not find list $list";
    return;
  }

  foreach my $addr ($pms->all_to_addrs()) {
    if ($self->_check_whitelist ($list_ref, $addr)) {
      return 1;
    }
  }

  return 0;
}

###########################################################################

sub check_from_in_whitelist {
  my ($self, $pms) = @_;
  $self->_check_from_in_whitelist($pms) unless exists $pms->{from_in_whitelist};
  return ($pms->{from_in_whitelist} > 0);
}

sub check_forged_in_whitelist {
  my ($self, $pms) = @_;
  $self->_check_from_in_whitelist($pms) unless exists $pms->{from_in_whitelist};
  $self->_check_from_in_default_whitelist($pms) unless exists $pms->{from_in_default_whitelist};
  return ($pms->{from_in_whitelist} < 0) && ($pms->{from_in_default_whitelist} == 0);
}

sub check_from_in_default_whitelist {
  my ($self, $pms) = @_;
  $self->_check_from_in_default_whitelist($pms) unless exists $pms->{from_in_default_whitelist};
  return ($pms->{from_in_default_whitelist} > 0);
}

sub check_forged_in_default_whitelist {
  my ($self, $pms) = @_;
  $self->_check_from_in_default_whitelist($pms) unless exists $pms->{from_in_default_whitelist};
  $self->_check_from_in_whitelist($pms) unless exists $pms->{from_in_whitelist};
  return ($pms->{from_in_default_whitelist} < 0) && ($pms->{from_in_whitelist} == 0);
}

###########################################################################

sub _check_from_in_whitelist {
  my ($self, $pms) = @_;
  my $found_match = 0;
  local ($_);
  foreach $_ ($pms->all_from_addrs()) {
    if ($self->_check_whitelist ($self->{main}->{conf}->{whitelist_from}, $_)) {
      $pms->{from_in_whitelist} = 1;
      return;
    }
    my $wh = $self->_check_whitelist_rcvd ($pms, $self->{main}->{conf}->{whitelist_from_rcvd}, $_);
    if ($wh == 1) {
      $pms->{from_in_whitelist} = 1;
      return;
    }
    elsif ($wh == -1) {
      $found_match = -1;
    }
  }

  $pms->{from_in_whitelist} = $found_match;
  return;
}

###########################################################################

sub _check_from_in_default_whitelist {
  my ($self, $pms) = @_;
  my $found_match = 0;
  local ($_);
  foreach $_ ($pms->all_from_addrs()) {
    my $wh = $self->_check_whitelist_rcvd ($pms, $self->{main}->{conf}->{def_whitelist_from_rcvd}, $_);
    if ($wh == 1) {
      $pms->{from_in_default_whitelist} = 1;
      return;
    }
    elsif ($wh == -1) {
      $found_match = -1;
    }
  }

  $pms->{from_in_default_whitelist} = $found_match;
  return;
}

###########################################################################

# look up $addr and trusted relays in a whitelist with rcvd
# note if it appears to be a forgery and $addr is not in any-relay list
sub _check_whitelist_rcvd {
  my ($self, $pms, $list, $addr) = @_;

  # we can only match this if we have at least 1 trusted or untrusted header
  return 0 unless ($pms->{num_relays_untrusted}+$pms->{num_relays_trusted} > 0);

  my @relays = ();
  # try the untrusted one first
  if ($pms->{num_relays_untrusted} > 0) {
    @relays = $pms->{relays_untrusted}->[0];
  }
  # then try the trusted ones; the user could have whitelisted a trusted
  # relay, totally permitted
  # but do not do this if any untrusted relays, to avoid forgery -- bug 4425
  if ($pms->{num_relays_trusted} > 0 && !$pms->{num_relays_untrusted} ) {
    push (@relays, @{$pms->{relays_trusted}});
  }

  $addr = lc $addr;
  my $found_forged = 0;
  foreach my $white_addr (keys %{$list}) {
    my $regexp = qr/$list->{$white_addr}{re}/i;
    foreach my $domain (@{$list->{$white_addr}{domain}}) {
      
      if ($addr =~ $regexp) {
        foreach my $lastunt (@relays) {
          my $rdns = $lastunt->{lc_rdns};
          if ($rdns =~ /(?:^|\.)\Q${domain}\E$/i) { 
            dbg("rules: address $addr matches (def_)whitelist_from_rcvd $list->{$white_addr}{re} ${domain}");
            return 1;
          }
        }
        # found address match but no relay match. note as possible forgery
        $found_forged = -1;
      }
    }
  }
  if ($found_forged) { # might be forgery. check if in list of exempted
    my $wlist = $self->{main}->{conf}->{whitelist_allows_relays};
    foreach my $fuzzy_addr (values %{$wlist}) {
      if ($addr =~ /$fuzzy_addr/i) {
        $found_forged = 0;
        last;
      }
    }
  }
  return $found_forged;
}

###########################################################################

sub _check_whitelist {
  my ($self, $list, $addr) = @_;
  $addr = lc $addr;
  if (defined ($list->{$addr})) { return 1; }
  study $addr;
  foreach my $regexp (values %{$list}) {
    if ($addr =~ qr/$regexp/i) {
      dbg("rules: address $addr matches whitelist or blacklist regexp: $regexp");
      return 1;
    }
  }

  return 0;
}

1;
