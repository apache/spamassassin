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

Mail::SpamAssassin::Plugin::DKIM - perform DKIM verification tests

=head1 SYNOPSIS

 loadplugin Mail::SpamAssassin::Plugin::DKIM [/path/to/DKIM.pm]

Taking into account signatures from any signing domains:

 full   DKIM_SIGNED           eval:check_dkim_signed()
 full   DKIM_VALID            eval:check_dkim_valid()
 full   DKIM_VALID_AU         eval:check_dkim_valid_author_sig()
 full   DKIM_VALID_EF         eval:check_dkim_valid_envelopefrom()

Taking into account ARC signatures (Authenticated Received Chain, RFC 8617)
from any signing domains:

 full   ARC_SIGNED            eval:check_arc_signed()
 full   ARC_VALID             eval:check_arc_valid()

Taking into account signatures from specified signing domains only:
(quotes may be omitted on domain names consisting only of letters, digits,
dots, and minus characters)

 full   DKIM_SIGNED_MY1       eval:check_dkim_signed('dom1','dom2',...)
 full   DKIM_VALID_MY1        eval:check_dkim_valid('dom1','dom2',...)
 full   DKIM_VALID_AU_MY1     eval:check_dkim_valid_author_sig('d1','d2',...)

 full   __DKIM_DEPENDABLE     eval:check_dkim_dependable()

Author Domain Signing Practices (ADSP) from any author domains:

 header DKIM_ADSP_NXDOMAIN    eval:check_dkim_adsp('N')
 header DKIM_ADSP_ALL         eval:check_dkim_adsp('A')
 header DKIM_ADSP_DISCARD     eval:check_dkim_adsp('D')
 header DKIM_ADSP_CUSTOM_LOW  eval:check_dkim_adsp('1')
 header DKIM_ADSP_CUSTOM_MED  eval:check_dkim_adsp('2')
 header DKIM_ADSP_CUSTOM_HIGH eval:check_dkim_adsp('3')

Author Domain Signing Practices (ADSP) from specified author domains only:

 header DKIM_ADSP_MY1         eval:check_dkim_adsp('*','dom1','dom2',...)

 describe DKIM_SIGNED   Message has a DKIM or DK signature, not necessarily valid
 describe DKIM_VALID    Message has at least one valid DKIM or DK signature
 describe DKIM_VALID_AU Message has a valid DKIM or DK signature from author's domain
 describe DKIM_VALID_EF Message has a valid DKIM or DK signature from envelope-from domain
 describe __DKIM_DEPENDABLE     A validation failure not attributable to truncation

 describe DKIM_ADSP_NXDOMAIN    Domain not in DNS and no valid author domain signature
 describe DKIM_ADSP_ALL         Domain signs all mail, no valid author domain signature
 describe DKIM_ADSP_DISCARD     Domain signs all mail and suggests discarding mail with no valid author domain signature, no valid author domain signature
 describe DKIM_ADSP_CUSTOM_LOW  adsp_override is CUSTOM_LOW, no valid author domain signature
 describe DKIM_ADSP_CUSTOM_MED  adsp_override is CUSTOM_MED, no valid author domain signature
 describe DKIM_ADSP_CUSTOM_HIGH adsp_override is CUSTOM_HIGH, no valid author domain signature

For compatibility with pre-3.3.0 versions, the following are synonyms:

 OLD: eval:check_dkim_verified = NEW: eval:check_dkim_valid
 OLD: eval:check_dkim_signall  = NEW: eval:check_dkim_adsp('A')
 OLD: eval:check_dkim_signsome = NEW: redundant, semantically always true

The __DKIM_DEPENDABLE eval rule deserves an explanation. The rule yields true
when signatures are supplied by a caller, OR ELSE when signatures are obtained
by this plugin AND either there are no signatures OR a rule __TRUNCATED was
false. In other words: __DKIM_DEPENDABLE is true when failed signatures can
not be attributed to message truncation when feeding a message to SpamAssassin.
It can be consulted to prevent false positives on large but truncated messages
with poor man's implementation of ADSP by hand-crafted rules.

=head1 DESCRIPTION

This SpamAssassin plugin implements DKIM lookups as described by the RFC 4871,
as well as historical DomainKeys lookups, as described by RFC 4870, thanks
to the support for both types of signatures by newer versions of module
Mail::DKIM.

It requires the C<Mail::DKIM> CPAN module to operate. Many thanks to Jason Long
for that module.

=head1 TAGS

The following tags are added to the set, available for use in reports,
header fields, other plugins, etc.:

  _DKIMIDENTITY_
    Agent or User Identifier (AUID) (the 'i' tag) from valid signatures;

  _DKIMDOMAIN_
    Signing Domain Identifier (SDID) (the 'd' tag) from valid signatures;

  _DKIMSELECTOR_
    DKIM selector (the 's' tag) from valid signatures;

Identities and domains from signatures which failed verification are not
included in these tags. Duplicates are eliminated (e.g. when there are two or
more valid signatures from the same signer, only one copy makes it into a tag).
Note that there may be more than one signature in a message - currently they
are provided as a space-separated list, although this behaviour may change.

=head1 SEE ALSO

C<Mail::DKIM> Mail::SpamAssassin::Plugin(3)

  http://dkimproxy.sourceforge.net/
  https://tools.ietf.org/rfc/rfc4871.txt
  https://tools.ietf.org/rfc/rfc4870.txt
  https://tools.ietf.org/rfc/rfc5617.txt
  https://datatracker.ietf.org/group/dkim/about/

=cut

package Mail::SpamAssassin::Plugin::DKIM;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;
use Mail::SpamAssassin::Util qw(idn_to_ascii);
use version;

use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # signatures
  $self->register_eval_rule("check_dkim_signed", $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS);
  $self->register_eval_rule("check_arc_signed", $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS);
  $self->register_eval_rule("check_dkim_valid", $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS);
  $self->register_eval_rule("check_arc_valid", $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS);
  $self->register_eval_rule("check_dkim_valid_author_sig", $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS);
  $self->register_eval_rule("check_dkim_testing", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_dkim_valid_envelopefrom", $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS);

  # author domain signing practices
  $self->register_eval_rule("check_dkim_adsp", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_dkim_dependable", $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS);

  # welcomelisting
  $self->register_eval_rule("check_for_dkim_welcomelist_from", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_for_dkim_whitelist_from", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);  #Stub - Remove in SA 4.1
  $self->register_eval_rule("check_for_def_dkim_welcomelist_from", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_for_def_dkim_whitelist_from", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);  #Stub - Remove in SA 4.1

  # old names (aliases) for compatibility
  $self->register_eval_rule("check_dkim_verified");  # = check_dkim_valid
  $self->register_eval_rule("check_dkim_signall");   # = check_dkim_adsp('A')
  $self->register_eval_rule("check_dkim_signsome");  # redundant, always false

  $self->set_config($mailsaobject->{conf});

  return $self;
}

###########################################################################

sub set_config {
  my($self, $conf) = @_;
  my @cmds;

=head1 USER SETTINGS

=over 4

=item welcomelist_from_dkim author@example.com [signing-domain]

Previously whitelist_from_dkim which will work interchangeably until 4.1.

Works similarly to welcomelist_from, except that in addition to matching
an author address (From) to the pattern in the first parameter, the message
must also carry a valid Domain Keys Identified Mail (DKIM) signature made by
a signing domain (SDID, i.e. the d= tag) that is acceptable to us.

Only one welcomelist entry is allowed per line, as in C<welcomelist_from_rcvd>.
Multiple C<welcomelist_from_dkim> lines are allowed. File-glob style characters
are allowed for the From address (the first parameter), just like with
C<welcomelist_from_rcvd>.

The second parameter (the signing-domain) does not accept full file-glob style
wildcards, although a simple '*.' (or just a '.') prefix to a domain name
is recognized and implies any subdomain of the specified domain (but not
the domain itself).

If no signing-domain parameter is specified, the only acceptable signature
will be an Author Domain Signature (sometimes called first-party signature)
which is a signature where the signing domain (SDID) of a signature matches
the domain of the author's address (i.e. the address in a From header field).

Since this welcomelist requires a DKIM check to be made, network tests must
be enabled.

Examples of welcomelisting based on an author domain signature (first-party):

  welcomelist_from_dkim joe@example.com
  welcomelist_from_dkim *@corp.example.com
  welcomelist_from_dkim *@*.example.com

Examples of welcomelisting based on third-party signatures:

  welcomelist_from_dkim jane@example.net      example.org
  welcomelist_from_dkim rick@info.example.net example.net
  welcomelist_from_dkim *@info.example.net    example.net
  welcomelist_from_dkim *@*                   mail7.remailer.example.com
  welcomelist_from_dkim *@*                   *.remailer.example.com

=item def_welcomelist_from_dkim author@example.com [signing-domain]

Previously def_whitelist_from_dkim which will work interchangeably until 4.1.

Same as C<welcomelist_from_dkim>, but used for the default welcomelist entries
in the SpamAssassin distribution.  The welcomelist score is lower, because
these are often targets for abuse of public mailers which sign their mail.

=item unwelcomelist_from_dkim author@example.com [signing-domain]

Previously unwhitelist_from_dkim which will work interchangeably until 4.1.

Removes an email address with its corresponding signing-domain field
from def_welcomelist_from_dkim and welcomelist_from_dkim tables, if it exists.
Parameters to unwelcomelist_from_dkim must exactly match the parameters of
a corresponding welcomelist_from_dkim or def_welcomelist_from_dkim config
option which created the entry, for it to be removed (a domain name is
matched case-insensitively);  i.e. if a signing-domain parameter was
specified in a welcomelisting command, it must also be specified in the
unwelcomelisting command.

Useful for removing undesired default entries from a distributed configuration
by a local or site-specific configuration or by C<user_prefs>.

=item adsp_override domain [signing-practices]

Currently few domains publish their signing practices (RFC 5617 - ADSP),
partly because the ADSP rfc is rather new, partly because they think
hardly any recipient bothers to check it, and partly for fear that some
recipients might lose mail due to problems in their signature validation
procedures or mail mangling by mailers beyond their control.

Nevertheless, recipients could benefit by knowing signing practices of a
sending (author's) domain, for example to recognize forged mail claiming
to be from certain domains which are popular targets for phishing, like
financial institutions. Unfortunately, as signing practices are seldom
published or are weak, it is hardly justifiable to look them up in DNS.

To overcome this chicken-or-the-egg problem, the C<adsp_override> mechanism
allows recipients using SpamAssassin to override published or defaulted
ADSP for certain domains. This makes it possible to manually specify a
stronger (or weaker) signing practices than a signing domain is willing
to publish (explicitly or by default), and also save on a DNS lookup.

Note that ADSP (published or overridden) is only consulted for messages
which do not contain a valid DKIM signature from the author's domain.

According to RFC 5617, signing practices can be one of the following:
C<unknown>, C<all> and C<discardable>.

C<unknown>: The domain might sign some or all email - messages from the
domain may or may not have an Author Domain Signature. This is a default
if a domain exists in DNS but no ADSP record is found.

C<all>: All mail from the domain is signed with an Author Domain Signature.

C<discardable>: All mail from the domain is signed with an Author Domain
Signature.  Furthermore, if a message arrives without a valid Author Domain
Signature, the domain encourages the recipient(s) to discard it.

ADSP lookup can also determine that a domain is "out of scope", i.e., the
domain does not exist (NXDOMAIN) in the DNS.

To override domain's signing practices in a SpamAssassin configuration file,
specify an C<adsp_override> directive for each sending domain to be overridden.

Its first argument is a domain name. Author's domain is matched against it,
matching is case insensitive. This is not a regular expression or a file-glob
style wildcard, but limited wildcarding is still available: if this argument
starts by a "*." (or is a sole "*"), author's domain matches if it is a
subdomain (to one or more levels) of the argument. Otherwise (with no leading
asterisk) the match must be exact (not a subdomain).

An optional second parameter is one of the following keywords
(case-insensitive): C<nxdomain>, C<unknown>, C<all>, C<discardable>,
C<custom_low>, C<custom_med>, C<custom_high>.

Absence of this second parameter implies C<discardable>. If a domain is not
listed by a C<adsp_override> directive nor does it explicitly publish any
ADSP record, then C<unknown> is implied for valid domains, and C<nxdomain>
for domains not existing in DNS. (Note: domain validity is only checked with
versions of Mail::DKIM 0.37 or later (actually since 0.36_5), the C<nxdomain>
would never turn up with older versions).

The strong setting C<discardable> is useful for domains which are known
to always sign their mail and to always send it directly to recipients
(not to mailing lists), and are frequent targets of fishing attempts,
such as financial institutions. The C<discardable> is also appropriate
for domains which are known never to send any mail.

When a message does not contain a valid signature by the author's domain
(the domain in a From header field), the signing practices pertaining
to author's domain determine which of the following rules fire and
contributes its score: DKIM_ADSP_NXDOMAIN, DKIM_ADSP_ALL, DKIM_ADSP_DISCARD,
DKIM_ADSP_CUSTOM_LOW, DKIM_ADSP_CUSTOM_MED, DKIM_ADSP_CUSTOM_HIGH. Not more
than one of these rules can fire for messages that have one author (but see
below). The last three can only result from a 'signing-practices' as given
in a C<adsp_override> directive (not from a DNS lookup), and can serve as
a convenient means of providing a different score if scores assigned to
DKIM_ADSP_ALL or DKIM_ADSP_DISCARD are not considered suitable for some
domains.

RFC 5322 permits a message to have more than one author - multiple addresses
may be listed in a single From header field.  RFC 5617 defines that a message
with multiple authors has multiple signing domain signing practices, but does
not prescribe how these should be combined. In presence of multiple signing
practices, more than one of the DKIM_ADSP_* rules may fire.

As a precaution against firing DKIM_ADSP_* rules when there is a known local
reason for a signature verification failure, the domain's ADSP is considered
'unknown' when DNS lookups are disabled or a DNS lookup encountered a temporary
problem on fetching a public key from the author's domain. Similarly, ADSP
is considered 'unknown' when this plugin did its own signature verification
(signatures were not passed to SA by a caller) and a metarule __TRUNCATED was
triggered, indicating the caller intentionally passed a truncated message to
SpamAssassin, which was a likely reason for a signature verification failure.

Example:

  adsp_override *.mydomain.example.com   discardable
  adsp_override *.neversends.example.com discardable

  adsp_override ebay.com
  adsp_override *.ebay.com
  adsp_override ebay.co.uk
  adsp_override *.ebay.co.uk
  adsp_override paypal.com
  adsp_override *.paypal.com
  adsp_override amazon.com
  adsp_override ealerts.bankofamerica.com
  adsp_override americangreetings.com
  adsp_override egreetings.com
  adsp_override bluemountain.com
  adsp_override hallmark.com   all
  adsp_override *.hallmark.com all
  adsp_override youtube.com    custom_high
  adsp_override google.com     custom_low
  adsp_override gmail.com      custom_low
  adsp_override googlemail.com custom_low
  adsp_override yahoo.com      custom_low
  adsp_override yahoo.com.au   custom_low
  adsp_override yahoo.se       custom_low

  adsp_override junkmailerkbw0rr.com nxdomain
  adsp_override junkmailerd2hlsg.com nxdomain

  # effectively disables ADSP network DNS lookups for all other domains:
  adsp_override *              unknown

  score DKIM_ADSP_ALL          2.5
  score DKIM_ADSP_DISCARD     25
  score DKIM_ADSP_NXDOMAIN     3

  score DKIM_ADSP_CUSTOM_LOW   1
  score DKIM_ADSP_CUSTOM_MED   3.5
  score DKIM_ADSP_CUSTOM_HIGH  8


=item dkim_minimum_key_bits n             (default: 1024)

The smallest size of a signing key (in bits) for a valid signature to be
considered for welcomelisting. Additionally, the eval function check_dkim_valid()
will return false on short keys when called with explicitly listed domains,
and the eval function check_dkim_valid_author_sig() will return false on short
keys (regardless of its arguments). Setting the option to 0 disables a key
size check.

Note that the option has no effect when the eval function check_dkim_valid()
is called with no arguments (like in a rule DKIM_VALID). A mere presence of
some valid signature on a message has no reputational value (without being
associated with a particular domain), regardless of its key size - anyone can
prepend its own signature on a copy of some third party mail and re-send it,
which makes it no more trustworthy than without such signature. This is also
a reason for a rule DKIM_VALID to have a near-zero score, i.e. a rule hit
is only informational.
This option is evaluated on ARC signatures checks as well.

=cut

  push (@cmds, {
    setting => 'welcomelist_from_dkim',
    aliases => ['whitelist_from_dkim'], # removed in 4.1
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local ($1,$2);
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^(\S+)(?:\s+(\S+))?$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $address = $1;
      my $sdid = defined $2 ? $2 : '';  # empty implies author domain signature
      $address =~ s/(\@[^@]*)\z/lc($1)/e;  # lowercase the email address domain
      $self->{parser}->add_to_addrlist_dkim('welcomelist_from_dkim',
                                            $address, lc $sdid);
    }
  });

  push (@cmds, {
    setting => 'def_welcomelist_from_dkim',
    aliases => ['def_whitelist_from_dkim'], # removed in 4.1
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local ($1,$2);
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^(\S+)(?:\s+(\S+))?$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $address = $1;
      my $sdid = defined $2 ? $2 : '';  # empty implies author domain signature
      $address =~ s/(\@[^@]*)\z/lc($1)/e;  # lowercase the email address domain
      $self->{parser}->add_to_addrlist_dkim('def_welcomelist_from_dkim',
                                            $address, lc $sdid);
    }
  });

  push (@cmds, {
    setting => 'unwelcomelist_from_dkim',
    aliases => ['unwhitelist_from_dkim'], # removed in 4.1
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local ($1,$2);
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^(\S+)(?:\s+(\S+))?$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $address = $1;
      my $sdid = defined $2 ? $2 : '';  # empty implies author domain signature
      $address =~ s/(\@[^@]*)\z/lc($1)/e;  # lowercase the email address domain
      $self->{parser}->remove_from_addrlist_dkim('welcomelist_from_dkim',
                                                 $address, lc $sdid);
      $self->{parser}->remove_from_addrlist_dkim('def_welcomelist_from_dkim',
                                                 $address, lc $sdid);
    }
  });

  push (@cmds, {
    setting => 'adsp_override',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local ($1,$2);
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^ \@? ( [*a-z0-9._-]+ )
                         (?: \s+ (nxdomain|unknown|all|discardable|
                                  custom_low|custom_med|custom_high) )?$/ix) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $domain = lc $1;  # author's domain
      my $adsp = $2;       # author domain signing practices
      $adsp = 'discardable' if !defined $adsp;
      $adsp = lc $adsp;
      if    ($adsp eq 'custom_low' ) { $adsp = '1' }
      elsif ($adsp eq 'custom_med' ) { $adsp = '2' }
      elsif ($adsp eq 'custom_high') { $adsp = '3' }
      else { $adsp = uc substr($adsp,0,1) }  # N/U/A/D/1/2/3
      $self->{parser}->{conf}->{adsp_override}->{$domain} = $adsp;
    }
  });

  # minimal signing key size in bits that is acceptable for welcomelisting
  push (@cmds, {
    setting => 'dkim_minimum_key_bits',
    default => 1024,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

=back

=head1 ADMINISTRATOR SETTINGS

=over 4

=item dkim_timeout n             (default: 5)

How many seconds to wait for a DKIM query to complete, before scanning
continues without the DKIM result. A numeric value is optionally suffixed
by a time unit (s, m, h, d, w, indicating seconds (default), minutes, hours,
days, weeks).

=back

=cut

  push (@cmds, {
    setting => 'dkim_timeout',
    is_admin => 1,
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_DURATION
  });

  $conf->{parser}->register_commands(\@cmds);
}

# ---------------------------------------------------------------------------

sub check_dkim_signed {
  my ($self, $pms, $full_ref, @acceptable_domains) = @_;
  $self->_check_dkim_signature($pms)  if !$pms->{dkim_checked_signature};
  my $result = 0;
  if (!$pms->{dkim_signed}) {
    # don't bother
  } elsif (!@acceptable_domains) {
    $result = 1;  # no additional constraints, any signing domain will do
  } else {
    $result = $self->_check_dkim_signed_by($pms,0,0,\@acceptable_domains);
  }
  return $result;
}

sub check_arc_signed {
  my ($self, $pms, $full_ref, @acceptable_domains) = @_;
  $self->_check_dkim_signature($pms)  if !$pms->{arc_checked_signature};
  my $result = 0;
  if (!$pms->{arc_signed}) {
    # don't bother
  } elsif (!@acceptable_domains) {
    $result = 1;  # no additional constraints, any signing domain will do
  }
  return $result;
}

sub check_dkim_valid {
  my ($self, $pms, $full_ref, @acceptable_domains) = @_;
  $self->_check_dkim_signature($pms)  if !$pms->{dkim_checked_signature};
  my $result = 0;
  if (!$pms->{dkim_valid}) {
    # don't bother
  } elsif (!@acceptable_domains) {
    $result = 1;  # no additional constraints, any signing domain will do,
                  # also any signing key size will do
  } else {
    $result = $self->_check_dkim_signed_by($pms,1,0,\@acceptable_domains);
  }
  return $result;
}

sub check_arc_valid {
  my ($self, $pms, $full_ref, @acceptable_domains) = @_;
  $self->_check_dkim_signature($pms)  if !$pms->{arc_checked_signature};
  my $result = 0;
  if (!$pms->{arc_valid}) {
    # don't bother
  } elsif (!@acceptable_domains) {
    $result = 1;  # no additional constraints, any signing domain will do,
                  # also any signing key size will do
  }
  return $result;
}

sub check_dkim_valid_author_sig {
  my ($self, $pms, $full_ref, @acceptable_domains) = @_;
  $self->_check_dkim_signature($pms)  if !$pms->{dkim_checked_signature};
  my $result = 0;
  if (!%{$pms->{dkim_has_valid_author_sig}}) {
    # don't bother
  } else {
    $result = $self->_check_dkim_signed_by($pms,1,1,\@acceptable_domains);
  }
  return $result;
}

sub check_dkim_valid_envelopefrom {
  my ($self, $pms, $full_ref) = @_;
  my $result = 0;
  my ($envfrom) = ($pms->get('EnvelopeFrom:addr')||'') =~ /\@(\S+)/;
  # if no envelopeFrom, it cannot be valid
  return $result if !defined $envfrom;
  $envfrom = lc $envfrom;
  $self->_check_dkim_signature($pms)  if !$pms->{dkim_checked_signature};
  if (!$pms->{dkim_valid}) {
    # don't bother
  } else {
    $result = $self->_check_dkim_signed_by($pms,1,0,[$envfrom]);
  }
  return $result;
}

sub check_dkim_dependable {
  my ($self, $pms) = @_;
  $self->_check_dkim_signature($pms)  if !$pms->{dkim_checked_signature};
  return $pms->{dkim_signatures_dependable};
}

# mosnomer, old synonym for check_dkim_valid, kept for compatibility
sub check_dkim_verified {
  return check_dkim_valid(@_);
}

# no valid Author Domain Signature && ADSP matches the argument
sub check_dkim_adsp {
  my ($self, $pms, $adsp_char, @domains_list) = @_;
  $self->_check_dkim_signature($pms)  if !$pms->{dkim_checked_signature};
  my $result = 0;
  if (!$pms->{dkim_signatures_ready}) {
    # don't bother
  } else {
    $self->_check_dkim_adsp($pms)  if !$pms->{dkim_checked_adsp};

    # an asterisk indicates any ADSP type can match (as long as
    # there is no valid author domain signature present)
    $adsp_char = 'NAD123'  if $adsp_char eq '*';  # a shorthand for NAD123

    if ( !(grep { index($adsp_char,$_) >= 0 } values %{$pms->{dkim_adsp}}) ) {
      # not the right ADSP type
    } elsif (!@domains_list) {
      $result = 1;  # no additional constraints, any author domain will do
    } else {
      local $1;
      my %author_domains = %{$pms->{dkim_author_domains}};
      foreach my $dom (@domains_list) {
        if ($dom =~ /^\*?\.(.*)\z/s) {  # domain itself or its subdomain
          my $doms = lc $1;
          if ($author_domains{$doms} ||
              (grep { /\.\Q$doms\E\z/s } keys %author_domains) ) {
            $result = 1; last;
          }
        } else {  # match on domain (not a subdomain)
          if ($author_domains{lc $dom}) {
            $result = 1; last;
          }
        }
      }
    }
  }
  return $result;
}

# useless, semantically always true according to ADSP (RFC 5617)
sub check_dkim_signsome {
  my ($self, $pms) = @_;
  # the signsome is semantically always true, and thus redundant;
  # for compatibility just returns false to prevent
  # a legacy rule DKIM_POLICY_SIGNSOME from always firing
  return 0;
}

# synonym with check_dkim_adsp('A'), kept for compatibility
sub check_dkim_signall {
  my ($self, $pms) = @_;
  check_dkim_adsp($self, $pms, 'A');
}

# public key carries a testing flag
sub check_dkim_testing {
  my ($self, $pms) = @_;
  my $result = 0;
  $self->_check_dkim_signature($pms)  if !$pms->{dkim_checked_signature};
  $result = 1  if $pms->{dkim_key_testing};
  return $result;
}

sub check_for_dkim_welcomelist_from {
  my ($self, $pms) = @_;
  $self->_check_dkim_welcomelist($pms)  if !$pms->{welcomelist_checked};
  return ($pms->{dkim_match_in_welcomelist_from_dkim} || 
          $pms->{dkim_match_in_welcomelist_auth}) ? 1 : 0;
}
*check_for_dkim_whitelist_from = \&check_for_dkim_welcomelist_from; # removed in 4.1

sub check_for_def_dkim_welcomelist_from {
  my ($self, $pms) = @_;
  $self->_check_dkim_welcomelist($pms)  if !$pms->{welcomelist_checked};
  return ($pms->{dkim_match_in_def_welcomelist_from_dkim} || 
         $pms->{dkim_match_in_def_welcomelist_auth}) ? 1 : 0;
}
*check_for_def_dkim_whitelist_from = \&check_for_def_dkim_welcomelist_from; # removed in 4.1

# ---------------------------------------------------------------------------

sub _dkim_load_modules {
  my ($self) = @_;

  if (!$self->{tried_loading}) {
    $self->{service_available} = 0;
    my $timemethod = $self->{main}->time_method("dkim_load_modules");
    my $eval_stat;
    eval {
      # Have to do this so that RPM doesn't find these as required perl modules.
      { require Mail::DKIM::Verifier }
    } or do {
      $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    };
    $self->{tried_loading} = 1;

    if (defined $eval_stat) {
      dbg("dkim: cannot load Mail::DKIM module, DKIM checks disabled: %s",
          $eval_stat);
    } else {
      my $version = Mail::DKIM::Verifier->VERSION;
      if (version->parse($version) >= version->parse(0.31)) {
        dbg("dkim: using Mail::DKIM version $version");
      } elsif (version->parse($version) < version->parse(0.50)) {
        dbg("dkim: Mail::DKIM $version is older than 0.50 ".
             "ARC support will not be available, suggested upgrade to 0.50 or later!");
      } else {
        info("dkim: Mail::DKIM $version is older than the required ".
             "minimal version 0.31, suggested upgrade to 0.37 or later!");
      }
      $self->{service_available} = 1;

      my $adsp_avail =
        eval { require Mail::DKIM::AuthorDomainPolicy };  # since 0.34
      if (!$adsp_avail) {  # fallback to pre-ADSP policy
        eval { require Mail::DKIM::DkimPolicy }  # ignoring status
      }
    }
    eval {
      # Have to do this so that RPM doesn't find these as required perl modules.
      { require Mail::DKIM::ARC::Verifier }
      $self->{arc_available} = 1;
    } or do {
      $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
      if (defined $eval_stat) {
        dbg("dkim: cannot load Mail::DKIM::ARC module, DKIM::ARC checks disabled: %s",
          $eval_stat);
      }
      $self->{arc_available} = 0;
    };
  }
  return $self->{service_available};
}

# ---------------------------------------------------------------------------

sub _check_dkim_signed_by {
  my ($self, $pms, $must_be_valid, $must_be_author_domain_signature,
      $acceptable_domains_ref) = @_;
  my $result = 0;
  my $verifier = $pms->{dkim_verifier};
  my $minimum_key_bits = $pms->{conf}->{dkim_minimum_key_bits};
  foreach my $sig (@{$pms->{dkim_signatures}}) {
    next if !defined $sig;
    if ($must_be_valid) {
      next if ($sig->UNIVERSAL::can("result") ? $sig : $verifier)
                ->result ne 'pass';
      next if $sig->UNIVERSAL::can("check_expiration") &&
              !$sig->check_expiration;
      next if $minimum_key_bits && $sig->{_spamassassin_key_size} &&
              $sig->{_spamassassin_key_size} < $minimum_key_bits;
    }
    my ($sdid) = (defined $sig->identity)? $sig->identity =~ /\@(\S+)/ : ($sig->domain);
    next if !defined $sdid;  # a signature with a missing required tag 'd' or 'i' ?
    $sdid = lc $sdid;
    if ($must_be_author_domain_signature) {
      next if !$pms->{dkim_author_domains}->{$sdid};
    }
    if (!@$acceptable_domains_ref) {
      $result = 1;
    } else {
      foreach my $ad (@$acceptable_domains_ref) {
        if ($ad =~ /^\*?\.(.*)\z/s) {  # domain itself or its subdomain
          my $d = lc $1;
          if ($sdid eq $d || $sdid =~ /\.\Q$d\E\z/s) { $result = 1; last }
        } else {  # match on domain (not a subdomain)
          if ($sdid eq lc $ad) { $result = 1; last }
        }
      }
    }
    last if $result;
  }
  return $result;
}

sub _get_authors {
  my ($self, $pms, $sig_type) = @_;

  # Note that RFC 5322 permits multiple addresses in the From header field,
  # and according to RFC 5617 such message has multiple authors and hence
  # multiple "Author Domain Signing Practices". For the time being the
  # SpamAssassin's get() can only provide a single author!

  my %author_domains;  local $1;
  my @authors = grep { defined $_ } ( $pms->get('from:addr',undef) );
  for (@authors) {
    # be tolerant, ignore trailing WSP after a domain name
    $author_domains{lc $1} = 1  if /\@([^\@]+?)[ \t]*\z/s;
  }
  $pms->{"${sig_type}_author_addresses"} = \@authors;       # list of full addresses
  $pms->{"${sig_type}_author_domains"} = \%author_domains;  # hash of their domains
}

sub _check_dkim_signature {
  my ($self, $pms) = @_;

  my $conf = $pms->{conf};
  my($verifier, $arc_verifier, @signatures, @arc_signatures, @valid_signatures, @arc_valid_signatures);

  $pms->{dkim_checked_signature} = 1; # has this sub already been invoked?
  $pms->{arc_checked_signature} = 1;  # has this sub already been invoked?
  $pms->{dkim_signatures_ready} = 0;  # have we obtained & verified signatures?
  $pms->{dkim_signatures_dependable} = 0;
  # dkim_signatures_dependable =
  #   (signatures supplied by a caller) or
  #   ( (signatures obtained by this plugin) and
  #     (no signatures, or message was not truncated) )
  $pms->{dkim_signatures} = \@signatures;
  $pms->{dkim_valid_signatures} = \@valid_signatures;
  $pms->{arc_signatures} = \@arc_signatures;
  $pms->{arc_valid_signatures} = \@arc_valid_signatures;
  $pms->{dkim_signed} = 0;
  $pms->{arc_signed} = 0;
  $pms->{dkim_valid} = 0;
  $pms->{arc_valid} = 0;
  $pms->{dkim_key_testing} = 0;
  # the following hashes are keyed by a signing domain (SDID):
  $pms->{dkim_author_sig_tempfailed} = {}; # DNS timeout verifying author sign.
  $pms->{dkim_has_valid_author_sig} = {};  # a valid author domain signature
  $pms->{dkim_has_any_author_sig} = {};  # valid or invalid author domain sign.

  my $suppl_attrib = $pms->{msg}->{suppl_attrib};
  if (defined $suppl_attrib && exists $suppl_attrib->{dkim_signatures}) {
    # caller of SpamAssassin already supplied DKIM signature objects
    my $provided_signatures = $suppl_attrib->{dkim_signatures};
    @signatures = @$provided_signatures  if ref $provided_signatures;
    $pms->{dkim_signatures_ready} = 1;
    $pms->{dkim_signatures_dependable} = 1;
    dbg("dkim: DKIM signatures provided by the caller, %d signatures",
        scalar(@signatures));
  }
  if (defined $suppl_attrib && exists $suppl_attrib->{arc_signatures}) {
    # caller of SpamAssassin already supplied ARC signature objects
    my $provided_arc_signatures = $suppl_attrib->{arc_signatures};
    @arc_signatures = @$provided_arc_signatures  if ref $provided_arc_signatures;
    $pms->{arc_signatures_ready} = 1;
    $pms->{arc_signatures_dependable} = 1;
    dbg("dkim: ARC signatures provided by the caller, %d signatures",
        scalar(@arc_signatures));
  }

  if ($pms->{dkim_signatures_ready} or $pms->{arc_signatures_ready}) {
    # signatures already available and verified
    _check_valid_signature($self, $pms, $verifier, 'DKIM', \@signatures) if $self->{service_available};
    _check_valid_signature($self, $pms, $arc_verifier, 'ARC', \@arc_signatures) if $self->{arc_available};
  } elsif (!$pms->is_dns_available()) {
    dbg("dkim: signature verification disabled, DNS resolving not available");
  } elsif (!$self->_dkim_load_modules()) {
    # Mail::DKIM module not available
  } else {
    # signature objects not provided by the caller, must verify for ourselves
    my $timemethod = $self->{main}->time_method("check_dkim_signature");
    if (version->parse(Mail::DKIM::Verifier->VERSION) >= version->parse(0.40)) {
      my $edns = $conf->{dns_options}->{edns};
      if ($edns && $edns >= 1024) {
        # Let Mail::DKIM use our interface to Net::DNS::Resolver.
        # Only do so if EDNS0 provides a reasonably-sized UDP payload size,
        # as our interface does not provide a DNS fallback to TCP, unlike
        # the Net::DNS::Resolver::send which does provide it.
        # See also Bug 7265 regarding a choice of a resolver.
      # my $res = $self->{main}->{resolver}->get_resolver;
        my $res = $self->{main}->{resolver};
        dbg("dkim: providing our own resolver: %s", ref $res);
        Mail::DKIM::DNS::resolver($res);
      }
    }
    $verifier = Mail::DKIM::Verifier->new if $self->{service_available};
    _check_signature($self, $pms, $verifier, 'DKIM', \@signatures) if $self->{service_available};
    $arc_verifier = Mail::DKIM::ARC::Verifier->new if $self->{arc_available};
    _check_signature($self, $pms, $arc_verifier, 'ARC', \@arc_signatures) if $self->{arc_available};
  }
}

sub _check_signature {
  my($self, $pms, $verifier, $type, $signatures) = @_;

  my $sig_type = lc $type;
  $self->_get_authors($pms, $sig_type)  if !$pms->{"${sig_type}_author_addresses"};

  my(@valid_signatures);
  my $conf = $pms->{conf};
  if (!$verifier) {
    if ($type eq 'DKIM') {
      dbg("dkim: cannot create Mail::DKIM::Verifier object");
    } elsif ($type eq 'ARC') {
      dbg("dkim: cannot create Mail::DKIM::ARC::Verifier object");
    }
    return;
  } else {
    if ($type eq 'DKIM') {
      $pms->{dkim_verifier} = $verifier;
    } elsif ($type eq 'ARC') {
      $pms->{arc_verifier} = $verifier;
    }
  }
  # feed content of a message into verifier, using \r\n endings,
  # required by Mail::DKIM API (see bug 5300)
  # note: bug 5179 comment 28: perl does silly things on non-Unix platforms
  # unless we use \015\012 instead of \r\n
  eval {
    my $str = $pms->{msg}->get_pristine();
    if ($pms->{msg}->{line_ending} eq "\015\012") {
      # message already CRLF, just feed it
      $verifier->PRINT($str);
    } else {
      # feeding large chunk to Mail::DKIM is _much_ faster than line-by-line
      $str =~ s/\012/\015\012/gs; # LF -> CRLF
      $verifier->PRINT($str);
      undef $str;
    }
    1;
  } or do {  # intercept die() exceptions and render safe
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    dbg("dkim: verification failed, intercepted error: $eval_stat");
    return 0;           # cannot verify message
  };

  my $timeout = $conf->{dkim_timeout};
  my $timer = Mail::SpamAssassin::Timeout->new(
                { secs => $timeout, deadline => $pms->{master_deadline} });

  my $err = $timer->run_and_catch(sub {
    dbg("dkim: performing public $type key lookup and signature verification");
    $verifier->CLOSE();  # the action happens here

    # currently SpamAssassin's parsing is better than Mail::Address parsing,
    # don't bother fetching $verifier->message_originator->address
    # to replace what we already have in $pms->{dkim_author_addresses}

    # versions before 0.29 only provided a public interface to fetch one
    # signature, newer versions allow access to all signatures of a message
    @$signatures = $verifier->UNIVERSAL::can("signatures") ?
                               $verifier->signatures : $verifier->signature;
    if (would_log("dbg","dkim")) {
      foreach my $signature (@$signatures) {
        dbg("dkim: $type signature i=%s d=%s",
          map(!defined $_ ? '(undef)' : $_,
            $signature->identity, $signature->domain
          )
        );
      }
    }
  });
  if ($timer->timed_out()) {
    dbg("dkim: public key lookup or verification timed out after %s s",
        $timeout );
#***
  # $pms->{dkim_author_sig_tempfailed}->{$_} = 1  for ...

  } elsif ($err) {
    chomp $err;
    dbg("dkim: $type public key lookup or verification failed: $err");
  }
  if ($type eq 'DKIM') {
    $pms->{dkim_signatures_ready} = 1;
    if (!@$signatures || !$pms->{tests_already_hit}->{'__TRUNCATED'}) {
      $pms->{dkim_signatures_dependable} = 1;
    }
    _check_valid_signature($self, $pms, $verifier, 'DKIM', \@$signatures) if $self->{service_available};
  } elsif ($type eq 'ARC') {
    $pms->{arc_signatures_ready} = 1;
    if (!@$signatures || !$pms->{tests_already_hit}->{'__TRUNCATED'}) {
      $pms->{arc_signatures_dependable} = 1;
    }
    _check_valid_signature($self, $pms, $verifier, 'ARC', \@$signatures) if $self->{arc_available};
  }
}

sub _check_valid_signature {
  my($self, $pms, $verifier, $type, $signatures) = @_;

  my $sig_type = lc $type;
  $self->_get_authors($pms, $sig_type)  if !$pms->{"${sig_type}_author_addresses"};

  my(@valid_signatures);
  my $conf = $pms->{conf};
  # DKIM signatures check
  if ($pms->{"${sig_type}_signatures_ready"}) {
    my $sig_result_supported;
    # dkim_minimum_key_bits is evaluated for ARC signatures as well
    my $minimum_key_bits = $conf->{dkim_minimum_key_bits};
    foreach my $signature (@$signatures) {
      # old versions of Mail::DKIM would give undef for an invalid signature
      next if !defined $signature;
      $sig_result_supported = $signature->UNIVERSAL::can("result_detail");
      # test for empty selector (must not treat a selector "0" as missing!)
      next if !defined $signature->selector || $signature->selector eq "";

      my($info, $valid, $expired);
      $valid =
        ($sig_result_supported ? $signature : $verifier)->result eq 'pass';
      $info = $valid ? 'VALID' : 'FAILED';
      if ($valid && $signature->UNIVERSAL::can("check_expiration")) {
        $expired = !$signature->check_expiration;
        $info .= ' EXPIRED'  if $expired;
      }
      my $key_size;
      if ($valid && !$expired && $minimum_key_bits) {
        $key_size = eval { my $pk = $signature->get_public_key;
                           $pk && $pk->cork && $pk->cork->size * 8 };
        if ($key_size) {
          $signature->{_spamassassin_key_size} = $key_size; # stash it for later
          $info .= " WEAK($key_size)"  if $key_size < $minimum_key_bits;
        }
      }
      push(@valid_signatures, $signature)  if $valid && !$expired;

      # check if we have a potential Author Domain Signature, valid or not
      my ($d) = (defined $signature->identity)? $signature->identity =~ /\@(\S+)/ : ($signature->domain);
      if (!defined $d) {
        # can be undefined on a broken signature with missing required tags
      } else {
        $d = lc $d;
        if ($pms->{"${sig_type}_author_domains"}->{$d}) {  # SDID matches author domain
          $pms->{"${sig_type}_has_any_author_sig"}->{$d} = 1;
          if ($valid && !$expired &&
              $key_size && $key_size >= $minimum_key_bits) {
            $pms->{"${sig_type}_has_valid_author_sig"}->{$d} = 1;
          } elsif ( ($sig_result_supported ? $signature
                                           : $verifier)->result_detail
                   =~ /\b(?:timed out|SERVFAIL)\b/i) {
            $pms->{"${sig_type}_author_sig_tempfailed"}->{$d} = 1;
          }
        }
      }
      if ($type eq 'DKIM') {
        if (would_log("dbg","dkim")) {
          dbg("dkim: %s %s, i=%s, d=%s, s=%s, a=%s, c=%s, %s, %s, %s",
            $info,
            $signature->isa('Mail::DKIM::DkSignature') ? 'DK' : 'DKIM',
            map(!defined $_ ? '(undef)' : $_,
              $signature->identity, $d, $signature->selector,
              $signature->algorithm, scalar($signature->canonicalization),
              $key_size ? "key_bits=$key_size" : "unknown key size",
              ($sig_result_supported ? $signature : $verifier)->result ),
            defined $d && $pms->{dkim_author_domains}->{$d}
              ? 'matches author domain'
              : 'does not match author domain',
          );
        }
      } elsif ($type eq 'ARC') {
        if (would_log("dbg","dkim")) {
          dbg("dkim: %s %s, i=%s, d=%s, s=%s, a=%s, c=%s, %s, %s, %s",
            $info,
            $type,
            map(!defined $_ ? '(undef)' : $_,
              $signature->identity, $d, $signature->selector,
              $signature->algorithm, scalar($signature->canonicalization),
              $key_size ? "key_bits=$key_size" : "unknown key size",
              ($sig_result_supported ? $signature : $verifier)->result ),
            defined $d && $pms->{arc_author_domains}->{$d}
              ? 'matches author domain'
              : 'does not match author domain',
          );
        }
      }
    }

    if (@valid_signatures) {
      if ($type eq 'DKIM') {
        $pms->{dkim_signed} = 1;
        $pms->{dkim_valid} = 1;

        # supply values for both tags
        my(%seen1, %seen2, %seen3, @identity_list, @domain_list, @selector_list);
        @identity_list = grep(defined $_ && $_ ne '' && !$seen1{$_}++,
                            map($_->identity, @valid_signatures));
        @domain_list =   grep(defined $_ && $_ ne '' && !$seen2{$_}++,
                            map($_->domain, @valid_signatures));
        @selector_list = grep(defined $_ && $_ ne '' && !$seen3{$_}++,
                            map($_->selector, @valid_signatures));
        $pms->set_tag('DKIMIDENTITY',
                    @identity_list == 1 ? $identity_list[0] : \@identity_list);
        $pms->set_tag('DKIMDOMAIN',
                    @domain_list == 1   ? $domain_list[0]   : \@domain_list);
        $pms->set_tag('DKIMSELECTOR',
                    @selector_list == 1 ? $selector_list[0] : \@selector_list);
      } elsif ($type eq 'ARC') {
        $pms->{arc_signed} = 1;
        $pms->{arc_valid} = 1;
      }
      # let the result stand out more clearly in the log, use uppercase
      my $sig = $valid_signatures[0];
      my $sig_res = ($sig_result_supported ? $sig : $verifier)->result_detail;
      dbg("dkim: $type signature verification result: %s", uc($sig_res));

    } elsif (@$signatures) {
      if ($type eq 'DKIM') {
        $pms->{dkim_signed} = 1;
      } elsif ($type eq 'ARC') {
        $pms->{arc_signed} = 1;
      }
      my $sig = @$signatures[0];
      my $sig_res = ($sig_result_supported ? $sig : $verifier)->result_detail;
      dbg("dkim: $type signature verification result: %s", uc($sig_res));

    } else {
      dbg("dkim: $type signature verification result: none");
    }
  }
}

sub _check_dkim_adsp {
  my ($self, $pms) = @_;

  $pms->{dkim_checked_adsp} = 1;

  # a message may have multiple authors (RFC 5322),
  # and hence multiple signing policies (RFC 5617)
  $pms->{dkim_adsp} = {};  # a hash: author_domain => adsp
  my $practices_as_string = '';

  $self->_get_authors($pms, 'dkim')  if !$pms->{dkim_author_addresses};

  # collect only fully qualified domain names, allow '-', think of IDN
  my @author_domains = grep { /.\.[a-z-]{2,}\z/si }
                            keys %{$pms->{dkim_author_domains}};

  my %label =
   ('D' => 'discardable', 'A' => 'all', 'U' => 'unknown', 'N' => 'nxdomain',
    '1' => 'custom_low', '2' => 'custom_med', '3' => 'custom_high');

  # must check the message first to obtain signer, domain, and verif. status
  $self->_check_dkim_signature($pms)  if !$pms->{dkim_checked_signature};

  if (!$pms->{dkim_signatures_ready}) {
    dbg("dkim: adsp not retrieved, signatures not obtained");

  } elsif (!@author_domains) {
    dbg("dkim: adsp not retrieved, no author f.q. domain name");
    $practices_as_string = 'no author domains, ignored';

  } else {

    foreach my $author_domain (@author_domains) {
      my $adsp;

      if ($pms->{dkim_has_valid_author_sig}->{$author_domain}) {
        # don't fetch adsp when valid
        # RFC 5617: If a message has an Author Domain Signature, ADSP provides
        # no benefit relative to that domain since the message is already known
        # to be compliant with any possible ADSP for that domain. [...]
        # implementations SHOULD avoid doing unnecessary DNS lookups
        #
        dbg("dkim: adsp not retrieved, author domain signature is valid");
        $practices_as_string = 'valid a. d. signature';

      } elsif ($pms->{dkim_author_sig_tempfailed}->{$author_domain}) {
        dbg("dkim: adsp ignored, tempfail varifying author domain signature");
        $practices_as_string = 'pub key tempfailed, ignored';

      } elsif ($pms->{dkim_has_any_author_sig}->{$author_domain} &&
               !$pms->{dkim_signatures_dependable}) {
        # the message did have an Author Domain Signature but it wasn't valid;
        # we also believe the message was truncated just before being passed
        # to SpamAssassin, which is a likely reason for verification failure,
        # so we shouldn't take it too harsh with ADSP rules - just pretend
        # the ADSP was 'unknown'
        #
        dbg("dkim: adsp ignored, message was truncated, ".
            "invalid author domain signature");
        $practices_as_string = 'truncated, ignored';

      } else {
        # search the adsp_override list

        # for a domain a.b.c.d it searches the hash in the following order:
        #   a.b.c.d
        #   *.b.c.d
        #     *.c.d
        #       *.d
        #         *
        my $matched_key;
        my $p = $pms->{conf}->{adsp_override};
        if ($p) {
          my @d = split(/\./, $author_domain);
          @d = map { shift @d; join('.', '*', @d) } (0..$#d);
          for my $key ($author_domain, @d) {
            $adsp = $p->{$key};
            if (defined $adsp) { $matched_key = $key; last }
          }
        }

        if (defined $adsp) {
          dbg("dkim: adsp override for domain %s", $author_domain);
          $practices_as_string = 'override';
          $practices_as_string .=
            " by $matched_key"  if $matched_key ne $author_domain;

        } elsif (!$pms->is_dns_available()) {
          dbg("dkim: adsp not retrieved, DNS resolving not available");

        } elsif (!$self->_dkim_load_modules()) {
          dbg("dkim: adsp not retrieved, module Mail::DKIM not available");

        } else {  # do the ADSP DNS lookup
          my $timemethod = $self->{main}->time_method("check_dkim_adsp");

          my $practices;  # author domain signing practices object
          my $timeout = $pms->{conf}->{dkim_timeout};
          my $timer = Mail::SpamAssassin::Timeout->new(
                    { secs => $timeout, deadline => $pms->{master_deadline} });
          my $err = $timer->run_and_catch(sub {
            eval {
              if (Mail::DKIM::AuthorDomainPolicy->UNIVERSAL::can("fetch")) {
                my $author_domain_ace = idn_to_ascii($author_domain);
                dbg("dkim: adsp: performing lookup on _adsp._domainkey.%s",
                    $author_domain_ace);
                # get our Net::DNS::Resolver object
                my $res = $self->{main}->{resolver}->get_resolver;
                $practices = Mail::DKIM::AuthorDomainPolicy->fetch(
                               Protocol => "dns", Domain => $author_domain_ace,
                               DnsResolver => $res);
              }
              1;
            } or do {
              # fetching/parsing adsp record may throw error, ignore such s.p.
              my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
              dbg("dkim: adsp: fetch or parse on domain %s failed: %s",
                  $author_domain, $eval_stat);
              undef $practices;
            };
          });
          if ($timer->timed_out()) {
            dbg("dkim: adsp lookup on domain %s timed out after %s seconds",
                $author_domain, $timeout);
          } elsif ($err) {
            chomp $err;
            dbg("dkim: adsp lookup on domain %s failed: %s",
                $author_domain, $err);
          } else {
            my $sp;  # ADSP: unknown / all / discardable
            ($sp) = $practices->policy  if $practices;
            if (!defined $sp || $sp eq '') {  # SERVFAIL or a timeout
              dbg("dkim: signing practices on %s unavailable", $author_domain);
              $adsp = 'U';
              $practices_as_string = 'dns: no result';
            } else {
              $adsp = $sp eq "unknown"      ? 'U'  # most common
                    : $sp eq "all"          ? 'A'
                    : $sp eq "discardable"  ? 'D'  # ADSP
                    : $sp eq "strict"       ? 'D'  # old style SSP
                    : uc($sp) eq "NXDOMAIN" ? 'N'
                                            : 'U';
              $practices_as_string = 'dns: ' . $sp;
            }
          }
        }
      }

      # is signing practices available?
      $pms->{dkim_adsp}->{$author_domain} = $adsp  if defined $adsp;

      dbg("dkim: adsp result: %s (%s), author domain '%s'",
          !defined($adsp) ? '-' : $adsp.'/'.$label{$adsp},
          $practices_as_string, $author_domain);
    }
  }
}

sub _check_dkim_welcomelist {
  my ($self, $pms) = @_;

  $pms->{welcomelist_checked} = 1;

  $self->_get_authors($pms, 'dkim')  if !$pms->{dkim_author_addresses};

  my $authors_str = join(", ", @{$pms->{dkim_author_addresses}});
  if ($authors_str eq '') {
    dbg("dkim: check_dkim_weclomelist: could not find author address");
    return;
  }

  # collect welcomelist entries matching the author from all lists
  my @acceptable_sdid_tuples;
  $self->_wlcheck_acceptable_signature($pms, \@acceptable_sdid_tuples,
                                       'def_welcomelist_from_dkim');
  $self->_wlcheck_author_signature($pms, \@acceptable_sdid_tuples,
                                       'def_welcomelist_auth');
  $self->_wlcheck_acceptable_signature($pms, \@acceptable_sdid_tuples,
                                       'welcomelist_from_dkim');
  $self->_wlcheck_author_signature($pms, \@acceptable_sdid_tuples,
                                       'welcomelist_auth');
  if (!@acceptable_sdid_tuples) {
    dbg("dkim: no wl entries match author %s, no need to verify sigs",
        $authors_str);
    return;
  }

  # if the message doesn't pass DKIM validation, it can't pass DKIM welcomelist

  # trigger a DKIM check;
  # continue if one or more signatures are valid or we want the debug info
  return unless $self->check_dkim_valid($pms) || would_log("dbg","dkim");
  return unless $pms->{dkim_signatures_ready};

  # now do all the matching in one go, against all signatures in a message
  my($any_match_at_all, $any_match_by_wl_ref) =
    _wlcheck_list($self, $pms, \@acceptable_sdid_tuples);

  my(@valid,@fail);
  foreach my $wl (keys %$any_match_by_wl_ref) {
    my $match = $any_match_by_wl_ref->{$wl};
    if (defined $match) {
      $pms->{"dkim_match_in_$wl"} = 1  if $match;
      push(@{$match ? \@valid : \@fail}, "$wl/$match");
    }
  }
  if (@valid) {
    dbg("dkim: author %s, WELCOMELISTED by %s",
        $authors_str, join(", ",@valid));
  } elsif (@fail) {
    dbg("dkim: author %s, found in %s BUT IGNORED",
        $authors_str, join(", ",@fail));
  } else {
    dbg("dkim: author %s, not in any dkim welcomelist", $authors_str);
  }
}

# check for verifier-acceptable signatures; an empty (or undefined) signing
# domain in a welcomelist implies checking for an Author Domain Signature
#
sub _wlcheck_acceptable_signature {
  my ($self, $pms, $acceptable_sdid_tuples_ref, $wl) = @_;
  my $wl_ref = $pms->{conf}->{$wl};
  foreach my $author (@{$pms->{dkim_author_addresses}}) {
    my $author_lc = lc($author);
    foreach my $welcome_addr (keys %$wl_ref) {
      my $wl_addr_ref = $wl_ref->{$welcome_addr};
    # dbg("dkim: WL %s %s, d: %s", $wl, $welcome_addr,
    #     join(", ", map { $_ eq '' ? "''" : $_ } @{$wl_addr_ref->{domain}}));
      if ($author_lc =~ /$wl_addr_ref->{re}/) {
        foreach my $sdid (@{$wl_addr_ref->{domain}}) {
          push(@$acceptable_sdid_tuples_ref, [$author,$sdid,$wl,$welcome_addr]);
        }
      }
    }
  }
}

# use a traditional welcomelist_from -style addrlist, the only acceptable DKIM
# signature is an Author Domain Signature.  Note: don't pre-parse and store
# domains; that's inefficient memory-wise and only saves one m//
#
sub _wlcheck_author_signature {
  my ($self, $pms, $acceptable_sdid_tuples_ref, $wl) = @_;
  my $wl_ref = $pms->{conf}->{$wl};
  foreach my $author (@{$pms->{dkim_author_addresses}}) {
    my $author_lc = lc($author);
    foreach my $welcome_addr (keys %$wl_ref) {
    # dbg("dkim: WL %s %s", $wl, $welcome_addr);
      if ($author_lc =~ /$wl_ref->{$welcome_addr}/) {
        push(@$acceptable_sdid_tuples_ref, [$author,undef,$wl,$welcome_addr]);
      }
    }
  }
}

sub _wlcheck_list {
  my ($self, $pms, $acceptable_sdid_tuples_ref) = @_;

  my %any_match_by_wl;
  my $any_match_at_all = 0;
  my $verifier = $pms->{dkim_verifier};
  my $minimum_key_bits = $pms->{conf}->{dkim_minimum_key_bits};

  # walk through all signatures present in a message
  foreach my $signature (@{$pms->{dkim_signatures}}) {
    # old versions of Mail::DKIM would give undef for an invalid signature
    next if !defined $signature;
    my $sig_result_supported = $signature->UNIVERSAL::can("result_detail");
    # test for empty selector (must not treat a selector "0" as missing!)
    next if !defined $signature->selector || $signature->selector eq "";

    my($info, $valid, $expired, $key_size_weak);
    $valid =
      ($sig_result_supported ? $signature : $verifier)->result eq 'pass';
    $info = $valid ? 'VALID' : 'FAILED';
    if ($valid && $signature->UNIVERSAL::can("check_expiration")) {
      $expired = !$signature->check_expiration;
      $info .= ' EXPIRED'  if $expired;
    }
    if ($valid && !$expired && $minimum_key_bits) {
      my $key_size = $signature->{_spamassassin_key_size};
      if ($key_size && $key_size < $minimum_key_bits) {
        $info .= " WEAK($key_size)"; $key_size_weak = 1;
      }
    }

    my ($sdid) = (defined $signature->identity)? $signature->identity =~ /\@(\S+)/ : ($signature->domain);
    $sdid = lc $sdid  if defined $sdid;

    my %tried_authors;
    foreach my $entry (@$acceptable_sdid_tuples_ref) {
      my($author, $acceptable_sdid, $wl, $welcome_addr) = @$entry;
      # $welcome_addr and $wl are here for logging purposes only, already checked.
      # The $acceptable_sdid is a verifier-acceptable signing domain
      # identifier (to be matched against a 'd' tag in signatures).
      # When $acceptable_sdid is undef or an empty string it implies
      # a check for Author Domain Signature.

      local $1;
      my $author_domain = $author !~ /\@([^\@]+)\z/s ? '' : lc $1;
      $tried_authors{$author} = 1;  # for logging purposes

      my $matches = 0;
      if (!defined $sdid) {
        # don't bother, invalid signature with a missing 'd' or 'i' tag

      } elsif (!defined $acceptable_sdid || $acceptable_sdid eq '') {
        # An "Author Domain Signature" (sometimes called a first-party
        # signature) is a Valid Signature in which the domain name of the
        # DKIM signing entity, i.e., the d= tag in the DKIM-Signature header
        # field, is the same as the domain name in the Author Address.
        # Following [RFC5321], domain name comparisons are case insensitive.

        # checking for Author Domain Signature
        $matches = 1  if $sdid eq $author_domain;

      } else {  # checking for verifier-acceptable signature
        # The second argument to a 'welcomelist_from_dkim' option is now (since
        # version 3.3.0) supposed to be a signing domain (SDID), no longer an
        # identity (AUID). Nevertheless, be prepared to accept the full e-mail
        # address there for compatibility, and just ignore its local-part.

        $acceptable_sdid = $1  if $acceptable_sdid =~ /\@([^\@]*)\z/s;
        if ($acceptable_sdid =~ s/^\*?\.//s) {
          $matches = 1  if $sdid =~ /\.\Q$acceptable_sdid\E\z/si;
        } else {
          $matches = 1  if $sdid eq lc $acceptable_sdid;
        }
      }
      if ($matches) {
        if (would_log("dbg","dkim")) {
          if ($sdid eq $author_domain) {
            dbg("dkim: %s author domain signature by %s, MATCHES %s %s",
                $info, $sdid, $wl, $welcome_addr);
          } else {
            dbg("dkim: %s third-party signature by %s, author domain %s, ".
                "MATCHES %s %s", $info, $sdid, $author_domain, $wl, $welcome_addr);
          }
        }
        # a defined value indicates at least a match, not necessarily valid
        # (this complication servers to preserve logging compatibility)
        $any_match_by_wl{$wl} = ''  if !exists $any_match_by_wl{$wl};
      }
      # only valid signature can cause welcomelisting
      $matches = 0  if !$valid || $expired || $key_size_weak;

      if ($matches) {
        $any_match_at_all = 1;
        $any_match_by_wl{$wl} = $sdid;  # value used for debug logging
      }
    }
    dbg("dkim: %s signature by %s, author %s, no valid matches",
        $info,  defined $sdid ? $sdid : '(undef)',
        join(", ", keys %tried_authors))  if !$any_match_at_all;
  }
  return ($any_match_at_all, \%any_match_by_wl);
}

# Version features
sub has_arc { 1 }

1;
