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

 full   DKIM_SIGNED           eval:check_dkim_signed()
 full   DKIM_VALID            eval:check_dkim_valid()
 full   DKIM_VALID_AU         eval:check_dkim_valid_author_sig()
 full   __DKIM_DEPENDABLE     eval:check_dkim_dependable()

 header DKIM_ADSP_NXDOMAIN    eval:check_dkim_adsp('N')
 header DKIM_ADSP_ALL         eval:check_dkim_adsp('A')
 header DKIM_ADSP_DISCARD     eval:check_dkim_adsp('D')
 header DKIM_ADSP_CUSTOM_LOW  eval:check_dkim_adsp('1')
 header DKIM_ADSP_CUSTOM_MED  eval:check_dkim_adsp('2')
 header DKIM_ADSP_CUSTOM_HIGH eval:check_dkim_adsp('3')

 describe DKIM_SIGNED       Message has a DKIM or DK signature, not necessarily valid
 describe DKIM_VALID        Message has at least one valid DKIM or DK signature
 describe DKIM_VALID_AU     Message has a valid DKIM or DK signature from author's domain
 describe __DKIM_DEPENDABLE A validation failure not attributable to truncation

 describe DKIM_ADSP_NXDOMAIN    No valid author signature and domain not in DNS
 describe DKIM_ADSP_ALL         No valid author signature, domain signs all mail
 describe DKIM_ADSP_DISCARD     No valid author signature, domain signs all mail and suggests discarding mail with no valid author signature
 describe DKIM_ADSP_CUSTOM_LOW  No valid author signature, adsp_override is CUSTOM_LOW
 describe DKIM_ADSP_CUSTOM_MED  No valid author signature, adsp_override is CUSTOM_MED
 describe DKIM_ADSP_CUSTOM_HIGH No valid author signature, adsp_override is CUSTOM_HIGH

For compatibility, the following are synonyms:
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

  _DKIMIDENTITY_  signing identities (the 'i' tag) from valid signatures;
  _DKIMDOMAIN_    signing domains (the 'd' tag) from valid signatures;

Identities and domains from signatures which failed verification are not
included in these tags. Duplicates are eliminated (e.g. when there are two or
more valid signatures from the same signer, only one copy makes it into a tag).
Note that there may be more than one signature in a message - currently they
are provided as a space-separated list, although this behaviour may change.

=head1 SEE ALSO

C<Mail::DKIM>, C<Mail::SpamAssassin::Plugin>

  http://jason.long.name/dkimproxy/
  http://tools.ietf.org/rfc/rfc4871.txt
  http://tools.ietf.org/rfc/rfc4870.txt
  http://ietf.org/html.charters/dkim-charter.html
  draft-ietf-dkim-ssp-09

=cut

package Mail::SpamAssassin::Plugin::DKIM;

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

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # signatures
  $self->register_eval_rule("check_dkim_signed");
  $self->register_eval_rule("check_dkim_valid");
  $self->register_eval_rule("check_dkim_valid_author_sig");
  $self->register_eval_rule("check_dkim_testing");

  # author domain signing practices
  $self->register_eval_rule("check_dkim_adsp");
  $self->register_eval_rule("check_dkim_dependable");

  # whitelisting
  $self->register_eval_rule("check_for_dkim_whitelist_from");
  $self->register_eval_rule("check_for_def_dkim_whitelist_from");

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

=item whitelist_from_dkim author@example.com [signing-identity]

Use this to supplement the whitelist_from addresses with a check to make
sure the message with a given From address (the author's address) carries a
valid Domain Keys Identified Mail (DKIM) signature by a verifier-acceptable
signing-identity (the i= tag).

Only one whitelist entry is allowed per line, as in C<whitelist_from_rcvd>.
Multiple C<whitelist_from_dkim> lines are allowed. File-glob style characters
are allowed for the From address (the first parameter), just like with
C<whitelist_from_rcvd>. The second parameter does not accept wildcards.

If no signing identity parameter is specified, the only acceptable signature
will be a first-party signature, i.e. the so called author signature, which
is a signature where the signing identity of a signature matches the author
address (i.e. the address in a From header field).

Since this whitelist requires a DKIM check to be made, network tests must
be enabled.

Examples of whitelisting based on an author signature (first-party):

  whitelist_from_dkim joe@example.com
  whitelist_from_dkim *@corp.example.com
  whitelist_from_dkim *@*.example.com

Examples of whitelisting based on third-party signatures:

  whitelist_from_dkim rick@example.net     richard@example.net
  whitelist_from_dkim rick@sub.example.net example.net
  whitelist_from_dkim jane@example.net     example.org
  whitelist_from_dkim *@info.example.com   example.com
  whitelist_from_dkim *@*                  remailer.example.com

=item def_whitelist_from_dkim author@example.com [signing-identity]

Same as C<whitelist_from_dkim>, but used for the default whitelist entries
in the SpamAssassin distribution.  The whitelist score is lower, because
these are often targets for abuse of public mailers which sign their mail.

=item adsp_override domain [signing_practices]

Currently few domains publish their signing practices (draft-ietf-dkim-ssp,
ADSP), partly because the ADSP draft/rfc is rather new, partly because they
think hardly any recipient bothers to check it, and partly for fear that
some recipients might lose mail due to problems in their signature validation
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

According to ADSP draft, signing practices can be one of the following:
C<unknown>, C<all> and C<discardable>.

C<unknown>: Messages from this domain might or might not have an author
signature. This is a default if a domain exists in DNS but no ADSP record
is found.

C<all>: All messages from this domain are signed with an Author Signature.

C<discardable>: All messages from this domain are signed with an Author
Signature. If a message arrives without a valid Author Signature, the domain
encourages the recipient(s) to discard it.

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
for domains not existing in DNS. (Note: domain validity may be unchecked
with current versions of Mail::DKIM, so C<nxdomain> may never turn up.)

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
than one of these rules can fire. The last three can only result from a
'signing_practices' as given in a C<adsp_override> directive (not from a
DNS lookup), and can serve as a convenient means of providing a different
score if scores assigned to DKIM_ADSP_ALL or DKIM_ADSP_DISCARD are not
considered suitable for some domains.

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

=cut

  push (@cmds, {
    setting => 'whitelist_from_dkim',
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
      my $identity = defined $2 ? $2 : '';  # empty implies author signature
      $self->{parser}->add_to_addrlist_rcvd('whitelist_from_dkim',
                                            $address, $identity);
    }
  });

  push (@cmds, {
    setting => 'def_whitelist_from_dkim',
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
      my $identity = defined $2 ? $2 : '';  # empty implies author signature
      $self->{parser}->add_to_addrlist_rcvd('def_whitelist_from_dkim',
                                            $address, $identity);
    }
  });

  push (@cmds, {
    setting => 'adsp_override',
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

=back

=head1 ADMINISTRATOR SETTINGS

=over 4

=item dkim_timeout n             (default: 5)

How many seconds to wait for a DKIM query to complete, before
scanning continues without the DKIM result.

=cut

  push (@cmds, {
    setting => 'dkim_timeout',
    is_admin => 1,
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

  $conf->{parser}->register_commands(\@cmds);
}

# ---------------------------------------------------------------------------

sub check_dkim_signed {
  my ($self, $pms) = @_;
  $self->_check_dkim_signature($pms) unless $pms->{dkim_checked_signature};
  return $pms->{dkim_signed};
}

sub check_dkim_valid_author_sig {
  my ($self, $pms) = @_;
  $self->_check_dkim_signature($pms) unless $pms->{dkim_checked_signature};
  return $pms->{dkim_has_valid_author_sig};
}

sub check_dkim_valid {
  my ($self, $pms) = @_;
  $self->_check_dkim_signature($pms) unless $pms->{dkim_checked_signature};
  return $pms->{dkim_valid};
}

sub check_dkim_dependable {
  my ($self, $pms) = @_;
  $self->_check_dkim_signature($pms) unless $pms->{dkim_checked_signature};
  return $pms->{dkim_signatures_dependable};
}

# mosnomer, old synonym for check_dkim_valid, kept for compatibility
sub check_dkim_verified {
  my ($self, $pms) = @_;
  $self->_check_dkim_signature($pms) unless $pms->{dkim_checked_signature};
  return $pms->{dkim_valid};
}

# no valid author signature && ADSP matches the argument
sub check_dkim_adsp {
  my ($self, $pms, $adsp_char) = @_;
  $self->_check_dkim_signature($pms) unless $pms->{dkim_checked_signature};
  if ($pms->{dkim_signatures_ready} && !$pms->{dkim_has_valid_author_sig}) {
    $self->_check_dkim_adsp($pms) unless $pms->{dkim_checked_adsp};
    return 1  if $pms->{dkim_adsp} eq $adsp_char;
  }
  return 0;
}

# useless, semantically always true according to the current SSP/ADSP draft
sub check_dkim_signsome {
  my ($self, $pms) = @_;
  # the signsome is semantically always true, and thus redundant;
  # for compatibility just returns false to prevent
  # a rule DKIM_POLICY_SIGNSOME from always firing
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
  $self->_check_dkim_signature($pms) unless $pms->{dkim_checked_signature};
  $result = 1  if $pms->{dkim_key_testing};
  return $result;
}

sub check_for_dkim_whitelist_from {
  my ($self, $pms) = @_;
  $self->_check_dkim_whitelist($pms) unless $pms->{whitelist_checked};
  return $pms->{dkim_match_in_whitelist_from_dkim} || 
         $pms->{dkim_match_in_whitelist_auth};
}

sub check_for_def_dkim_whitelist_from {
  my ($self, $pms) = @_;
  $self->_check_dkim_whitelist($pms) unless $pms->{whitelist_checked};
  return $pms->{dkim_match_in_def_whitelist_from_dkim} || 
         $pms->{dkim_match_in_def_whitelist_auth};
}

# ---------------------------------------------------------------------------

sub _dkim_load_modules {
  my ($self) = @_;

  return $self->{tried_loading} if defined $self->{tried_loading};
  $self->{tried_loading} = 0;

  my $timemethod = $self->{main}->UNIVERSAL::can("time_method") &&
                   $self->{main}->time_method("dkim_load_modules");
  my $eval_stat;
  eval {
    # Have to do this so that RPM doesn't find these as required perl modules.
    { require Mail::DKIM; require Mail::DKIM::Verifier;
      require Mail::DKIM::DkimPolicy;
      eval { require Mail::DKIM::AuthorDomainPolicy }; # since Mail::DKIM 0.34
    }
  } or do {
    $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
  };

  if (!defined($eval_stat)) {
    my $version = Mail::DKIM::Verifier->VERSION;
    if ($version >= 0.31) {
      dbg("dkim: using Mail::DKIM version $version for DKIM checks");
    } else {
      warn("dkim: Mail::DKIM $version is older than the required ".
           "minimal version 0.31, suggested upgrade to 0.35 or later!\n");
    }
    $self->{tried_loading} = 1;
  } else {
    dbg("dkim: cannot load Mail::DKIM module, DKIM checks disabled: $eval_stat");
  }
}

# ---------------------------------------------------------------------------

sub _check_dkim_signature {
  my ($self, $pms) = @_;

  my($verifier, @signatures, @valid_signatures);
  $pms->{dkim_checked_signature} = 1; # has this sub already been invoked?
  $pms->{dkim_signatures_ready} = 0;  # have we obtained & verified signatures?
  $pms->{dkim_signatures_dependable} = 0;
  # dkim_signatures_dependable =
  #   (signatures supplied by a caller) or
  #   ( (signatures obtained by this plugin) and
  #     (no signatures, or message was not truncated) )
  $pms->{dkim_author_sig_tempfailed} = 0;  # DNS timeout verifying author sign.
  $pms->{dkim_signatures} = \@signatures;
  $pms->{dkim_valid_signatures} = \@valid_signatures;
  $pms->{dkim_signed} = 0;
  $pms->{dkim_valid} = 0;
  $pms->{dkim_has_valid_author_sig} = 0;
  $pms->{dkim_has_any_author_sig} = 0;  # valid or invalid author signature
  $pms->{dkim_key_testing} = 0;
  $pms->{dkim_author_address} =
    $pms->get('from:addr',undef)  if !defined $pms->{dkim_author_address};

  my $suppl_attrib = $pms->{msg}->{suppl_attrib};
  if (defined $suppl_attrib && exists $suppl_attrib->{dkim_signatures}) {
    # caller of SpamAssassin already supplied DKIM signature objects
    my $provided_signatures = $suppl_attrib->{dkim_signatures};
    @signatures = @$provided_signatures  if ref $provided_signatures;
    $pms->{dkim_signatures_ready} = 1;
    $pms->{dkim_signatures_dependable} = 1;
    dbg("dkim: signatures provided by the caller, %d signatures",
        scalar(@signatures));
  }

  if ($pms->{dkim_signatures_ready}) {
    # signatures already available and verified
  } elsif (!$pms->is_dns_available()) {
    dbg("dkim: signature verification disabled, DNS resolving not available");
  } elsif (!$self->_dkim_load_modules()) {
    # Mail::DKIM module not available
  } else {
    # signature objects not provided by the caller, must verify for ourselves
    my $timemethod = $self->{main}->UNIVERSAL::can("time_method") &&
                     $self->{main}->time_method("check_dkim_signature");
    $verifier = Mail::DKIM::Verifier->new();
    if (!$verifier) {
      dbg("dkim: cannot create Mail::DKIM::Verifier object");
      return;
    }
    $pms->{dkim_verifier} = $verifier;
    #
    # feed content of a message into verifier, using \r\n endings,
    # required by Mail::DKIM API (see bug 5300)
    # note: bug 5179 comment 28: perl does silly things on non-Unix platforms
    # unless we use \015\012 instead of \r\n
    eval {
      my $str = $pms->{msg}->get_pristine;
      $str =~ s/\r?\n/\015\012/sg;  # ensure \015\012 ending
      # feeding large chunks to Mail::DKIM is much faster than line-by-line
      $verifier->PRINT($str);
      1;
    } or do {  # intercept die() exceptions and render safe
      my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
      dbg("dkim: verification failed, intercepted error: $eval_stat");
      return 0;           # cannot verify message
    };

    my $timeout = $pms->{conf}->{dkim_timeout};
    my $timer = Mail::SpamAssassin::Timeout->new({ secs => $timeout });

    my $err = $timer->run_and_catch(sub {
      dbg("dkim: performing public key lookup and signature verification");
      $verifier->CLOSE();  # the action happens here

      # currently SpamAssassin's parsing is better than Mail::Address parsing,
      # don't bother fetching $verifier->message_originator->address
      # to replace what we already have in $pms->{dkim_author_address}

      # versions before 0.29 only provided a public interface to fetch one
      # signature, newer versions allow access to all signatures of a message
      @signatures = $verifier->UNIVERSAL::can("signatures") ?
                                 $verifier->signatures : $verifier->signature;
    });
    if ($timer->timed_out()) {
      dbg("dkim: public key lookup or verification timed out after %s s",
          $timeout );
      $pms->{dkim_author_sig_tempfailed} = 1;
    } elsif ($err) {
      chomp $err;
      dbg("dkim: public key lookup or verification failed: $err");
    }
    $pms->{dkim_signatures_ready} = 1;
    if (!@signatures || !$pms->{tests_already_hit}->{'__TRUNCATED'}) {
      $pms->{dkim_signatures_dependable} = 1;
    }
  }

  if ($pms->{dkim_signatures_ready}) {
    # ADSP+RFC5321: localpart is case sensitive, domain is case insensitive
    my $author = $pms->{dkim_author_address};
    local($1,$2);
    $author = ''  if !defined $author;
    $author = $1 . lc($2)  if $author =~ /^(.*)(\@[^\@]*)\z/s;

    my $sig_result_supported;
    foreach my $signature (@signatures) {
      # old versions of Mail::DKIM would give undef for an invalid signature
      next if !defined $signature;
      $sig_result_supported = $signature->UNIVERSAL::can("result_detail");
      #
      # i=  Identity of the user or agent (e.g., a mailing list manager) on
      #     behalf of which this message is signed (dkim-quoted-printable;
      #     OPTIONAL, default is an empty local-part followed by an "@"
      #     followed by the domain from the "d=" tag).
      my $identity = $signature->identity;
      $identity = $1 . lc($2)  if defined $identity &&
                                  $identity =~ /^(.*)(\@[^\@]*)\z/s;
      my $valid =
        ($sig_result_supported ? $signature : $verifier)->result eq 'pass';
      my $expired = 0;
      if ($valid && $signature->UNIVERSAL::can("check_expiration")) {
        $expired = !$signature->check_expiration;
      }
      # check if we have a potential author signature, valid or not
      my $id_matches_author = 0;
      if (!defined $identity || $identity eq '') {
        # identity not provided
      } elsif ($identity =~ /.\@[^\@]*\z/s) {  # identity has a localpart
        $id_matches_author = 1  if $author eq $identity;
      } elsif ($author =~ /(\@[^\@]*)?\z/s && defined $1 && $1 eq $identity) {
        # ignoring localpart if identity doesn't have a localpart
        $id_matches_author = 1;
      }
      push(@valid_signatures, $signature)  if $valid && !$expired;
      if ($id_matches_author) {
        $pms->{dkim_has_any_author_sig} = 1;
        if ($valid && !$expired) {
          $pms->{dkim_has_valid_author_sig} = 1;
        } elsif (
            ($sig_result_supported ? $signature : $verifier)->result_detail
            =~ /\b(?:timed out|SERVFAIL)\b/i) {
          $pms->{dkim_author_sig_tempfailed} = 1;
        }
      }
      would_log("dbg","dkim") &&
        dbg("dkim: i=%s, d=%s, a=%s, c=%s, %s%s, %s",
          defined $identity ? $identity : 'UNDEF',  $signature->domain,
          $signature->algorithm, scalar($signature->canonicalization),
          ($sig_result_supported ? $signature : $verifier)->result,
          !$expired ? '' : ', expired',
          $id_matches_author ? 'matches author' : 'does not match author');
    }
    if (@valid_signatures) {
      $pms->{dkim_signed} = 1;
      $pms->{dkim_valid} = 1;
      # let the result stand out more clearly in the log, use uppercase
      my $sig = $valid_signatures[0];
      my $sigres = ($sig_result_supported ? $sig : $verifier)->result_detail;
      dbg("dkim: signature verification result: %s", uc($sigres));
      my(%seen1,%seen2);
      $pms->set_tag('DKIMIDENTITY',
              join(" ", grep { defined($_) && $_ ne '' && !$seen1{$_}++ }
                         map { $_->identity } @valid_signatures));
      $pms->set_tag('DKIMDOMAIN',
              join(" ", grep { defined($_) && $_ ne '' && !$seen2{$_}++ }
                         map { $_->domain } @valid_signatures));
    } elsif (@signatures) {
      $pms->{dkim_signed} = 1;
      my $sig = $signatures[0];
      my $sigres =
        ($sig_result_supported && $sig ? $sig : $verifier)->result_detail;
      dbg("dkim: signature verification result: %s", uc($sigres));
    } else {
      dbg("dkim: signature verification result: none");
    }
  }
}

sub _lookup_dkim_adsp_override {
  my ($self, $pms, $author_domain) = @_;
  # for a domain a.b.c.d it searches the hash in the following order:
  #   a.b.c.d
  #   *.b.c.d
  #     *.c.d
  #       *.d
  #         *
  my($adsp,$matched_key);
  my $p = $pms->{conf}->{adsp_override};
  if ($p) {
    my @d = split(/\./, $author_domain);
    @d = map { shift @d; join('.', '*', @d) } (0..$#d);
    for my $key ($author_domain, @d) {
      $adsp = $p->{$key};
      if (defined $adsp) { $matched_key = $key; last }
    };
  }
  return !defined $adsp ? () : ($adsp,$matched_key);
}

sub _check_dkim_adsp {
  my ($self, $pms) = @_;

  $pms->{dkim_checked_adsp} = 1;
  $pms->{dkim_adsp} = 'U';
  $pms->{dkim_author_address} =
    $pms->get('from:addr',undef)  if !defined $pms->{dkim_author_address};
  local $1;
  my $author_domain = $pms->{dkim_author_address};
  $author_domain = ''  if !defined $author_domain;
  $author_domain = $author_domain =~ /\@([^\@]*)$/ ? lc $1 : '';
  my $practices_as_string = '';
  my %label =
   ('D' => 'discardable', 'A' => 'all', 'U' => 'unknown', 'N' => 'nxdomain',
    '1' => 'custom_low', '2' => 'custom_med', '3' => 'custom_high');

  # must check the message first to obtain signer, domain, and verif. status
  $self->_check_dkim_signature($pms) unless $pms->{dkim_checked_signature};

  if (!$pms->{dkim_signatures_ready}) {
    dbg("dkim: adsp not retrieved, signatures not obtained");

  } elsif ($pms->{dkim_has_valid_author_sig}) {  # don't fetch adsp when valid
    # draft-allman-dkim-ssp: If the message contains a valid Author
    # Signature, no Sender Signing Practices check need be performed:
    # the Verifier SHOULD NOT look up the Sender Signing Practices
    # and the message SHOULD be considered non-Suspicious.
    #
    # ADSP: If a message has an Author Signature, ADSP provides no benefit
    # relative to that domain since the message is already known to be
    # compliant with any possible ADSP for that domain. [...]
    # implementations SHOULD avoid doing unnecessary DNS lookups
    #
    dbg("dkim: adsp not retrieved, author signature is valid");

  } elsif ($author_domain eq '') {        # have mercy, don't claim a NXDOMAIN
    dbg("dkim: adsp not retrieved, no author domain (empty)");
    $practices_as_string = 'empty domain, ignored';

  } elsif ($author_domain =~ /^[^.]+$/s) {  # have mercy, don't claim NXDOMAIN
    dbg("dkim: adsp not retrieved, author domain not fqdn: $author_domain");
    $practices_as_string = 'not fqdn, ignored';

  } elsif ($author_domain !~ /.\.[a-z-]{2,}\z/si) {  # allow '-', think of IDN
    dbg("dkim: adsp not retrieved, author domain not a fqdn: %s (%s)",
        $author_domain, $pms->{dkim_author_address});
    $pms->{dkim_adsp} = 'N'; $practices_as_string = 'invalid fqdn, ignored';

  } elsif ($pms->{dkim_author_sig_tempfailed}) {
    dbg("dkim: adsp ignored, temporary failure varifying author signature");
    $practices_as_string = 'pub key tempfailed, ignored';

  } elsif ($pms->{dkim_has_any_author_sig} &&
           !$pms->{dkim_signatures_dependable}) {
    # the message did have an author signature but it wasn't valid; we also
    # expect the message was truncated just before being passed to SpamAssassin,
    # which is a likely reason for verification failure, so we shouldn't take
    # it too harsh with ADSP rules - just pretend the ADSP was 'unknown'
    #
    dbg("dkim: adsp ignored, message was truncated, invalid author signature");
    $practices_as_string = 'truncated, ignored';

  } elsif (my($adsp,$key) =
             $self->_lookup_dkim_adsp_override($pms,$author_domain)) {
    $pms->{dkim_adsp} = $adsp;
    $practices_as_string = 'override';
    $practices_as_string .= " by $key"  if $key ne $author_domain;

  } elsif (!$pms->is_dns_available()) {
    dbg("dkim: adsp not retrieved, DNS resolving not available");

  } elsif (!$self->_dkim_load_modules()) {
    dbg("dkim: adsp not retrieved, module Mail::DKIM not available");

  } else {
    my $timemethod = $self->{main}->UNIVERSAL::can("time_method") &&
                     $self->{main}->time_method("check_dkim_adsp");

    my $timeout = $pms->{conf}->{dkim_timeout};
    my $timer = Mail::SpamAssassin::Timeout->new({ secs => $timeout });
    my $err = $timer->run_and_catch(sub {
      my $practices;  # author domain signing practices
      eval {
        if (Mail::DKIM::AuthorDomainPolicy->UNIVERSAL::can("fetch")) {
          dbg("dkim: adsp: performing _adsp lookup on %s", $author_domain);
          # _adsp._domainkey.domain
          $practices = Mail::DKIM::AuthorDomainPolicy->fetch(
                         Protocol => "dns", Domain => $author_domain);
        } else {  # fall back to pre-ADSP style
          dbg("dkim: adsp: performing _policy lookup on %s", $author_domain);
          # _policy._domainkey.domain
          $practices = Mail::DKIM::DkimPolicy->fetch(
                         Protocol => "dns", Domain => $author_domain);
        }
        1;
      } or do {
        # fetching/parsing adsp record may throw error, ignore such practices
        my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
        dbg("dkim: adsp: fetch or parse on domain %s failed: %s",
            $author_domain,$eval_stat);
        undef $practices;
      };
      if (!$practices) {
        dbg("dkim: signing practices: none");
      } else {
        # ADSP: unknown / all / discardable
        $practices_as_string = $practices->as_string;
        my $sp = $practices->policy;
        $pms->{dkim_adsp} = $sp eq "unknown"      ? 'U'  # most common
                          : $sp eq "all"          ? 'A'
                          : $sp eq "discardable"  ? 'D'  # ADSP
                          : $sp eq "strict"       ? 'D'  # old style SSP
                          : uc($sp) eq "NXDOMAIN" ? 'N'
                                                  : 'U';
      }
    });

    if ($timer->timed_out()) {
      dbg("dkim: adsp lookup timed out after $timeout seconds");
    } elsif ($err) {
      chomp $err;
      dbg("dkim: adsp lookup failed: $err");
    }
  }

  dbg("dkim: adsp result: %s (%s), domain %s",
      $pms->{dkim_has_valid_author_sig} ? "accept" : $label{$pms->{dkim_adsp}},
      $practices_as_string, $author_domain);
}

sub _check_dkim_whitelist {
  my ($self, $pms) = @_;

  $pms->{whitelist_checked} = 1;

  my $author = $pms->{dkim_author_address};
  if (!defined $author) {
    $pms->{dkim_author_address} = $author = $pms->get('from:addr',undef);
  }
  if (!defined $author || $author eq '') {
    dbg("dkim: check_dkim_whitelist: could not find author address");
    return;
  }

  # collect whitelist entries matching the author from all lists
  my @acceptable_identity_tuples;
  $self->_wlcheck_acceptable_signature($pms, \@acceptable_identity_tuples,
                                       'def_whitelist_from_dkim');
  $self->_wlcheck_author_signature($pms, \@acceptable_identity_tuples,
                                       'def_whitelist_auth');
  $self->_wlcheck_acceptable_signature($pms, \@acceptable_identity_tuples,
                                       'whitelist_from_dkim');
  $self->_wlcheck_author_signature($pms, \@acceptable_identity_tuples,
                                       'whitelist_auth');
  if (!@acceptable_identity_tuples) {
    dbg("dkim: no wl entries match author $author, no need to verify sigs");
    return;
  }

  # if the message doesn't pass DKIM validation, it can't pass DKIM whitelist

  # trigger a DKIM check so we can get address/identity info;
  # continue if one or more signatures are valid or we want the debug info
  return unless $self->check_dkim_valid($pms) || would_log("dbg","dkim");
  return unless $pms->{dkim_signatures_ready};

  # now do all the matching in one go, against all signatures in a message
  my($any_match_at_all, $any_match_by_wl_ref) =
    _wlcheck_list($self, $pms, \@acceptable_identity_tuples);

  my(@valid,@fail);
  foreach my $wl (keys %$any_match_by_wl_ref) {
    my $match = $any_match_by_wl_ref->{$wl};
    if (defined $match) {
      $pms->{"dkim_match_in_$wl"} = 1  if $match;
      push(@{$match ? \@valid : \@fail}, "$wl/$match");
    }
  }
  if (@valid) {
    dbg("dkim: author %s, WHITELISTED by %s", $author, join(", ",@valid));
  } elsif (@fail) {
    dbg("dkim: author %s, found in %s BUT IGNORED", $author, join(", ",@fail));
  } else {
    dbg("dkim: author %s, not in any dkim whitelist", $author);
  }
}

# check for verifier-acceptable signatures; an empty (or undefined) signing
# identity in a whitelist implies checking for an author signature
#
sub _wlcheck_acceptable_signature {
  my ($self, $pms, $acceptable_identity_tuples_ref, $wl) = @_;
  my $author = $pms->{dkim_author_address};
  foreach my $white_addr (keys %{$pms->{conf}->{$wl}}) {
    my $re = qr/$pms->{conf}->{$wl}->{$white_addr}{re}/i;
    if ($author =~ $re) {
      foreach my $acc_id (@{$pms->{conf}->{$wl}->{$white_addr}{domain}}) {
        push(@$acceptable_identity_tuples_ref, [$acc_id,$wl,$re] );
      }
    }
  }
}

# use a traditional whitelist_from -style addrlist, the only acceptable DKIM
# signature is an Author Signature.  Note: don't pre-parse and store the
# domains; that's inefficient memory-wise and only saves one m//
#
sub _wlcheck_author_signature {
  my ($self, $pms, $acceptable_identity_tuples_ref, $wl) = @_;
  my $author = $pms->{dkim_author_address};
  foreach my $white_addr (keys %{$pms->{conf}->{$wl}}) {
    my $re = $pms->{conf}->{$wl}->{$white_addr};
    if ($author =~ $re) {
      push(@$acceptable_identity_tuples_ref, [undef,$wl,$re] );
    }
  }
}

sub _wlcheck_list {
  my ($self, $pms, $acceptable_identity_tuples_ref) = @_;

  my %any_match_by_wl;
  my $any_match_at_all = 0;
  my $verifier = $pms->{dkim_verifier};
  my @signatures = @{$pms->{dkim_signatures}};
  my $author = $pms->{dkim_author_address};  # address in a From header field
  $author = ''  if !defined $author;

  # walk through all signatures present in a message
  foreach my $signature (@signatures) {
    # old versions of Mail::DKIM would give undef for an invalid signature
    next if !defined $signature;
    my $sig_result_supported = $signature->UNIVERSAL::can("result_detail");
    my $valid =
      ($sig_result_supported ? $signature : $verifier)->result eq 'pass';
    my $expired = 0;
    if ($valid && $signature->UNIVERSAL::can("check_expiration")) {
      $expired = !$signature->check_expiration;
    }
    my $identity = $signature->identity;
    local($1,$2);
    if (!defined $identity || $identity eq '') {
      $identity = '@' . $signature->domain;
      dbg("dkim: identity empty, setting to %s", $identity);
    } elsif ($identity !~ /\@/) {  # just in case
      $identity = '@' . $identity;
      dbg("dkim: identity with no domain, setting to %s", $identity);
    }
    # split identity into local part and domain
    $identity =~ /^ (.*?) \@ ([^\@]*) $/xs;
    my($identity_mbx, $identity_dom) = ($1,$2);

    my $author_matching_part = $author;
    if ($identity =~ /^\@/) {  # empty localpart in signing identity
      $author_matching_part =~ s/^.*?(\@[^\@]*)?$/$1/s; # strip localpart
    }

    my $info = '';  # summary info string to be used for logging
    $info .= ($valid ? 'VALID' : 'FAILED') . ($expired ? ' EXPIRED' : '');
    $info .= lc $identity eq lc $author_matching_part ? ' author'
                                                      : ' third-party';
    $info .= " signature by id " . $identity;

    foreach my $entry (@$acceptable_identity_tuples_ref) {
      my($acceptable_identity, $wl, $re) = @$entry;
      # $re and $wl are here for logging purposes only, $re already checked.
      # The $acceptable_identity is a verifier-acceptable signing identity.
      # When $acceptable_identity is undef or an empty string it implies an
      # author signature check.

      my $matches = 0;
      if (!defined $acceptable_identity || $acceptable_identity eq '') {

        # An "Author Signature" (also called a first-party signature) is
        # any Valid Signature where the signing identity matches the Author
        # Address. If the signing identity does not include a localpart,
        # then only the domains must match; otherwise, the two addresses
        # must be identical.

        # checking for author signature
        $matches = 1  if lc $identity eq lc $author_matching_part;
      }
      else {  # checking for verifier-acceptable signature
        if ($acceptable_identity !~ /\@/) {
          $acceptable_identity = '@' . $acceptable_identity;
        }
        # split into local part and domain
        $acceptable_identity =~ /^ (.*?) \@ ([^\@]*) $/xs;
        my($accept_id_mbx, $accept_id_dom) = ($1,$2);

        # let's take a liberty and compare local parts case-insensitively
        if ($accept_id_mbx ne '') {  # local part exists, full id must match
          $matches = 1  if lc $identity eq lc $acceptable_identity;
        } else {  # any local part in signing identity is acceptable
                  # as long as domain matches or is a subdomain
          $matches = 1  if $identity_dom =~ /(^|\.)\Q$accept_id_dom\E\z/i;
        }
      }
      if ($matches) {
        dbg("dkim: $info, author $author, MATCHES $wl $re");
        # a defined value indicates at least a match, not necessarily valid
        $any_match_by_wl{$wl} = ''  if !exists $any_match_by_wl{$wl};
      }
      # only valid signature can cause whitelisting
      $matches = 0  if !$valid || $expired;

      if ($matches) {
        $any_match_at_all = 1;
        $any_match_by_wl{$wl} = $identity;  # value used for debug logging
      }
    }
    dbg("dkim: $info, author $author, no valid matches") if !$any_match_at_all;
  }
  return ($any_match_at_all, \%any_match_by_wl);
}

1;
