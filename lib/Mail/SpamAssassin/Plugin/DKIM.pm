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

 full DKIM_VALID     eval:check_dkim_valid()
 full DKIM_VALID_AU  eval:check_dkim_valid_author_sig()

(for compatibility, a check_dkim_verified is a synonym for check_dkim_valid)

=head1 DESCRIPTION

This SpamAssassin plugin implements DKIM lookups as described by the RFC 4871,
as well as historical DomainKeys lookups, as described by RFC 4870, thanks
to the support for both types of signatures by newer versions of module
Mail::DKIM (0.22 or later).

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

=cut

package Mail::SpamAssassin::Plugin::DKIM;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;

use strict;
use warnings;
use bytes;

# Have to do this so that RPM doesn't find these as required perl modules.
BEGIN { require Mail::DKIM; require Mail::DKIM::Verifier; }

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule ("check_dkim_signed");
  $self->register_eval_rule ("check_dkim_verified");  # old synonym for _valid
  $self->register_eval_rule ("check_dkim_valid");
  $self->register_eval_rule ("check_dkim_valid_author_sig");
  $self->register_eval_rule ("check_dkim_signsome");
  $self->register_eval_rule ("check_dkim_testing");
  $self->register_eval_rule ("check_dkim_signall");
  $self->register_eval_rule ("check_for_dkim_whitelist_from");
  $self->register_eval_rule ("check_for_def_dkim_whitelist_from");

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
  my ($self, $scan) = @_;
  $self->_check_dkim_signature($scan) unless $scan->{dkim_checked_signature};
  return $scan->{dkim_signed};
}


sub check_dkim_valid_author_sig {
  my ($self, $scan) = @_;
  $self->_check_dkim_signature($scan) unless $scan->{dkim_checked_signature};
  return $scan->{dkim_valid_author_sig};
}

sub check_dkim_valid {
  my ($self, $scan) = @_;
  $self->_check_dkim_signature($scan) unless $scan->{dkim_checked_signature};
  return $scan->{dkim_valid};
}

# mosnomer, old synonym for check_dkim_valid, kept for compatibility
sub check_dkim_verified {
  my ($self, $scan) = @_;
  $self->_check_dkim_signature($scan) unless $scan->{dkim_checked_signature};
  return $scan->{dkim_valid};
}

# useless, semantically always true according to the current SSP draft
sub check_dkim_signsome {
  my ($self, $scan) = @_;
# $self->_check_dkim_policy($scan) unless $scan->{dkim_checked_policy};
# return $scan->{dkim_signsome};
  # just return false to avoid rule DKIM_POLICY_SIGNSOME always firing
  return 0;
}

sub check_dkim_signall {
  my ($self, $scan) = @_;
  $self->_check_dkim_policy($scan) unless $scan->{dkim_checked_policy};
  return $scan->{dkim_signall};
}

# public key carries a testing flag, or fetched policy carries a testing flag
sub check_dkim_testing {
  my ($self, $scan) = @_;
  my $result = 0;
  $self->_check_dkim_signature($scan) unless $scan->{dkim_checked_signature};
  if ($scan->{dkim_key_testing}) {
    $result = 1;
  } else {
    $self->_check_dkim_policy($scan) unless $scan->{dkim_checked_policy};
    $result = 1  if $scan->{dkim_policy_testing};
  }
  return $result;
}

sub check_for_dkim_whitelist_from {
  my ($self, $scan) = @_;
  $self->_check_dkim_whitelist($scan) unless $scan->{whitelist_checked};
  return $scan->{dkim_match_in_whitelist_from_dkim} || 
         $scan->{dkim_match_in_whitelist_auth};
}

sub check_for_def_dkim_whitelist_from {
  my ($self, $scan) = @_;
  $self->_check_dkim_whitelist($scan) unless $scan->{whitelist_checked};
  return $scan->{dkim_match_in_def_whitelist_from_dkim} || 
         $scan->{dkim_match_in_def_whitelist_auth};
}

# ---------------------------------------------------------------------------

sub _check_dkim_signature {
  my ($self, $scan) = @_;

  $scan->{dkim_checked_signature} = 1;
  $scan->{dkim_signed} = 0;
  $scan->{dkim_valid} = 0;
  $scan->{dkim_valid_author_sig} = 0;
  $scan->{dkim_key_testing} = 0;
  $scan->{dkim_author_address} =
    $scan->get('from:addr')  if !defined $scan->{dkim_author_address};

# my $timemethod = $self->{main}->time_method("check_dkim_signature");

# my $verifier = Mail::DKIM::Verifier->new();         # per new docs
  my $verifier = Mail::DKIM::Verifier->new_object();  # old style???
  if (!$verifier) {
    dbg("dkim: cannot create Mail::DKIM::Verifier");
    return;
  }
  $scan->{dkim_object} = $verifier;

  # feed content of message into verifier, using \r\n endings,
  # required by Mail::DKIM API (see bug 5300)
  # note: bug 5179 comment 28: perl does silly things on non-Unix platforms
  # unless we use \015\012 instead of \r\n
  eval {
    my $str = $scan->{msg}->get_pristine;
    $str =~ s/\r?\n/\015\012/sg;  # ensure \015\012 ending
    # feeding large chunks to Mail::DKIM is much faster than line-by-line feed
    $verifier->PRINT($str);
    1;
  } or do {  # intercept die() exceptions and render safe
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    dbg("dkim: verification failed, intercepted error: $eval_stat");
    return 0;           # cannot verify message
  };

  my $timeout = $scan->{conf}->{dkim_timeout};

  my $timer = Mail::SpamAssassin::Timeout->new({ secs => $timeout });
  my $err = $timer->run_and_catch(sub {

    dbg("dkim: performing public key lookup and signature verification");
    $verifier->CLOSE();      # the action happens here

    my $author = $verifier->message_originator;
    $author = $author->address()  if $author;
    $author = '' if !defined $author;  # when a From header field is missing
    # Mail::DKIM sometimes leaves leading or trailing whitespace in address
    $author =~ s/^[ \t]+//s;  $author =~ s/[ \t]+\z//s;  # trim
    if ($author ne $scan->{dkim_author_address}) {
      dbg("dkim: author parsing inconsistency, SA: <%s>, DKIM: <%s>",
           $author, $scan->{dkim_author_address});
    # currently SpamAssassin's parsing is better than Mail::Address parsing
    # $scan->{dkim_author_address} = $author;
    }

    $scan->{dkim_signatures} = [];

    # versions before 0.29 only provided a public interface to fetch one
    # signature, new versions allow access to all signatures of a message
    my @signatures = Mail::DKIM->VERSION >= 0.29 ? $verifier->signatures
                                                 : $verifier->signature;
    @signatures = grep { defined } @signatures;  # just in case
    my $has_author_sig = 0;
    foreach my $signature (@signatures) {
      # i=  Identity of the user or agent (e.g., a mailing list manager) on
      #     behalf of which this message is signed (dkim-quoted-printable;
      #     OPTIONAL, default is an empty local-part followed by an "@"
      #     followed by the domain from the "d=" tag).
      my $identity = $signature->identity;
      dbg("dkim: signing identity: %s, d=%s, a=%s, c=%s",
          $identity, $signature->domain,
          $signature->algorithm, scalar($signature->canonicalization));
      if (!defined $identity || $identity eq '') {  # just in case
        $identity = '@' . $signature->domain;
        $signature->identity($identity);
      } elsif ($identity !~ /\@/) {  # just in case
        $identity = '@' . $identity;
        $signature->identity($identity);
      }
      if ($signature->result eq 'pass') {
        local ($1);  # check if we have a valid first-party signature
        if ($identity =~ /.\@[^@]*\z/s) {  # identity has a localpart
          $has_author_sig = 1  if lc($author) eq lc($identity);
        } elsif ($author =~ /^.*?(\@[^\@]*)?\z/s && lc($1) eq lc($identity)) {
          # ignoring localpart if identity doesn't have a localpart
          $has_author_sig = 1;
        }
      }
    }
    $scan->{dkim_signatures} = \@signatures;
    { my (%seen1,%seen2);
      my @valid_s = grep { $_->result eq 'pass' } @signatures;
      $scan->set_tag('DKIMIDENTITY',
              join(" ", grep { !$seen1{$_}++ } map { $_->identity } @valid_s));
      $scan->set_tag('DKIMDOMAIN',
              join(" ", grep { !$seen2{$_}++ } map { $_->domain } @valid_s));
    }
    # corresponds to 'best' result in case of multiple signatures
    my $result = $verifier->result();
    my $detail = $verifier->result_detail();
    # let the result stand out more clearly in the log, use uppercase
    dbg("dkim: signature verification result: ".
        ($detail eq 'none' ? $detail : uc $detail));

    # check and remember verification results
    if ($result eq 'pass') {
      $scan->{dkim_signed} = 1;
      $scan->{dkim_valid} = 1;
      $scan->{dkim_valid_author_sig} = $has_author_sig;
    }
    elsif ($result eq 'fail') {
      $scan->{dkim_signed} = 1;
      # Returned if a valid DKIM-Signature header was found, but the
      # signature does not contain a correct value for the message.
    }
    elsif ($result eq 'invalid') {
      $scan->{dkim_signed} = 1;
      # Returned if no valid DKIM-Signature headers were found,
      # but there is at least one invalid DKIM-Signature header.
    }
    elsif ($result eq 'none') {
      # no signatures, this is a default state
    }

  });

  if ($timer->timed_out()) {
    dbg("dkim: public key lookup or verification timed out after $timeout s");
  } elsif ($err) {
    chomp $err;
    dbg("dkim: public key lookup or verification failed: $err");
  }
}

sub _check_dkim_policy {
  my ($self, $scan) = @_;

  $scan->{dkim_checked_policy} = 1;
  $scan->{dkim_signsome} = 0;
  $scan->{dkim_signall} = 0;
  $scan->{dkim_policy_testing} = 0;
  $scan->{dkim_author_address} =
    $scan->get('from:addr')  if !defined $scan->{dkim_author_address};

  # must check the message first to obtain signer, domain, and verif. status
  $self->_check_dkim_signature($scan) unless $scan->{dkim_checked_signature};
  my $verifier = $scan->{dkim_object};

# my $timemethod = $self->{main}->time_method("check_dkim_policy");

  if (!$verifier) {
    dbg("dkim: policy: dkim object not available (programming error?)");
  } elsif (!$scan->is_dns_available()) {
    dbg("dkim: policy: not retrieved, no DNS resolving available");
  } elsif ($scan->{dkim_valid_author_sig}) {  # don't fetch policy when valid
    # draft-allman-dkim-ssp: If the message contains a valid Author
    # Signature, no Sender Signing Practices check need be performed:
    # the Verifier SHOULD NOT look up the Sender Signing Practices
    # and the message SHOULD be considered non-Suspicious.

    dbg("dkim: policy: not retrieved, author signature is valid");

  } else {
    my $timeout = $scan->{conf}->{dkim_timeout};
    my $timer = Mail::SpamAssassin::Timeout->new({ secs => $timeout });
    my $err = $timer->run_and_catch(sub {

      dbg("dkim: policy: performing lookup");

      my $policy;
      eval {
        $policy = $verifier->fetch_author_policy;  1;
      } or do {
        # fetching or parsing a policy may throw an error, ignore such policy
        my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
        dbg("dkim: policy: fetch or parse failed: $eval_stat");
        undef $policy;
      };
      if (!$policy) {
        dbg("dkim: policy: none");
      } else {
        my $policy_result = $policy->apply($verifier);
        dbg("dkim: policy result $policy_result: ".$policy->as_string());

        # extract the flags we expose, from the policy
        my $pol_o = $policy->policy();
        if ($pol_o eq '~') {
          $scan->{dkim_signsome} = 1;
        }
        elsif ($pol_o eq '-') {
          $scan->{dkim_signall} = 1;
        }
        if ($policy->testing()) {
          $scan->{dkim_policy_testing} = 1;
        }
      }
    });

    if ($timer->timed_out()) {
      dbg("dkim: lookup timed out after $timeout seconds");
    } elsif ($err) {
      chomp $err;
      dbg("dkim: lookup failed: $err");
    }
  }
}

sub _check_dkim_whitelist {
  my ($self, $scan) = @_;

  $scan->{whitelist_checked} = 1;
  return unless $scan->is_dns_available();

  my $author = $scan->{dkim_author_address};
  if (!defined $author) {
    $scan->{dkim_author_address} = $author = $scan->get('from:addr');
  }
  if (!defined $author || $author eq '') {
    dbg("dkim: check_dkim_whitelist: could not find author address");
    return;
  }

  # collect whitelist entries matching the author from all lists
  my @acceptable_identity_tuples;
  $self->_wlcheck_acceptable_signature($scan, \@acceptable_identity_tuples,
                                       'def_whitelist_from_dkim');
  $self->_wlcheck_author_signature($scan, \@acceptable_identity_tuples,
                                       'def_whitelist_auth');
  $self->_wlcheck_acceptable_signature($scan, \@acceptable_identity_tuples,
                                       'whitelist_from_dkim');
  $self->_wlcheck_author_signature($scan, \@acceptable_identity_tuples,
                                       'whitelist_auth');
  if (!@acceptable_identity_tuples) {
    dbg("dkim: no wl entries match author $author, no need to verify sigs");
    return;
  }

  # if the message doesn't pass DKIM validation, it can't pass DKIM whitelist

  # trigger a DKIM check so we can get address/identity info;
  # continue if one or more signatures are valid or we want the debug info
  return unless $self->check_dkim_valid($scan) || would_log("dbg","dkim");

  # now do all the matching in one go, against all signatures in a message
  my($any_match_at_all, $any_match_by_wl_ref) =
    _wlcheck_list($self, $scan, \@acceptable_identity_tuples);

  my(@valid,@fail);
  foreach my $wl (keys %$any_match_by_wl_ref) {
    my $match = $any_match_by_wl_ref->{$wl};
    if (defined $match) {
      $scan->{"dkim_match_in_$wl"} = 1  if $match;
      if ($match) { push(@valid,$wl) } else { push(@fail,$wl) }
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
  my ($self, $scan, $acceptable_identity_tuples_ref, $wl) = @_;
  my $author = $scan->{dkim_author_address};
  foreach my $white_addr (keys %{$scan->{conf}->{$wl}}) {
    my $re = qr/$scan->{conf}->{$wl}->{$white_addr}{re}/i;
    if ($author =~ $re) {
      foreach my $acc_id (@{$scan->{conf}->{$wl}->{$white_addr}{domain}}) {
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
  my ($self, $scan, $acceptable_identity_tuples_ref, $wl) = @_;
  my $author = $scan->{dkim_author_address};
  foreach my $white_addr (keys %{$scan->{conf}->{$wl}}) {
    my $re = $scan->{conf}->{$wl}->{$white_addr};
    if ($author =~ $re) {
      push(@$acceptable_identity_tuples_ref, [undef,$wl,$re] );
    }
  }
}

sub _wlcheck_list {
  my ($self, $scan, $acceptable_identity_tuples_ref) = @_;

  my %any_match_by_wl;
  my $any_match_at_all = 0;
  my $expiration_supported = Mail::DKIM->VERSION >= 0.29 ? 1 : 0;
  my $author = $scan->{dkim_author_address};  # address in a From header field

  # walk through all signatures present in a message
  foreach my $signature (@{$scan->{dkim_signatures}}) {
    local ($1,$2);

    my $valid = $signature->result eq 'pass';

    my $expiration_time;
    $expiration_time = $signature->expiration  if $expiration_supported;
    my $expired = defined $expiration_time &&
                  $expiration_time =~ /^\d{1,12}\z/ && time > $expiration_time;

    my $identity = $signature->identity;
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
        $any_match_by_wl{$wl} = 0  if !exists $any_match_by_wl{$wl};
      }
      # only valid signature can cause whitelisting
      $matches = 0  if !$valid || $expired;

      $any_match_by_wl{$wl} = $any_match_at_all = 1  if $matches;
    }
    dbg("dkim: $info, author $author, no valid matches") if !$any_match_at_all;
  }
  return ($any_match_at_all, \%any_match_by_wl);
}

1;
