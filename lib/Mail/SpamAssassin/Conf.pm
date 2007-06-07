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

Mail::SpamAssassin::Conf - SpamAssassin configuration file

=head1 SYNOPSIS

  # a comment

  rewrite_header Subject          *****SPAM*****

  full PARA_A_2_C_OF_1618         /Paragraph .a.{0,10}2.{0,10}C. of S. 1618/i
  describe PARA_A_2_C_OF_1618     Claims compliance with senate bill 1618

  header FROM_HAS_MIXED_NUMS      From =~ /\d+[a-z]+\d+\S*@/i
  describe FROM_HAS_MIXED_NUMS    From: contains numbers mixed in with letters

  score A_HREF_TO_REMOVE          2.0

  lang es describe FROM_FORGED_HOTMAIL Forzado From: simula ser de hotmail.com

  lang pt_BR report O programa detetor de Spam ZOE [...]

=head1 DESCRIPTION

SpamAssassin is configured using traditional UNIX-style configuration files,
loaded from the C</usr/share/spamassassin> and C</etc/mail/spamassassin>
directories.

The following web page lists the most important configuration settings
used to configure SpamAssassin; novices are encouraged to read it first:

  http://wiki.apache.org/spamassassin/ImportantInitialConfigItems

=head1 FILE FORMAT

The C<#> character starts a comment, which continues until end of line.
B<NOTE:> if the C<#> character is to be used as part of a rule or
configuration option, it must be escaped with a backslash.  i.e.: C<\#>

Whitespace in the files is not significant, but please note that starting a
line with whitespace is deprecated, as we reserve its use for multi-line rule
definitions, at some point in the future.

Currently, each rule or configuration setting must fit on one-line; multi-line
settings are not supported yet.

File and directory paths can use C<~> to refer to the user's home
directory, but no other shell-style path extensions such as globing or
C<~user/> are supported.

Where appropriate below, default values are listed in parentheses.

=head1 USER PREFERENCES

The following options can be used in both site-wide (C<local.cf>) and
user-specific (C<user_prefs>) configuration files to customize how
SpamAssassin handles incoming email messages.

=cut

package Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::Util;
use Mail::SpamAssassin::NetSet;
use Mail::SpamAssassin::Constants qw(:sa);
use Mail::SpamAssassin::Conf::Parser;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util::TieOneStringHash;
use File::Spec;

use strict;
use warnings;
use bytes;

use vars qw{
  @ISA $VERSION
  $CONF_TYPE_STRING $CONF_TYPE_BOOL
  $CONF_TYPE_NUMERIC $CONF_TYPE_HASH_KEY_VALUE
  $CONF_TYPE_ADDRLIST $CONF_TYPE_TEMPLATE
  $INVALID_VALUE $MISSING_REQUIRED_VALUE
  @MIGRATED_SETTINGS

$TYPE_HEAD_TESTS $TYPE_HEAD_EVALS
$TYPE_BODY_TESTS $TYPE_BODY_EVALS $TYPE_FULL_TESTS $TYPE_FULL_EVALS
$TYPE_RAWBODY_TESTS $TYPE_RAWBODY_EVALS $TYPE_URI_TESTS $TYPE_URI_EVALS
$TYPE_META_TESTS $TYPE_RBL_EVALS
};

@ISA = qw();

# odd => eval test.  Not constants so they can be shared with Parser
# TODO: move to Constants.pm?
$TYPE_HEAD_TESTS    = 0x0008;
$TYPE_HEAD_EVALS    = 0x0009;
$TYPE_BODY_TESTS    = 0x000a;
$TYPE_BODY_EVALS    = 0x000b;
$TYPE_FULL_TESTS    = 0x000c;
$TYPE_FULL_EVALS    = 0x000d;
$TYPE_RAWBODY_TESTS = 0x000e;
$TYPE_RAWBODY_EVALS = 0x000f;
$TYPE_URI_TESTS     = 0x0010;
$TYPE_URI_EVALS     = 0x0011;
$TYPE_META_TESTS    = 0x0012;
$TYPE_RBL_EVALS     = 0x0013;

my @rule_types = ("body_tests", "uri_tests", "uri_evals",
                  "head_tests", "head_evals", "body_evals", "full_tests",
                  "full_evals", "rawbody_tests", "rawbody_evals",
		  "rbl_evals", "meta_tests");

$VERSION = 'bogus';     # avoid CPAN.pm picking up version strings later

# these are variables instead of constants so that other classes can
# access them; if they're constants, they'd have to go in Constants.pm
# TODO: move to Constants.pm?
$CONF_TYPE_STRING           = 1;
$CONF_TYPE_BOOL             = 2;
$CONF_TYPE_NUMERIC          = 3;
$CONF_TYPE_HASH_KEY_VALUE   = 4;
$CONF_TYPE_ADDRLIST         = 5;
$CONF_TYPE_TEMPLATE         = 6;
$MISSING_REQUIRED_VALUE     = -99999999999999;
$INVALID_VALUE              = -99999999999998;

# set to "1" by the test suite code, to record regression tests
# $Mail::SpamAssassin::Conf::COLLECT_REGRESSION_TESTS = 1;

# search for "sub new {" to find the start of the code
###########################################################################

sub set_default_commands {
  my($self) = @_;

  # see "perldoc Mail::SpamAssassin::Conf::Parser" for details on this fmt.
  # push each config item like this, to avoid a POD bug; it can't just accept
  # ( { ... }, { ... }, { ...} ) otherwise POD parsing dies.
  my @cmds = ();

=head2 SCORING OPTIONS

=over 4

=item required_score n.nn (default: 5)

Set the score required before a mail is considered spam.  C<n.nn> can
be an integer or a real number.  5.0 is the default setting, and is
quite aggressive; it would be suitable for a single-user setup, but if
you're an ISP installing SpamAssassin, you should probably set the
default to be more conservative, like 8.0 or 10.0.  It is not
recommended to automatically delete or discard messages marked as
spam, as your users B<will> complain, but if you choose to do so, only
delete messages with an exceptionally high score such as 15.0 or
higher. This option was previously known as C<required_hits> and that
name is still accepted, but is deprecated.

=cut

  push (@cmds, {
    setting => 'required_score',
    aliases => ['required_hits'],       # backwards compat
    default => 5,
    type => $CONF_TYPE_NUMERIC
  });

=item score SYMBOLIC_TEST_NAME n.nn [ n.nn n.nn n.nn ]

Assign scores (the number of points for a hit) to a given test.
Scores can be positive or negative real numbers or integers.
C<SYMBOLIC_TEST_NAME> is the symbolic name used by SpamAssassin for
that test; for example, 'FROM_ENDS_IN_NUMS'.

If only one valid score is listed, then that score is always used
for a test.

If four valid scores are listed, then the score that is used depends
on how SpamAssassin is being used. The first score is used when
both Bayes and network tests are disabled (score set 0). The second
score is used when Bayes is disabled, but network tests are enabled
(score set 1). The third score is used when Bayes is enabled and
network tests are disabled (score set 2). The fourth score is used
when Bayes is enabled and network tests are enabled (score set 3).

Setting a rule's score to 0 will disable that rule from running.

If any of the score values are surrounded by parenthesis '()', then
all of the scores in the line are considered to be relative to the
already set score.  ie: '(3)' means increase the score for this
rule by 3 points in all score sets.  '(3) (0) (3) (0)' means increase
the score for this rule by 3 in score sets 0 and 2 only.

If no score is given for a test by the end of the configuration, a
default score is assigned: a score of 1.0 is used for all tests,
except those who names begin with 'T_' (this is used to indicate a
rule in testing) which receive 0.01.

Note that test names which begin with '__' are indirect rules used
to compose meta-match rules and can also act as prerequisites to
other rules.  They are not scored or listed in the 'tests hit'
reports, but assigning a score of 0 to an indirect rule will disable
it from running.

=cut

  push (@cmds, {
    setting => 'score',
    is_frequent => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      my($rule, @scores) = split(/\s+/, $value);
      unless (defined $value && $value !~ /^$/ &&
		(scalar @scores == 1 || scalar @scores == 4)) {
	info("config: score: requires a symbolic rule name and 1 or 4 scores");
	return $MISSING_REQUIRED_VALUE;
      }

      # Figure out if we're doing relative scores, remove the parens if we are
      my $relative = 0;
      foreach (@scores) {
        if (s/^\((-?\d+(?:\.\d+)?)\)$/$1/) {
	  $relative = 1;
	}
	unless (/^-?\d+(?:\.\d+)?$/) {
	  info("config: score: the non-numeric score ($_) is not valid, " .
	    "a numeric score is required");
	  return $INVALID_VALUE;
	}
      }

      if ($relative && !exists $self->{scoreset}->[0]->{$rule}) {
        info("config: score: relative score without previous setting in " .
	  "configuration");
        return $INVALID_VALUE;
      }

      # If we're only passed 1 score, copy it to the other scoresets
      if (@scores) {
        if (@scores != 4) {
          @scores = ( $scores[0], $scores[0], $scores[0], $scores[0] );
        }

        # Set the actual scoreset values appropriately
        for my $index (0..3) {
          my $score = $relative ?
            $self->{scoreset}->[$index]->{$rule} + $scores[$index] :
            $scores[$index];

          $self->{scoreset}->[$index]->{$rule} = $score + 0.0;
        }
      }
    }
  });

=head2 WHITELIST AND BLACKLIST OPTIONS

=over 4

=item whitelist_from add@ress.com

Used to whitelist sender addresses which send mail that is often tagged
(incorrectly) as spam.

Use of this setting is not recommended, since it blindly trusts the message,
which is routinely and easily forged by spammers and phish senders. The
recommended solution is to instead use C<whitelist_auth> or other authenticated
whitelisting methods, or C<whitelist_from_rcvd>.

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

In addition, the "envelope sender" data, taken from the SMTP envelope data
where this is available, is looked up.  See C<envelope_sender_header>.

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
it will be, but for a complex network you may get better results by setting that
parameter.

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

=item whitelist_auth add@ress.com

Used to specify addresses which send mail that is often tagged (incorrectly) as
spam.  This is different from C<whitelist_from> and C<whitelist_from_rcvd> in
that it first verifies that the message was sent by an authorized sender for
the address, before whitelisting.

Authorization is performed using one of the installed sender-authorization
schemes: SPF (using C<Mail::SpamAssassin::Plugins::SPF>), Domain Keys (using
C<Mail::SpamAssassin::Plugins::DomainKeys>), or DKIM (using
C<Mail::SpamAssassin::Plugins::DKIM>).  Note that those plugins must be active,
and working, for this to operate.

Using C<whitelist_auth> is roughly equivalent to specifying duplicate
C<whitelist_from_spf>, C<whitelist_from_dk>, and C<whitelist_from_dkim> lines
for each of the addresses specified.

e.g.

  whitelist_auth joe@example.com fred@example.com
  whitelist_auth *@example.com

=item def_whitelist_auth add@ress.com

Same as C<whitelist_auth>, but used for the default whitelist entries
in the SpamAssassin distribution.  The whitelist score is lower, because
these are often targets for spammer spoofing.

=cut

  push (@cmds, {
    setting => 'whitelist_auth',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST
  });

  push (@cmds, {
    setting => 'def_whitelist_auth',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST
  });

=item unwhitelist_auth add@ress.com

Used to override a C<whitelist_auth> entry. The specified email address has to
match exactly the address previously used in a C<whitelist_auth> line.

e.g.

  unwhitelist_auth joe@example.com fred@example.com
  unwhitelist_auth *@example.com

=cut

  push (@cmds, {
    command => 'unwhitelist_auth',
    setting => 'whitelist_auth',
    code => \&Mail::SpamAssassin::Conf::Parser::remove_addrlist_value
  });

=back

=head2 BASIC MESSAGE TAGGING OPTIONS

=over 4

=item rewrite_header { subject | from | to } STRING

By default, suspected spam messages will not have the C<Subject>,
C<From> or C<To> lines tagged to indicate spam. By setting this option,
the header will be tagged with C<STRING> to indicate that a message is
spam. For the From or To headers, this will take the form of an RFC 2822
comment following the address in parantheses. For the Subject header,
this will be prepended to the original subject. Note that you should
only use the _REQD_ and _SCORE_ tags when rewriting the Subject header
if C<report_safe> is 0. Otherwise, you may not be able to remove
the SpamAssassin markup via the normal methods.  More information
about tags is explained below in the B<TEMPLATE TAGS> section.

Parentheses are not permitted in STRING if rewriting the From or To headers.
(They will be converted to square brackets.)

If C<rewrite_header subject> is used, but the message being rewritten
does not already contain a C<Subject> header, one will be created.

A null value for C<STRING> will remove any existing rewrite for the specified
header.

=cut

  push (@cmds, {
    setting => 'rewrite_header',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      my($hdr, $string) = split(/\s+/, $value, 2);
      $hdr = ucfirst(lc($hdr));

      if ($hdr =~ /^$/) {
	return $MISSING_REQUIRED_VALUE;
      }
      # We only deal with From, Subject, and To ...
      elsif ($hdr =~ /^(?:From|Subject|To)$/) {
	unless (defined $string && $string =~ /\S/) {
	  delete $self->{rewrite_header}->{$hdr};
	  return;
	}

	if ($hdr ne 'Subject') {
          $string =~ tr/()/[]/;
	}
        $self->{rewrite_header}->{$hdr} = $string;
        return;
      }
      else {
	# if we get here, note the issue, then we'll fail through for an error.
	info("config: rewrite_header: ignoring $hdr, not From, Subject, or To");
	return $INVALID_VALUE;
      }
    }
  });

=item add_header { spam | ham | all } header_name string

Customized headers can be added to the specified type of messages (spam,
ham, or "all" to add to either).  All headers begin with C<X-Spam->
(so a C<header_name> Foo will generate a header called X-Spam-Foo).
header_name is restricted to the character set [A-Za-z0-9_-].

C<string> can contain tags as explained below in the B<TEMPLATE TAGS> section.
You can also use C<\n> and C<\t> in the header to add newlines and tabulators
as desired.  A backslash has to be written as \\, any other escaped chars will
be silently removed.

All headers will be folded if fold_headers is set to C<1>. Note: Manually
adding newlines via C<\n> disables any further automatic wrapping (ie:
long header lines are possible). The lines will still be properly folded
(marked as continuing) though.

You can customize existing headers with B<add_header> (only the specified
subset of messages will be changed).

See also C<clear_headers> for removing headers.

Here are some examples (these are the defaults, note that Checker-Version can
not be changed or removed):

  add_header spam Flag _YESNOCAPS_
  add_header all Status _YESNO_, score=_SCORE_ required=_REQD_ tests=_TESTS_ autolearn=_AUTOLEARN_ version=_VERSION_
  add_header all Level _STARS(*)_
  add_header all Checker-Version SpamAssassin _VERSION_ (_SUBVERSION_) on _HOSTNAME_

=cut

  push (@cmds, {
    setting => 'add_header',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value !~ /^(ham|spam|all)\s+([A-Za-z0-9_-]+)\s+(.*?)\s*$/) {
        return $INVALID_VALUE;
      }

      my ($type, $name, $hline) = ($1, $2, $3);
      if ($hline =~ /^"(.*)"$/) {
        $hline = $1;
      }
      my @line = split(
                  /\\\\/,     # split at backslashes,
                  $hline."\n" # newline needed to make trailing backslashes work
                );
      map {
        s/\\t/\t/g; # expand tabs
        s/\\n/\n/g; # expand newlines
        s/\\.//g;   # purge all other escapes
      } @line;
      $hline = join("\\", @line);
      chop($hline);  # remove dummy newline again
      if (($type eq "ham") || ($type eq "all")) {
        $self->{headers_ham}->{$name} = $hline;
      }
      if (($type eq "spam") || ($type eq "all")) {
        $self->{headers_spam}->{$name} = $hline;
      }
    }
  });

=item remove_header { spam | ham | all } header_name

Headers can be removed from the specified type of messages (spam, ham,
or "all" to remove from either).  All headers begin with C<X-Spam->
(so C<header_name> will be appended to C<X-Spam->).

See also C<clear_headers> for removing all the headers at once.

Note that B<X-Spam-Checker-Version> is not removable because the version
information is needed by mail administrators and developers to debug
problems.  Without at least one header, it might not even be possible to
determine that SpamAssassin is running.

=cut

  push (@cmds, {
    setting => 'remove_header',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value !~ /^(ham|spam|all)\s+([A-Za-z0-9_-]+)\s*$/) {
        return $INVALID_VALUE;
      }

      my ($type, $name) = ($1, $2);
      return if ( $name eq "Checker-Version" );

      if (($type eq "ham") || ($type eq "all")) {
        delete $self->{headers_ham}->{$name};
      }
      if (($type eq "spam") || ($type eq "all")) {
        delete $self->{headers_spam}->{$name};
      }
    }
  });

=item clear_headers

Clear the list of headers to be added to messages.  You may use this
before any B<add_header> options to prevent the default headers from being
added to the message.

Note that B<X-Spam-Checker-Version> is not removable because the version
information is needed by mail administrators and developers to debug
problems.  Without at least one header, it might not even be possible to
determine that SpamAssassin is running.

=cut

  push (@cmds, {
    setting => 'clear_headers',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      for my $name (keys %{ $self->{headers_ham} }) {
        delete $self->{headers_ham}->{$name} if $name ne "Checker-Version";
      }
      for my $name (keys %{ $self->{headers_spam} }) {
        delete $self->{headers_spam}->{$name} if $name ne "Checker-Version";
      }
    }
  });

=item report_safe ( 0 | 1 | 2 )	(default: 1)

if this option is set to 1, if an incoming message is tagged as spam,
instead of modifying the original message, SpamAssassin will create a
new report message and attach the original message as a message/rfc822
MIME part (ensuring the original message is completely preserved, not
easily opened, and easier to recover).

If this option is set to 2, then original messages will be attached with
a content type of text/plain instead of message/rfc822.  This setting
may be required for safety reasons on certain broken mail clients that
automatically load attachments without any action by the user.  This
setting may also make it somewhat more difficult to extract or view the
original message.

If this option is set to 0, incoming spam is only modified by adding
some C<X-Spam-> headers and no changes will be made to the body.  In
addition, a header named B<X-Spam-Report> will be added to spam.  You
can use the B<remove_header> option to remove that header after setting
B<report_safe> to 0.

See B<report_safe_copy_headers> if you want to copy headers from
the original mail into tagged messages.

=cut

  push (@cmds, {
    setting => 'report_safe',
    default => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $MISSING_REQUIRED_VALUE;
      }
      elsif ($value !~ /^[012]$/) {
        return $INVALID_VALUE;
      }

      $self->{report_safe} = $value+0;
      if (! $self->{report_safe}) {
        $self->{headers_spam}->{"Report"} = "_REPORT_";
      }
    }
  });

=back

=head2 LANGUAGE OPTIONS

=over 4

=item ok_locales xx [ yy zz ... ]		(default: all)

This option is used to specify which locales are considered OK for
incoming mail.  Mail using the B<character sets> that are allowed by
this option will not be marked as possibly being spam in a foreign
language.

If you receive lots of spam in foreign languages, and never get any non-spam in
these languages, this may help.  Note that all ISO-8859-* character sets, and
Windows code page character sets, are always permitted by default.

Set this to C<all> to allow all character sets.  This is the default.

The rules C<CHARSET_FARAWAY>, C<CHARSET_FARAWAY_BODY>, and
C<CHARSET_FARAWAY_HEADERS> are triggered based on how this is set.

Examples:

  ok_locales all         (allow all locales)
  ok_locales en          (only allow English)
  ok_locales en ja zh    (allow English, Japanese, and Chinese)

Note: if there are multiple ok_locales lines, only the last one is used.

Select the locales to allow from the list below:

=over 4

=item en	- Western character sets in general

=item ja	- Japanese character sets

=item ko	- Korean character sets

=item ru	- Cyrillic character sets

=item th	- Thai character sets

=item zh	- Chinese (both simplified and traditional) character sets

=back

=cut

  push (@cmds, {
    setting => 'ok_locales',
    default => 'all',
    type => $CONF_TYPE_STRING
  });

=item normalize_charset ( 0 | 1)        (default: 0)

Whether to detect character sets and normalize message content to
Unicode.  Requires the Encode::Detect module, HTML::Parser version
3.46 or later, and Perl 5.8.5 or later.

=cut

  push (@cmds, {
    setting => 'normalize_charset',
    default => 0,
    code => sub {
	my ($self, $key, $value, $line) = @_;
	unless (defined $value && $value !~ /^$/) {
	    return $MISSING_REQUIRED_VALUE;
	}
	return undef if $value == 0;
	return $INVALID_VALUE unless $value == 1;

	unless ($] > 5.008004) {
	    $self->{parser}->lint_warn("config: normalize_charset requires Perl 5.8.5 or later");
	    return $INVALID_VALUE;
	}
	require HTML::Parser;
	unless ($HTML::Parser::VERSION >= 3.46) {
	    $self->{parser}->lint_warn("config: normalize_charset requires HTML::Parser 3.46 or later");
	    return $INVALID_VALUE;
	}
	unless (eval 'require Encode::Detect::Detector') {
	    $self->{parser}->lint_warn("config: normalize_charset requires Encode::Detect");
	    return $INVALID_VALUE;
	}
	unless (eval 'require Encode') {
	    $self->{parser}->lint_warn("config: normalize_charset requires Encode");
	    return $INVALID_VALUE;
	}

	$self->{normalize_charset} = 1;
    }
  });


=back

=head2 NETWORK TEST OPTIONS

=over 4

=item trusted_networks ip.add.re.ss[/mask] ...   (default: none)

What networks or hosts are 'trusted' in your setup.  B<Trusted> in this case
means that relay hosts on these networks are considered to not be potentially
operated by spammers, open relays, or open proxies.  A trusted host could
conceivably relay spam, but will not originate it, and will not forge header
data. DNS blacklist checks will never query for hosts on these networks. 

See C<http://wiki.apache.org/spamassassin/TrustPath> for more information.

MXes for your domain(s) and internal relays should B<also> be specified using
the C<internal_networks> setting. When there are 'trusted' hosts that
are not MXes or internal relays for your domain(s) they should B<only> be
specified in C<trusted_networks>.

If a C</mask> is specified, it's considered a CIDR-style 'netmask', specified
in bits.  If it is not specified, but less than 4 octets are specified with a
trailing dot, that's considered a mask to allow all addresses in the remaining
octets.  If a mask is not specified, and there is not trailing dot, then just
the single IP address specified is used, as if the mask was C</32>.

If a network or host address is prefaced by a C<!> the network or host will be
excluded (or included) in a first listed match fashion.

Note: 127/8 is always included in trusted_networks, regardless of your config.

Examples:

   trusted_networks 192.168/16            # all in 192.168.*.*
   trusted_networks 212.17.35.15          # just that host
   trusted_networks !10.0.1.5 10.0.1/24   # all in 10.0.1.* but not 10.0.1.5

This operates additively, so a C<trusted_networks> line after another one
will result in all those networks becoming trusted.  To clear out the
existing entries, use C<clear_trusted_networks>.

If C<trusted_networks> is not set and C<internal_networks> is, the value
of C<internal_networks> will be used for this parameter.

If neither C<trusted_networks> or C<internal_networks> is set, a basic
inference algorithm is applied.  This works as follows:

=over 4

=item *

If the 'from' host has an IP address in a private (RFC 1918) network range,
then it's trusted

=item *

If there are authentication tokens in the received header, and
the previous host was trusted, then this host is also trusted

=item *

Otherwise this host, and all further hosts, are consider untrusted.

=back

=cut

  push (@cmds, {
    setting => 'trusted_networks',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
	return $MISSING_REQUIRED_VALUE;
      }
      foreach my $net (split (/\s+/, $value)) {
        $self->{trusted_networks}->add_cidr ($net);
      }
      $self->{trusted_networks_configured} = 1;
    }
  });

=item clear_trusted_networks

Empty the list of trusted networks.

=cut

  push (@cmds, {
    setting => 'clear_trusted_networks',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      $self->{trusted_networks} = $self->new_netset();
      $self->{trusted_networks_configured} = 0;
    }
  });

=item internal_networks ip.add.re.ss[/mask] ...   (default: none)

What networks or hosts are 'internal' in your setup.   B<Internal> means
that relay hosts on these networks are considered to be MXes for your
domain(s), or internal relays.  This uses the same format as
C<trusted_networks>, above.

This value is used when checking 'dial-up' or dynamic IP address
blocklists, in order to detect direct-to-MX spamming.

Trusted relays that accept mail directly from dial-up connections should
not be listed in C<internal_networks>. List them only in
C<trusted_networks>.

If C<trusted_networks> is set and C<internal_networks> is not, the value
of C<trusted_networks> will be used for this parameter.

If neither C<trusted_networks> or C<internal_networks> is set, no addresses
will be considered local; in other words, any relays past the machine where
SpamAssassin is running will be considered external.

Every entry in C<internal_networks> must appear in C<trusted_networks>; in
other words, C<internal_networks> is always a subset of the trusted set.

Note: 127/8 is always included in internal_networks, regardless of your config.

=cut

  push (@cmds, {
    setting => 'internal_networks',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
	return $MISSING_REQUIRED_VALUE;
      }
      foreach my $net (split (/\s+/, $value)) {
        $self->{internal_networks}->add_cidr ($net);
      }
      $self->{internal_networks_configured} = 1;
    }
  });

=item clear_internal_networks

Empty the list of internal networks.

=cut

  push (@cmds, {
    setting => 'clear_internal_networks',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      $self->{internal_networks} = $self->new_netset();
      $self->{internal_networks_configured} = 0;
    }
  });

=item msa_networks ip.add.re.ss[/mask] ...   (default: none)

The networks or hosts are acting as MSAs in your setup.  B<MSA> means
that the relay hosts on these networks accept mail from your own users
and authenticates them appropriately.  These relays will never accept
mail from hosts that aren't authenticated in some way.  Examples of
authentication include, IP lists, SMTP AUTH, POP-before-SMTP, etc.

All relays found in the message headers after the MSA relay will take
on the same trusted and internal classifcations as the MSA relay itself,
as defined by your I<trusted_networks> and I<internal_networks> configuration.

For example, if the MSA relay is trusted and internal so will all of the
relays that precede it.

When using msa_networks to identify an MSA it is recommended that you treat
that MSA as both trusted and internal.  When an MSA is not included in
msa_networks you should treat the MSA as trusted but not internal, however
if the MSA is also acting as an MX or intermediate relay you must always
treat it as both trusted and internal and ensure that the MSA includes
visible auth tokens in its Received header to identify submission clients.

B<Warning:> Never include an MSA that also acts as an MX (or is also an
intermediate relay for an MX) or otherwise accepts mail from
non-authenticated users in msa_networks.  Doing so will result in unknown
external relays being trusted.

=cut

  push (@cmds, {
    setting => 'msa_networks',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
	return $MISSING_REQUIRED_VALUE;
      }
      foreach my $net (split (/\s+/, $value)) {
        $self->{msa_networks}->add_cidr ($net);
      }
      $self->{msa_networks_configured} = 1;
    }
  });

=item clear_msa_networks

Empty the list of msa networks.

=cut

  push (@cmds, {
    setting => 'clear_msa_networks',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      $self->{msa_networks} = Mail::SpamAssassin::NetSet->new(); # not new_netset
      $self->{msa_networks_configured} = 0;
    }
  });

=item always_trust_envelope_sender ( 0 | 1 )   (default: 0)

Trust the envelope sender even if the message has been passed through one or
more trusted relays.  See also C<envelope_sender_header>.

=cut

  push (@cmds, {
    setting => 'always_trust_envelope_sender',
    default => 0,
    type => $CONF_TYPE_BOOL
  });

=item skip_rbl_checks ( 0 | 1 )   (default: 0)

By default, SpamAssassin will run RBL checks.  If your ISP already does this
for you, set this to 1.

=cut

  push (@cmds, {
    setting => 'skip_rbl_checks',
    default => 0,
    type => $CONF_TYPE_BOOL
  });

=item dns_available { yes | test[: name1 name2...] | no }   (default: test)

By default, SpamAssassin will query some default hosts on the internet to
attempt to check if DNS is working or not. The problem is that it can
introduce some delay if your network connection is down, and in some cases it
can wrongly guess that DNS is unavailable because the test connections failed.
SpamAssassin includes a default set of 13 servers, among which 3 are picked
randomly.

You can however specify your own list by specifying

  dns_available test: domain1.tld domain2.tld domain3.tld

Please note, the DNS test queries for NS records.

SpamAssassin's network rules are run in parallel.  This can cause overhead in
terms of the number of file descriptors required; it is recommended that the
minimum limit on file descriptors be raised to at least 256 for safety.

=cut

  push (@cmds, {
    setting => 'dns_available',
    default => 'test',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /^test(?::\s+.+)?$/) {
        $self->{dns_available} = $value;
      }
      elsif ($value =~ /^(?:yes|1)$/) {
        $self->{dns_available} = 'yes';
      }
      elsif ($value =~ /^(?:no|0)$/) {
        $self->{dns_available} = 'no';
      }
      else {
        return $INVALID_VALUE;
      }
    }
  });

=item dns_test_interval n   (default: 600 seconds)

If dns_available is set to 'test' (which is the default), the dns_test_interval
time in number of seconds will tell SpamAssassin how often to retest for working DNS.

=cut

  push (@cmds, {
    setting => 'dns_test_interval',
    default => 600,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value !~ /^\d+$/) { return $INVALID_VALUE; }
      $self->{dns_test_interval} = $value;
    }
  });

=back

=head2 LEARNING OPTIONS

=over 4

=item use_bayes ( 0 | 1 )		(default: 1)

Whether to use the naive-Bayesian-style classifier built into
SpamAssassin.  This is a master on/off switch for all Bayes-related
operations.

=cut

  push (@cmds, {
    setting => 'use_bayes',
    default => 1,
    type => $CONF_TYPE_BOOL
  });

=item use_bayes_rules ( 0 | 1 )		(default: 1)

Whether to use rules using the naive-Bayesian-style classifier built
into SpamAssassin.  This allows you to disable the rules while leaving
auto and manual learning enabled.

=cut

  push (@cmds, {
    setting => 'use_bayes_rules',
    default => 1,
    type => $CONF_TYPE_BOOL
  });

=item bayes_auto_learn ( 0 | 1 )      (default: 1)

Whether SpamAssassin should automatically feed high-scoring mails (or
low-scoring mails, for non-spam) into its learning systems.  The only
learning system supported currently is a naive-Bayesian-style classifier.

See the documentation for the
C<Mail::SpamAssassin::Plugin::AutoLearnThreshold> plugin module
for details on how Bayes auto-learning is implemented by default.

=cut

  push (@cmds, {
    setting => 'bayes_auto_learn',
    default => 1,
    type => $CONF_TYPE_BOOL
  });

=item bayes_ignore_header header_name

If you receive mail filtered by upstream mail systems, like
a spam-filtering ISP or mailing list, and that service adds
new headers (as most of them do), these headers may provide
inappropriate cues to the Bayesian classifier, allowing it
to take a "short cut". To avoid this, list the headers using this
setting.  Example:

        bayes_ignore_header X-Upstream-Spamfilter
        bayes_ignore_header X-Upstream-SomethingElse

=cut

  push (@cmds, {
    setting => 'bayes_ignore_header',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $MISSING_REQUIRED_VALUE;
      }
      push (@{$self->{bayes_ignore_headers}}, split(/\s+/, $value));
    }
  });

=item bayes_ignore_from add@ress.com

Bayesian classification and autolearning will not be performed on mail
from the listed addresses.  Program C<sa-learn> will also ignore the
listed addresses if it is invoked using the C<--use-ignores> option.
One or more addresses can be listed, see C<whitelist_from>.

Spam messages from certain senders may contain many words that
frequently occur in ham.  For example, one might read messages from a
preferred bookstore but also get unwanted spam messages from other
bookstores.  If the unwanted messages are learned as spam then any
messages discussing books, including the preferred bookstore and
antiquarian messages would be in danger of being marked as spam.  The
addresses of the annoying bookstores would be listed.  (Assuming they
were halfway legitimate and didn't send you mail through myriad
affiliates.)

Those who have pieces of spam in legitimate messages or otherwise
receive ham messages containing potentially spammy words might fear
that some spam messages might be in danger of being marked as ham.
The addresses of the spam mailing lists, correspondents, etc.  would
be listed.

=cut

  push (@cmds, {
    setting => 'bayes_ignore_from',
    type => $CONF_TYPE_ADDRLIST
  });

=item bayes_ignore_to add@ress.com

Bayesian classification and autolearning will not be performed on mail
to the listed addresses.  See C<bayes_ignore_from> for details.

=cut

  push (@cmds, {
    setting => 'bayes_ignore_to',
    type => $CONF_TYPE_ADDRLIST
  });

=item bayes_min_ham_num			(Default: 200)

=item bayes_min_spam_num		(Default: 200)

To be accurate, the Bayes system does not activate until a certain number of
ham (non-spam) and spam have been learned.  The default is 200 of each ham and
spam, but you can tune these up or down with these two settings.

=cut

  push (@cmds, {
    setting => 'bayes_min_ham_num',
    default => 200,
    type => $CONF_TYPE_NUMERIC
  });
  push (@cmds, {
    setting => 'bayes_min_spam_num',
    default => 200,
    type => $CONF_TYPE_NUMERIC
  });

=item bayes_learn_during_report         (Default: 1)

The Bayes system will, by default, learn any reported messages
(C<spamassassin -r>) as spam.  If you do not want this to happen, set
this option to 0.

=cut

  push (@cmds, {
    setting => 'bayes_learn_during_report',
    default => 1,
    type => $CONF_TYPE_BOOL
  });

=item bayes_sql_override_username

Used by BayesStore::SQL storage implementation.

If this options is set the BayesStore::SQL module will override the set
username with the value given.  This could be useful for implementing global or
group bayes databases.

=cut

  push (@cmds, {
    setting => 'bayes_sql_override_username',
    default => '',
    type => $CONF_TYPE_STRING
  });

=item bayes_use_hapaxes		(default: 1)

Should the Bayesian classifier use hapaxes (words/tokens that occur only
once) when classifying?  This produces significantly better hit-rates, but
increases database size by about a factor of 8 to 10.

=cut

  push (@cmds, {
    setting => 'bayes_use_hapaxes',
    default => 1,
    type => $CONF_TYPE_BOOL
  });

=item bayes_journal_max_size		(default: 102400)

SpamAssassin will opportunistically sync the journal and the database.
It will do so once a day, but will sync more often if the journal file
size goes above this setting, in bytes.  If set to 0, opportunistic
syncing will not occur.

=cut

  push (@cmds, {
    setting => 'bayes_journal_max_size',
    default => 102400,
    type => $CONF_TYPE_NUMERIC
  });

=item bayes_expiry_max_db_size		(default: 150000)

What should be the maximum size of the Bayes tokens database?  When expiry
occurs, the Bayes system will keep either 75% of the maximum value, or
100,000 tokens, whichever has a larger value.  150,000 tokens is roughly
equivalent to a 8Mb database file.

=cut

  push (@cmds, {
    setting => 'bayes_expiry_max_db_size',
    default => 150000,
    type => $CONF_TYPE_NUMERIC
  });

=item bayes_auto_expire       		(default: 1)

If enabled, the Bayes system will try to automatically expire old tokens
from the database.  Auto-expiry occurs when the number of tokens in the
database surpasses the bayes_expiry_max_db_size value.

=cut

  push (@cmds, {
    setting => 'bayes_auto_expire',
    default => 1,
    type => $CONF_TYPE_BOOL
  });

=item bayes_learn_to_journal  	(default: 0)

If this option is set, whenever SpamAssassin does Bayes learning, it
will put the information into the journal instead of directly into the
database.  This lowers contention for locking the database to execute
an update, but will also cause more access to the journal and cause a
delay before the updates are actually committed to the Bayes database.

=cut

  push (@cmds, {
    setting => 'bayes_learn_to_journal',
    default => 0,
    type => $CONF_TYPE_BOOL
  });

=back

=head2 MISCELLANEOUS OPTIONS

=over 4

=item lock_method type

Select the file-locking method used to protect database files on-disk. By
default, SpamAssassin uses an NFS-safe locking method on UNIX; however, if you
are sure that the database files you'll be using for Bayes and AWL storage will
never be accessed over NFS, a non-NFS-safe locking system can be selected.

This will be quite a bit faster, but may risk file corruption if the files are
ever accessed by multiple clients at once, and one or more of them is accessing
them through an NFS filesystem.

Note that different platforms require different locking systems.

The supported locking systems for C<type> are as follows:

=over 4

=item I<nfssafe> - an NFS-safe locking system

=item I<flock> - simple UNIX C<flock()> locking

=item I<win32> - Win32 locking using C<sysopen (..., O_CREAT|O_EXCL)>.

=back

nfssafe and flock are only available on UNIX, and win32 is only available
on Windows.  By default, SpamAssassin will choose either nfssafe or
win32 depending on the platform in use.

=cut

  push (@cmds, {
    setting => 'lock_method',
    default => '',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value !~ /^(nfssafe|flock|win32)$/) {
        return $INVALID_VALUE;
      }
      
      $self->{lock_method} = $value;
      # recreate the locker
      $self->{main}->create_locker();
    }
  });

=item fold_headers ( 0 | 1 )        (default: 1)

By default,  headers added by SpamAssassin will be whitespace folded.
In other words, they will be broken up into multiple lines instead of
one very long one and each other line will have a tabulator prepended
to mark it as a continuation of the preceding one.

The automatic wrapping can be disabled here.  Note that this can generate very
long lines.

=cut

  push (@cmds, {
    setting => 'fold_headers',
    default => 1,
    type => $CONF_TYPE_BOOL
  });

=item report_safe_copy_headers header_name ...

If using C<report_safe>, a few of the headers from the original message
are copied into the wrapper header (From, To, Cc, Subject, Date, etc.)
If you want to have other headers copied as well, you can add them
using this option.  You can specify multiple headers on the same line,
separated by spaces, or you can just use multiple lines.

=cut

  push (@cmds, {
    setting => 'report_safe_copy_headers',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $MISSING_REQUIRED_VALUE;
      }
      push(@{$self->{report_safe_copy_headers}}, split(/\s+/, $value));
    }
  });

=item envelope_sender_header Name-Of-Header

SpamAssassin will attempt to discover the address used in the 'MAIL FROM:'
phase of the SMTP transaction that delivered this message, if this data has
been made available by the SMTP server.  This is used in the C<EnvelopeFrom>
pseudo-header, and for various rules such as SPF checking.

By default, various MTAs will use different headers, such as the following:

    X-Envelope-From
    Envelope-Sender
    X-Sender
    Return-Path

SpamAssassin will attempt to use these, if some heuristics (such as the header
placement in the message, or the absence of fetchmail signatures) appear to
indicate that they are safe to use.  However, it may choose the wrong headers
in some mailserver configurations.  (More discussion of this can be found
in bug 2142 and bug 4747 in the SpamAssassin BugZilla.)

To avoid this heuristic failure, the C<envelope_sender_header> setting may be
helpful.  Name the header that your MTA adds to messages containing the address
used at the MAIL FROM step of the SMTP transaction.

If the header in question contains C<E<lt>> or C<E<gt>> characters at the start
and end of the email address in the right-hand side, as in the SMTP
transaction, these will be stripped.

If the header is not found in a message, or if it's value does not contain an
C<@> sign, SpamAssassin will issue a warning in the logs and fall back to its
default heuristics.

(Note for MTA developers: we would prefer if the use of a single header be
avoided in future, since that precludes 'downstream' spam scanning.
C<http://wiki.apache.org/spamassassin/EnvelopeSenderInReceived> details a
better proposal, storing the envelope sender at each hop in the C<Received>
header.)

example:

    envelope_sender_header X-SA-Exim-Mail-From

=cut

  push (@cmds, {
    setting => 'envelope_sender_header',
    default => undef,
    type => $CONF_TYPE_STRING
  });

=item describe SYMBOLIC_TEST_NAME description ...

Used to describe a test.  This text is shown to users in the detailed report.

Note that test names which begin with '__' are reserved for meta-match
sub-rules, and are not scored or listed in the 'tests hit' reports.

Also note that by convention, rule descriptions should be limited in
length to no more than 50 characters.

=cut

  push (@cmds, {
    command => 'describe',
    setting => 'descriptions',
    is_frequent => 1,
    type => $CONF_TYPE_HASH_KEY_VALUE
  });

=item report_charset CHARSET		(default: unset)

Set the MIME Content-Type charset used for the text/plain report which
is attached to spam mail messages.

=cut

  push (@cmds, {
    setting => 'report_charset',
    default => '',
    type => $CONF_TYPE_STRING
  });

=item report ...some text for a report...

Set the report template which is attached to spam mail messages.  See the
C<10_default_prefs.cf> configuration file in C</usr/share/spamassassin> for an
example.

If you change this, try to keep it under 78 columns. Each C<report>
line appends to the existing template, so use C<clear_report_template>
to restart.

Tags can be included as explained above.

=cut

  push (@cmds, {
    command => 'report',
    setting => 'report_template',
    type => $CONF_TYPE_TEMPLATE
  });

=item clear_report_template

Clear the report template.

=cut

  push (@cmds, {
    command => 'clear_report_template',
    setting => 'report_template',
    default => '',
    code => \&Mail::SpamAssassin::Conf::Parser::set_template_clear
  });

=item report_contact ...text of contact address...

Set what _CONTACTADDRESS_ is replaced with in the above report text.
By default, this is 'the administrator of that system', since the hostname
of the system the scanner is running on is also included.

=cut

  push (@cmds, {
    setting => 'report_contact',
    default => 'the administrator of that system',
    type => $CONF_TYPE_STRING
  });

=item report_hostname ...hostname to use...

Set what _HOSTNAME_ is replaced with in the above report text.
By default, this is determined dynamically as whatever the host running
SpamAssassin calls itself.

=cut

  push (@cmds, {
    setting => 'report_hostname',
    default => '',
    type => $CONF_TYPE_STRING
  });

=item unsafe_report ...some text for a report...

Set the report template which is attached to spam mail messages which contain a
non-text/plain part.  See the C<10_default_prefs.cf> configuration file in
C</usr/share/spamassassin> for an example.

Each C<unsafe-report> line appends to the existing template, so use
C<clear_unsafe_report_template> to restart.

Tags can be used in this template (see above for details).

=cut

  push (@cmds, {
    command => 'unsafe_report',
    setting => 'unsafe_report_template',
    default => '',
    type => $CONF_TYPE_TEMPLATE
  });

=item clear_unsafe_report_template

Clear the unsafe_report template.

=cut

  push (@cmds, {
    command => 'clear_unsafe_report_template',
    setting => 'unsafe_report_template',
    code => \&Mail::SpamAssassin::Conf::Parser::set_template_clear
  });

=back

=head1 RULE DEFINITIONS AND PRIVILEGED SETTINGS

These settings differ from the ones above, in that they are considered
'privileged'.  Only users running C<spamassassin> from their procmailrc's or
forward files, or sysadmins editing a file in C</etc/mail/spamassassin>, can
use them.   C<spamd> users cannot use them in their C<user_prefs> files, for
security and efficiency reasons, unless C<allow_user_rules> is enabled (and
then, they may only add rules from below).

=over 4

=item allow_user_rules ( 0 | 1 )		(default: 0)

This setting allows users to create rules (and only rules) in their
C<user_prefs> files for use with C<spamd>. It defaults to off, because
this could be a severe security hole. It may be possible for users to
gain root level access if C<spamd> is run as root. It is NOT a good
idea, unless you have some other way of ensuring that users' tests are
safe. Don't use this unless you are certain you know what you are
doing. Furthermore, this option causes spamassassin to recompile all
the tests each time it processes a message for a user with a rule in
his/her C<user_prefs> file, which could have a significant effect on
server load. It is not recommended.

Note that it is not currently possible to use C<allow_user_rules> to modify an
existing system rule from a C<user_prefs> file with C<spamd>.

=cut

  push (@cmds, {
    setting => 'allow_user_rules',
    is_priv => 1,
    default => 0,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $MISSING_REQUIRED_VALUE;
      }
      elsif ($value !~ /^[01]$/) {
        return $INVALID_VALUE;
      }

      $self->{allow_user_rules} = $value+0;
      dbg("config: " . ($self->{allow_user_rules} ? "allowing":"not allowing") . " user rules!");
    }
  });

=item redirector_pattern	/pattern/modifiers

A regex pattern that matches both the redirector site portion, and
the target site portion of a URI.

Note: The target URI portion must be surrounded in parentheses and
      no other part of the pattern may create a backreference.

Example: http://chkpt.zdnet.com/chkpt/whatever/spammer.domain/yo/dude

  redirector_pattern	/^https?:\/\/(?:opt\.)?chkpt\.zdnet\.com\/chkpt\/\w+\/(.*)$/i

=cut

  push (@cmds, {
    setting => 'redirector_pattern',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
	return $MISSING_REQUIRED_VALUE;
      }
      elsif (!$self->{parser}->is_delimited_regexp_valid("redirector_pattern", $value)) {
	return $INVALID_VALUE;
      }

      # convert to qr// while including modifiers
      $value =~ /^m?(\W)(.*)(?:\1|>|}|\)|\])(.*?)$/;
      my $pattern = $2;
      $pattern = "(?".$3.")".$pattern if $3;
      $pattern = qr/$pattern/;

      push @{$self->{main}->{conf}->{redirector_patterns}}, $pattern;
      # dbg("config: adding redirector regex: " . $value);
    }
  });

=item header SYMBOLIC_TEST_NAME header op /pattern/modifiers	[if-unset: STRING]

Define a test.  C<SYMBOLIC_TEST_NAME> is a symbolic test name, such as
'FROM_ENDS_IN_NUMS'.  C<header> is the name of a mail header, such as
'Subject', 'To', etc.

Appending C<:raw> to the header name will inhibit decoding of quoted-printable
or base-64 encoded strings.

Appending C<:addr> to the header name will cause everything except
the first email address to be removed from the header.  For example,
all of the following will result in "example@foo":

=over 4

=item example@foo

=item example@foo (Foo Blah)

=item example@foo, example@bar

=item display: example@foo (Foo Blah), example@bar ;

=item Foo Blah <example@foo>

=item "Foo Blah" <example@foo>

=item "'Foo Blah'" <example@foo>

=back

Appending C<:name> to the header name will cause everything except
the first real name to be removed from the header.  For example,
all of the following will result in "Foo Blah"

=over 4

=item example@foo (Foo Blah)

=item example@foo (Foo Blah), example@bar

=item display: example@foo (Foo Blah), example@bar ;

=item Foo Blah <example@foo>

=item "Foo Blah" <example@foo>

=item "'Foo Blah'" <example@foo>

=back

There are several special pseudo-headers that can be specified:

=over 4

=item C<ALL> can be used to mean the text of all the message's headers.

=item C<ToCc> can be used to mean the contents of both the 'To' and 'Cc'
headers.

=item C<EnvelopeFrom> is the address used in the 'MAIL FROM:' phase of the SMTP
transaction that delivered this message, if this data has been made available
by the SMTP server.  See C<envelope_sender_header> for more information
on how to set this.

=item C<MESSAGEID> is a symbol meaning all Message-Id's found in the message;
some mailing list software moves the real 'Message-Id' to 'Resent-Message-Id'
or 'X-Message-Id', then uses its own one in the 'Message-Id' header.  The value
returned for this symbol is the text from all 3 headers, separated by newlines.

=item C<X-Spam-Relays-Untrusted>, C<X-Spam-Relays-Trusted>,
C<X-Spam-Relays-Internal> and C<X-Spam-Relays-External> represent a portable,
pre-parsed representation of the message's network path, as recorded in the
Received headers, divided into 'trusted' vs 'untrusted' and 'internal' vs
'external' sets.  See C<http://wiki.apache.org/spamassassin/TrustedRelays> for
more details.

=back

C<op> is either C<=~> (contains regular expression) or C<!~> (does not contain
regular expression), and C<pattern> is a valid Perl regular expression, with
C<modifiers> as regexp modifiers in the usual style.   Note that multi-line
rules are not supported, even if you use C<x> as a modifier.  Also note that
the C<#> character must be escaped (C<\#>) or else it will be considered to be
the start of a comment and not part of the regexp.

If the C<[if-unset: STRING]> tag is present, then C<STRING> will
be used if the header is not found in the mail message.

Test names must not start with a number, and must contain only
alphanumerics and underscores.  It is suggested that lower-case characters
not be used, and names have a length of no more than 22 characters,
as an informal convention.  Dashes are not allowed.

Note that test names which begin with '__' are reserved for meta-match
sub-rules, and are not scored or listed in the 'tests hit' reports.
Test names which begin with 'T_' are reserved for tests which are
undergoing QA, and these are given a very low score.

If you add or modify a test, please be sure to run a sanity check afterwards
by running C<spamassassin --lint>.  This will avoid confusing error
messages, or other tests being skipped as a side-effect.

=item header SYMBOLIC_TEST_NAME exists:name_of_header

Define a header existence test.  C<name_of_header> is the name of a
header to test for existence.  This is just a very simple version of
the above header tests.

=item header SYMBOLIC_TEST_NAME eval:name_of_eval_method([arguments])

Define a header eval test.  C<name_of_eval_method> is the name of
a method on the C<Mail::SpamAssassin::EvalTests> object.  C<arguments>
are optional arguments to the function call.

=item header SYMBOLIC_TEST_NAME eval:check_rbl('set', 'zone' [, 'sub-test'])

Check a DNSBL (a DNS blacklist or whitelist).  This will retrieve Received:
headers from the message, extract the IP addresses, select which ones are
'untrusted' based on the C<trusted_networks> logic, and query that DNSBL
zone.  There's a few things to note:

=over 4

=item duplicated or private IPs

Duplicated IPs are only queried once and reserved IPs are not queried.
Private IPs are those listed in
<http://www.iana.org/assignments/ipv4-address-space>,
<http://duxcw.com/faq/network/privip.htm>,
<http://duxcw.com/faq/network/autoip.htm>, or
<ftp://ftp.rfc-editor.org/in-notes/rfc3330.txt> as private.

=item the 'set' argument

This is used as a 'zone ID'.  If you want to look up a multiple-meaning zone
like NJABL or SORBS, you can then query the results from that zone using it;
but all check_rbl_sub() calls must use that zone ID.

Also, if more than one IP address gets a DNSBL hit for a particular rule, it
does not affect the score because rules only trigger once per message.

=item the 'zone' argument

This is the root zone of the DNSBL, ending in a period.

=item the 'sub-test' argument

This optional argument behaves the same as the sub-test argument in
C<check_rbl_sub()> below.

=item selecting all IPs except for the originating one

This is accomplished by placing '-notfirsthop' at the end of the set name.
This is useful for querying against DNS lists which list dialup IP
addresses; the first hop may be a dialup, but as long as there is at least
one more hop, via their outgoing SMTP server, that's legitimate, and so
should not gain points.  If there is only one hop, that will be queried
anyway, as it should be relaying via its outgoing SMTP server instead of
sending directly to your MX (mail exchange).

=item selecting IPs by whether they are trusted

When checking a 'nice' DNSBL (a DNS whitelist), you cannot trust the IP
addresses in Received headers that were not added by trusted relays.  To
test the first IP address that can be trusted, place '-firsttrusted' at the
end of the set name.  That should test the IP address of the relay that
connected to the most remote trusted relay.

Note that this requires that SpamAssassin know which relays are trusted.  For
simple cases, SpamAssassin can make a good estimate.  For complex cases, you
may get better results by setting C<trusted_networks> manually.

In addition, you can test all untrusted IP addresses by placing '-untrusted'
at the end of the set name.   Important note -- this does NOT include the 
IP address from the most recent 'untrusted line', as used in '-firsttrusted'
above.  That's because we're talking about the trustworthiness of the
IP address data, not the source header line, here; and in the case of 
the most recent header (the 'firsttrusted'), that data can be trusted.
See the Wiki page at C<http://wiki.apache.org/spamassassin/TrustedRelays>
for more information on this.

=item Selecting just the last external IP

By using '-lastexternal' at the end of the set name, you can select only
the external host that connected to your internal network, or at least
the last external host with a public IP.

=back

=item header SYMBOLIC_TEST_NAME eval:check_rbl_txt('set', 'zone')

Same as check_rbl(), except querying using IN TXT instead of IN A records.
If the zone supports it, it will result in a line of text describing
why the IP is listed, typically a hyperlink to a database entry.

=item header SYMBOLIC_TEST_NAME eval:check_rbl_sub('set', 'sub-test')

Create a sub-test for 'set'.  If you want to look up a multi-meaning zone
like relays.osirusoft.com, you can then query the results from that zone
using the zone ID from the original query.  The sub-test may either be an
IPv4 dotted address for RBLs that return multiple A records or a
non-negative decimal number to specify a bitmask for RBLs that return a
single A record containing a bitmask of results, a SenderBase test
beginning with "sb:", or (if none of the preceding options seem to fit) a
regular expression.

Note: the set name must be exactly the same for as the main query rule,
including selections like '-notfirsthop' appearing at the end of the set
name.

=cut

  push (@cmds, {
    setting => 'header',
    is_frequent => 1,
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /^(\S+)\s+(?:rbl)?eval:(.*)$/) {
        my ($name, $fn) = ($1, $2);

        if ($fn =~ /^check_(?:rbl|dns)/) {
          $self->{parser}->add_test ($name, $fn, $TYPE_RBL_EVALS);
        }
        else {
          $self->{parser}->add_test ($name, $fn, $TYPE_HEAD_EVALS);
        }
      }
      elsif ($value =~ /^(\S+)\s+exists:(.*)$/) {
        $self->{parser}->add_test ($1, "$2 =~ /./", $TYPE_HEAD_TESTS);
        $self->{descriptions}->{$1} = "Found a $2 header";
      }
      else {
	my @values = split(/\s+/, $value, 2);
	if (@values != 2) {
	  return $MISSING_REQUIRED_VALUE;
	}
        $self->{parser}->add_test (@values, $TYPE_HEAD_TESTS);
      }
    }
  });

=item body SYMBOLIC_TEST_NAME /pattern/modifiers

Define a body pattern test.  C<pattern> is a Perl regular expression.  Note:
as per the header tests, C<#> must be escaped (C<\#>) or else it is considered
the beginning of a comment.

The 'body' in this case is the textual parts of the message body;
any non-text MIME parts are stripped, and the message decoded from
Quoted-Printable or Base-64-encoded format if necessary.  The message
Subject header is considered part of the body and becomes the first
paragraph when running the rules.  All HTML tags and line breaks will
be removed before matching.

=item body SYMBOLIC_TEST_NAME eval:name_of_eval_method([args])

Define a body eval test.  See above.

=cut

  push (@cmds, {
    setting => 'body',
    is_frequent => 1,
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /^(\S+)\s+eval:(.*)$/) {
        $self->{parser}->add_test ($1, $2, $TYPE_BODY_EVALS);
      }
      else {
	my @values = split(/\s+/, $value, 2);
	if (@values != 2) {
	  return $MISSING_REQUIRED_VALUE;
	}
        $self->{parser}->add_test (@values, $TYPE_BODY_TESTS);
      }
    }
  });

=item uri SYMBOLIC_TEST_NAME /pattern/modifiers

Define a uri pattern test.  C<pattern> is a Perl regular expression.  Note: as
per the header tests, C<#> must be escaped (C<\#>) or else it is considered
the beginning of a comment.

The 'uri' in this case is a list of all the URIs in the body of the email,
and the test will be run on each and every one of those URIs, adjusting the
score if a match is found. Use this test instead of one of the body tests
when you need to match a URI, as it is more accurately bound to the start/end
points of the URI, and will also be faster.

=cut

# we don't do URI evals yet - maybe later
#    if (/^uri\s+(\S+)\s+eval:(.*)$/) {
#      $self->{parser}->add_test ($1, $2, $TYPE_URI_EVALS);
#      next;
#    }
  push (@cmds, {
    setting => 'uri',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      my @values = split(/\s+/, $value, 2);
      if (@values != 2) {
        return $MISSING_REQUIRED_VALUE;
      }
      $self->{parser}->add_test (@values, $TYPE_URI_TESTS);
    }
  });

=item rawbody SYMBOLIC_TEST_NAME /pattern/modifiers

Define a raw-body pattern test.  C<pattern> is a Perl regular expression.
Note: as per the header tests, C<#> must be escaped (C<\#>) or else it is
considered the beginning of a comment.

The 'raw body' of a message is the raw data inside all textual parts.
The text will be decoded from base64 or quoted-printable encoding,
but HTML tags and line breaks will still be present.   The pattern
will be applied line-by-line.

=item rawbody SYMBOLIC_TEST_NAME eval:name_of_eval_method([args])

Define a raw-body eval test.  See above.

=cut

  push (@cmds, {
    setting => 'rawbody',
    is_frequent => 1,
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /^(\S+)\s+eval:(.*)$/) {
        $self->{parser}->add_test ($1, $2, $TYPE_RAWBODY_EVALS);
      } else {
	my @values = split(/\s+/, $value, 2);
	if (@values != 2) {
	  return $MISSING_REQUIRED_VALUE;
	}
        $self->{parser}->add_test (@values, $TYPE_RAWBODY_TESTS);
      }
    }
  });

=item full SYMBOLIC_TEST_NAME /pattern/modifiers

Define a full message pattern test.  C<pattern> is a Perl regular expression.
Note: as per the header tests, C<#> must be escaped (C<\#>) or else it is
considered the beginning of a comment.

The full message is the pristine message headers plus the pristine message
body, including all MIME data such as images, other attachments, MIME
boundaries, etc.

=item full SYMBOLIC_TEST_NAME eval:name_of_eval_method([args])

Define a full message eval test.  See above.

=cut

  push (@cmds, {
    setting => 'full',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /^(\S+)\s+eval:(.*)$/) {
        $self->{parser}->add_test ($1, $2, $TYPE_FULL_EVALS);
      } else {
	my @values = split(/\s+/, $value, 2);
	if (@values != 2) {
	  return $MISSING_REQUIRED_VALUE;
	}
        $self->{parser}->add_test (@values, $TYPE_FULL_TESTS);
      }
    }
  });

=item meta SYMBOLIC_TEST_NAME boolean expression

Define a boolean expression test in terms of other tests that have
been hit or not hit.  For example:

meta META1        TEST1 && !(TEST2 || TEST3)

Note that English language operators ("and", "or") will be treated as
rule names, and that there is no C<XOR> operator.

=item meta SYMBOLIC_TEST_NAME boolean arithmetic expression

Can also define a boolean arithmetic expression in terms of other
tests, with an unhit test having the value "0" and a hit test having a
nonzero value.  The value of a hit meta test is that of its arithmetic
expression.  The value of a hit eval test is that returned by its
method.  The value of a hit header, body, rawbody, uri, or full test
which has the "multiple" tflag is the number of times the test hit.
The value of any other type of hit test is "1".

For example:

meta META2        (3 * TEST1 - 2 * TEST2) > 0

Note that Perl builtins and functions, like C<abs()>, B<can't> be
used, and will be treated as rule names.

If you want to define a meta-rule, but do not want its individual sub-rules to
count towards the final score unless the entire meta-rule matches, give the
sub-rules names that start with '__' (two underscores).  SpamAssassin will
ignore these for scoring.

=cut

  push (@cmds, {
    setting => 'meta',
    is_frequent => 1,
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      my @values = split(/\s+/, $value, 2);
      if (@values != 2) {
        return $MISSING_REQUIRED_VALUE;
      }
      if ($values[1] =~ /\*\s*\*/) {
	info("config: found invalid '**' or '* *' operator in meta command");
        return $INVALID_VALUE;
      }
      $self->{parser}->add_test (@values, $TYPE_META_TESTS);
    }
  });

=item tflags SYMBOLIC_TEST_NAME [ {net|nice|learn|userconf|noautolearn|multiple} ]

Used to set flags on a test.  These flags are used in the
score-determination back end system for details of the test's
behaviour.  Please see C<bayes_auto_learn> for more information
about tflag interaction with those systems. The following flags
can be set:

=over 4

=item  net

The test is a network test, and will not be run in the mass checking system
or if B<-L> is used, therefore its score should not be modified.

=item  nice

The test is intended to compensate for common false positives, and should be
assigned a negative score.

=item  userconf

The test requires user configuration before it can be used (like language-
specific tests).

=item  learn

The test requires training before it can be used.

=item noautolearn

The test will explicitly be ignored when calculating the score for
learning systems.

=item multiple

The test will be evaluated multiple times, for use with meta rules.
Only affects header, body, rawbody, uri, and full tests.

=back

=cut

  push (@cmds, {
    setting => 'tflags',
    is_frequent => 1,
    is_priv => 1,
    type => $CONF_TYPE_HASH_KEY_VALUE
  });

=item priority SYMBOLIC_TEST_NAME n

Assign a specific priority to a test.  All tests, except for DNS and Meta
tests, are run in increasing priority value order (negative priority values
are run before positive priority values). The default test priority is 0
(zero).

The values <-99999999999999> and <-99999999999998> have a special meaning
internally, and should not be used.

=cut

  push (@cmds, {
    setting => 'priority',
    is_priv => 1,
    type => $CONF_TYPE_HASH_KEY_VALUE
  });

=back

=head1 ADMINISTRATOR SETTINGS

These settings differ from the ones above, in that they are considered 'more
privileged' -- even more than the ones in the B<PRIVILEGED SETTINGS> section.
No matter what C<allow_user_rules> is set to, these can never be set from a
user's C<user_prefs> file when spamc/spamd is being used.  However, all
settings can be used by local programs run directly by the user.

=over 4

=item version_tag string

This tag is appended to the SA version in the X-Spam-Status header. You should
include it when modify your ruleset, especially if you plan to distribute it.
A good choice for I<string> is your last name or your initials followed by a
number which you increase with each change.

The version_tag will be lowercased, and any non-alphanumeric or period
character will be replaced by an underscore.

e.g.

  version_tag myrules1    # version=2.41-myrules1

=cut

  push (@cmds, {
    setting => 'version_tag',
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $MISSING_REQUIRED_VALUE;
      }
      my $tag = lc($value);
      $tag =~ tr/a-z0-9./_/c;
      foreach (@Mail::SpamAssassin::EXTRA_VERSION) {
        if($_ eq $tag) { $tag = undef; last; }
      }
      push(@Mail::SpamAssassin::EXTRA_VERSION, $tag) if($tag);
    }
  });

=item test SYMBOLIC_TEST_NAME (ok|fail) Some string to test against

Define a regression testing string. You can have more than one regression test
string per symbolic test name. Simply specify a string that you wish the test
to match.

These tests are only run as part of the test suite - they should not affect the
general running of SpamAssassin.

=cut

  push (@cmds, {
    setting => 'test',
    is_admin => 1,
    code => sub {
      return unless defined($Mail::SpamAssassin::Conf::COLLECT_REGRESSION_TESTS);
      my ($self, $key, $value, $line) = @_;
      if ($value !~ /^(\S+)\s+(ok|fail)\s+(.*)$/) { return $INVALID_VALUE; }
      $self->{parser}->add_regression_test($1, $2, $3);
    }
  });

=item rbl_timeout n		(default: 15)

All DNS queries are made at the beginning of a check and we try to read the
results at the end.  This value specifies the maximum period of time to wait
for an DNS query.  If most of the DNS queries have succeeded for a particular
message, then SpamAssassin will not wait for the full period to avoid wasting
time on unresponsive server(s).  For the default 15 second timeout, here is a
chart of queries remaining versus the effective timeout in seconds:

  queries left    100%  90%  80%  70%  60%  50%  40%  30%  20%  10%  0%
  timeout          15   15   14   14   13   11   10    8    5    3   0

In addition, whenever the effective timeout is lowered due to additional query
results returning, the remaining queries are always given at least one more
second before timing out, but the wait time will never exceed rbl_timeout.

For example, if 20 queries are made at the beginning of a message check and 16
queries have returned (leaving 20%), the remaining 4 queries must finish
within 5 seconds of the beginning of the check or they will be timed out.

=cut

  push (@cmds, {
    setting => 'rbl_timeout',
    is_admin => 1,
    default => 15,
    type => $CONF_TYPE_NUMERIC
  });

=item util_rb_tld tld1 tld2 ...

This option allows the addition of new TLDs to the RegistrarBoundaries code.
Updates to the list usually happen when new versions of SpamAssassin are
released, but sometimes it's necessary to add in new TLDs faster than a
release can occur.  TLDs include things like com, net, org, etc.

=cut

  push (@cmds, {
    setting => 'util_rb_tld',
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
	return $MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^[a-zA-Z]+(?:\s+[a-zA-Z]+)*$/) {
	return $INVALID_VALUE;
      }
      foreach (split(/\s+/, $value)) {
        $Mail::SpamAssassin::Util::RegistrarBoundaries::VALID_TLDS{lc $_} = 1;
      }
    }
  });

=item util_rb_2tld 2tld-1.tld 2tld-2.tld ...

This option allows the addition of new 2nd-level TLDs (2TLD) to the
RegistrarBoundaries code.  Updates to the list usually happen when new
versions of SpamAssassin are released, but sometimes it's necessary to add in
new 2TLDs faster than a release can occur.  2TLDs include things like co.uk,
fed.us, etc.

=cut

  push (@cmds, {
    setting => 'util_rb_2tld',
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
	return $MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^[^\s.]+\.[^\s.]+(?:\s+[^\s.]+\.[^\s.]+)*$/) {
	return $INVALID_VALUE;
      }
      foreach (split(/\s+/, $value)) {
        $Mail::SpamAssassin::Util::RegistrarBoundaries::TWO_LEVEL_DOMAINS{lc $_} = 1;
      }
    }
  });

=item bayes_path /path/filename	(default: ~/.spamassassin/bayes)

This is the directory and filename for Bayes databases.  Several databases
will be created, with this as the base directory and filename, with C<_toks>,
C<_seen>, etc. appended to the base.  The default setting results in files
called C<~/.spamassassin/bayes_seen>, C<~/.spamassassin/bayes_toks>, etc.

By default, each user has their own in their C<~/.spamassassin> directory with
mode 0700/0600.  For system-wide SpamAssassin use, you may want to reduce disk
space usage by sharing this across all users.  However, Bayes appears to be
more effective with individual user databases.

=cut

  push (@cmds, {
    setting => 'bayes_path',
    is_admin => 1,
    default => '__userstate__/bayes',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
	return $MISSING_REQUIRED_VALUE;
      }
      if (-d $value) {
	return $INVALID_VALUE;
      }
     $self->{bayes_path} = $value;
    }
  });

=item bayes_file_mode		(default: 0700)

The file mode bits used for the Bayesian filtering database files.

Make sure you specify this using the 'x' mode bits set, as it may also be used
to create directories.  However, if a file is created, the resulting file will
not have any execute bits set (the umask is set to 111).

=cut

  push (@cmds, {
    setting => 'bayes_file_mode',
    is_admin => 1,
    default => '0700',
    type => $CONF_TYPE_NUMERIC
  });

=item bayes_store_module Name::Of::BayesStore::Module

If this option is set, the module given will be used as an alternate
to the default bayes storage mechanism.  It must conform to the
published storage specification (see
Mail::SpamAssassin::BayesStore). For example, set this to
Mail::SpamAssassin::BayesStore::SQL to use the generic SQL storage
module.

=cut

  push (@cmds, {
    setting => 'bayes_store_module',
    is_admin => 1,
    default => '',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value !~ /^([_A-Za-z0-9:]+)$/) { return $INVALID_VALUE; }
      $self->{bayes_store_module} = $1;
    }
  });

=item bayes_sql_dsn DBI::databasetype:databasename:hostname:port

Used for BayesStore::SQL storage implementation.

This option give the connect string used to connect to the SQL based Bayes storage.

=cut

  push (@cmds, {
    setting => 'bayes_sql_dsn',
    is_admin => 1,
    default => '',
    type => $CONF_TYPE_STRING
  });

=item bayes_sql_username

Used by BayesStore::SQL storage implementation.

This option gives the username used by the above DSN.

=cut

  push (@cmds, {
    setting => 'bayes_sql_username',
    is_admin => 1,
    default => '',
    type => $CONF_TYPE_STRING
  });

=item bayes_sql_password

Used by BayesStore::SQL storage implementation.

This option gives the password used by the above DSN.

=cut

  push (@cmds, {
    setting => 'bayes_sql_password',
    is_admin => 1,
    default => '',
    type => $CONF_TYPE_STRING
  });

=item bayes_sql_username_authorized ( 0 | 1 )  (default: 0)

Whether to call the services_authorized_for_username plugin hook in BayesSQL.
If the hook does not determine that the user is allowed to use bayes or is
invalid then then database will not be initialized.

NOTE: By default the user is considered invalid until a plugin returns
a true value.  If you enable this, but do not have a proper plugin
loaded, all users will turn up as invalid.

The username passed into the plugin can be affected by the
bayes_sql_override_username config option.

=cut

  push (@cmds, {
    setting => 'bayes_sql_username_authorized',
    is_admin => 1,
    default => 0,
    type => $CONF_TYPE_BOOL
  });

=item user_scores_dsn DBI:databasetype:databasename:hostname:port

If you load user scores from an SQL database, this will set the DSN
used to connect.  Example: C<DBI:mysql:spamassassin:localhost>

If you load user scores from an LDAP directory, this will set the DSN used to
connect. You have to write the DSN as an LDAP URL, the components being the
host and port to connect to, the base DN for the seasrch, the scope of the
search (base, one or sub), the single attribute being the multivalued attribute
used to hold the configuration data (space separated pairs of key and value,
just as in a file) and finally the filter being the expression used to filter
out the wanted username. Note that the filter expression is being used in a
sprintf statement with the username as the only parameter, thus is can hold a
single __USERNAME__ expression. This will be replaced with the username.

Example: C<ldap://localhost:389/dc=koehntopp,dc=de?spamassassinconfig?uid=__USERNAME__>

=cut

  push (@cmds, {
    setting => 'user_scores_dsn',
    is_admin => 1,
    default => '',
    type => $CONF_TYPE_STRING
  });

=item user_scores_sql_username username

The authorized username to connect to the above DSN.

=cut

  push (@cmds, {
    setting => 'user_scores_sql_username',
    is_admin => 1,
    default => '',
    type => $CONF_TYPE_STRING
  });

=item user_scores_sql_password password

The password for the database username, for the above DSN.

=cut

  push (@cmds, {
    setting => 'user_scores_sql_password',
    is_admin => 1,
    default => '',
    type => $CONF_TYPE_STRING
  });

=item user_scores_sql_custom_query query

This option gives you the ability to create a custom SQL query to
retrieve user scores and preferences.  In order to work correctly your
query should return two values, the preference name and value, in that
order.  In addition, there are several "variables" that you can use
as part of your query, these variables will be substituted for the
current values right before the query is run.  The current allowed
variables are:

=over 4

=item _TABLE_

The name of the table where user scores and preferences are stored. Currently
hardcoded to userpref, to change this value you need to create a new custom
query with the new table name.

=item _USERNAME_

The current user's username.

=item _MAILBOX_

The portion before the @ as derived from the current user's username.

=item _DOMAIN_

The portion after the @ as derived from the current user's username, this
value may be null.

=back

The query must be one one continuous line in order to parse correctly.

Here are several example queries, please note that these are broken up
for easy reading, in your config it should be one continuous line.

=over 4

=item Current default query:

C<SELECT preference, value FROM _TABLE_ WHERE username = _USERNAME_ OR username = '@GLOBAL' ORDER BY username ASC>

=item Use global and then domain level defaults:

C<SELECT preference, value FROM _TABLE_ WHERE username = _USERNAME_ OR username = '@GLOBAL' OR username = '@~'||_DOMAIN_ ORDER BY username ASC>

=item Maybe global prefs should override user prefs:

C<SELECT preference, value FROM _TABLE_ WHERE username = _USERNAME_ OR username = '@GLOBAL' ORDER BY username DESC>

=back

=cut

  push (@cmds, {
    setting => 'user_scores_sql_custom_query',
    is_admin => 1,
    type => $CONF_TYPE_STRING
  });

=item user_scores_ldap_username

This is the Bind DN used to connect to the LDAP server.

Example: C<cn=master,dc=koehntopp,dc=de>

=cut

  push (@cmds, {
    setting => 'user_scores_ldap_username',
    is_admin => 1,
    default => 'username',
    type => $CONF_TYPE_STRING
  });

=item user_scores_ldap_password

This is the password used to connect to the LDAP server.

=cut

  push (@cmds, {
    setting => 'user_scores_ldap_password',
    is_admin => 1,
    default => '',
    type => $CONF_TYPE_STRING
  });

=item loadplugin PluginModuleName [/path/module.pm]

Load a SpamAssassin plugin module.  The C<PluginModuleName> is the perl module
name, used to create the plugin object itself.

C</path/to/module.pm> is the file to load, containing the module's perl code;
if it's specified as a relative path, it's considered to be relative to the
current configuration file.  If it is omitted, the module will be loaded
using perl's search path (the C<@INC> array).

See C<Mail::SpamAssassin::Plugin> for more details on writing plugins.

=cut

  push (@cmds, {
    setting => 'loadplugin',
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $MISSING_REQUIRED_VALUE;
      }
      if ($value =~ /^(\S+)\s+(\S+)$/) {
        $self->load_plugin ($1, $2);
      } elsif ($value =~ /^(?:\S+)$/) {
        $self->load_plugin ($value);
      } else {
	return $INVALID_VALUE;
      }
    }
  });

=item tryplugin PluginModuleName [/path/module.pm]

Same as C<loadplugin>, but silently ignored if the .pm file cannot be found in
the filesystem.

=cut

  push (@cmds, {
    setting => 'tryplugin',
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $MISSING_REQUIRED_VALUE;
      }
      if ($value =~ /^(\S+)\s+(\S+)$/) {
        $self->load_plugin ($1, $2, 1);
      } elsif ($value =~ /^(?:\S+)$/) {
        $self->load_plugin ($value, undef, 1);
      } else {
	return $INVALID_VALUE;
      }
    }
  });

=back

=head1 PREPROCESSING OPTIONS

=over 4

=item include filename

Include configuration lines from C<filename>.   Relative paths are considered
relative to the current configuration file or user preferences file.

=item if (conditional perl expression)

Used to support conditional interpretation of the configuration
file. Lines between this and a corresponding C<else> or C<endif> line,
will be ignored unless the conditional expression evaluates as true
(in the perl sense; that is, defined and non-0).

The conditional accepts a limited subset of perl for security -- just enough to
perform basic arithmetic comparisons.  The following input is accepted:

=over 4

=item numbers, whitespace, arithmetic operations and grouping

Namely these characters and ranges:

  ( ) - + * / _ . , < = > ! ~ 0-9 whitespace

=item version

This will be replaced with the version number of the currently-running
SpamAssassin engine.  Note: The version used is in the internal SpamAssassin
version format which is C<x.yyyzzz>, where x is major version, y is minor
version, and z is maintenance version.  So 3.0.0 is C<3.000000>, and 3.4.80 is
C<3.004080>.

=item plugin(Name::Of::Plugin)

This is a function call that returns C<1> if the plugin named
C<Name::Of::Plugin> is loaded, or C<undef> otherwise.

=back

If the end of a configuration file is reached while still inside a
C<if> scope, a warning will be issued, but parsing will restart on
the next file.

For example:

	if (version > 3.000000)
	  header MY_FOO	...
	endif

	loadplugin MyPlugin plugintest.pm

	if plugin (MyPlugin)
	  header MY_PLUGIN_FOO	eval:check_for_foo()
	  score  MY_PLUGIN_FOO	0.1
	endif

=item ifplugin PluginModuleName

An alias for C<if plugin(PluginModuleName)>.

=item else

Used to support conditional interpretation of the configuration
file. Lines between this and a corresponding C<endif> line,
will be ignored unless the conditional expression evaluates as false
(in the perl sense; that is, not defined and 0).

=item require_version n.nnnnnn

Indicates that the entire file, from this line on, requires a certain
version of SpamAssassin to run.  If a different (older or newer) version
of SpamAssassin tries to read the configuration from this file, it will
output a warning instead, and ignore it.

Note: The version used is in the internal SpamAssassin version format which is
C<x.yyyzzz>, where x is major version, y is minor version, and z is maintenance
version.  So 3.0.0 is C<3.000000>, and 3.4.80 is C<3.004080>.

=cut

  push (@cmds, {
    setting => 'require_version',
    code => sub {
    }
  });

=back

=head1 TEMPLATE TAGS

The following C<tags> can be used as placeholders in certain options.
They will be replaced by the corresponding value when they are used.

Some tags can take an argument (in parentheses). The argument is
optional, and the default is shown below.

 _YESNOCAPS_       "YES"/"NO" for is/isn't spam
 _YESNO_           "Yes"/"No" for is/isn't spam
 _SCORE(PAD)_      message score, if PAD is included and is either spaces or
                   zeroes, then pad scores with that many spaces or zeroes
		   (default, none)  ie: _SCORE(0)_ makes 2.4 become 02.4,
		   _SCORE(00)_ is 002.4.  12.3 would be 12.3 and 012.3
		   respectively.
 _REQD_            message threshold
 _VERSION_         version (eg. 3.0.0 or 3.1.0-r26142-foo1)
 _SUBVERSION_      sub-version/code revision date (eg. 2004-01-10)
 _HOSTNAME_        hostname of the machine the mail was processed on
 _REMOTEHOSTNAME_  hostname of the machine the mail was sent from, only
                   available with spamd
 _REMOTEHOSTADDR_  ip address of the machine the mail was sent from, only
                   available with spamd
 _BAYES_           bayes score
 _TOKENSUMMARY_    number of new, neutral, spammy, and hammy tokens found
 _BAYESTC_         number of new tokens found
 _BAYESTCLEARNED_  number of seen tokens found
 _BAYESTCSPAMMY_   number of spammy tokens found
 _BAYESTCHAMMY_    number of hammy tokens found
 _HAMMYTOKENS(N)_  the N most significant hammy tokens (default, 5)
 _SPAMMYTOKENS(N)_ the N most significant spammy tokens (default, 5)
 _DATE_            rfc-2822 date of scan
 _STARS(*)_        one "*" (use any character) for each full score point
                   (note: limited to 50 'stars')
 _RELAYSTRUSTED_   relays used and deemed to be trusted (see the 
                   'X-Spam-Relays-Trusted' pseudo-header)
 _RELAYSUNTRUSTED_ relays used that can not be trusted (see the 
                   'X-Spam-Relays-Untrusted' pseudo-header)
 _RELAYSINTERNAL_  relays used and deemed to be internal (see the 
                   'X-Spam-Relays-Internal' pseudo-header)
 _RELAYSEXTERNAL_  relays used and deemed to be external (see the 
                   'X-Spam-Relays-External' pseudo-header)
 _LASTEXTERNALIP_  IP address of client in the external-to-internal
                   SMTP handover
 _LASTEXTERNALRDNS_ reverse-DNS of client in the external-to-internal
                   SMTP handover
 _LASTEXTERNALHELO_ HELO string used by client in the external-to-internal
                   SMTP handover
 _AUTOLEARN_       autolearn status ("ham", "no", "spam", "disabled",
                   "failed", "unavailable")
 _AUTOLEARNSCORE_  portion of message score used by autolearn
 _TESTS(,)_        tests hit separated by "," (or other separator)
 _TESTSSCORES(,)_  as above, except with scores appended (eg. AWL=-3.0,...)
 _SUBTESTS(,)_     subtests (start with "__") hit separated by ","
                   (or other separator)
 _DCCB_            DCC's "Brand"
 _DCCR_            DCC's results
 _PYZOR_           Pyzor results
 _RBL_             full results for positive RBL queries in DNS URI format
 _LANGUAGES_       possible languages of mail
 _PREVIEW_         content preview
 _REPORT_          terse report of tests hit (for header reports)
 _SUMMARY_         summary of tests hit for standard report (for body reports)
 _CONTACTADDRESS_  contents of the 'report_contact' setting
 _HEADER(NAME)_    includes the value of a message header.  value is the same
                   as is found for header rules (see elsewhere in this doc)

If a tag reference uses the name of a tag which is not in this list or defined
by a loaded plugin, the reference will be left intact and not replaced by any
value.

The C<HAMMYTOKENS> and C<SPAMMYTOKENS> tags have an optional second argument
which specifies a format.  See the B<HAMMYTOKENS/SPAMMYTOKENS TAG FORMAT>
section, below, for details.

=head2 HAMMYTOKENS/SPAMMYTOKENS TAG FORMAT

The C<HAMMYTOKENS> and C<SPAMMYTOKENS> tags have an optional second argument
which specifies a format: C<_SPAMMYTOKENS(N,FMT)_>, C<_HAMMYTOKENS(N,FMT)_>
The following formats are available:

=over 4

=item short

Only the tokens themselves are listed.
I<For example, preference file entry:>

C<add_header all Spammy _SPAMMYTOKENS(2,short)_>

I<Results in message header:>

C<X-Spam-Spammy: remove.php, UD:jpg>

Indicating that the top two spammy tokens found are C<remove.php>
and C<UD:jpg>.  (The token itself follows the last colon, the
text before the colon indicates something about the token.
C<UD> means the token looks like it might be part of a domain name.)

=item compact

The token probability, an abbreviated declassification distance (see
example), and the token are listed.
I<For example, preference file entry:>

C<add_header all Spammy _SPAMMYTOKENS(2,compact)_>

I<Results in message header:>

C<0.989-6--remove.php, 0.988-+--UD:jpg>

Indicating that the probabilities of the top two tokens are 0.989 and
0.988, respectively.  The first token has a declassification distance
of 6, meaning that if the token had appeared in at least 6 more ham
messages it would not be considered spammy.  The C<+> for the second
token indicates a declassification distance greater than 9.

=item long

Probability, declassification distance, number of times seen in a ham
message, number of times seen in a spam message, age and the token are
listed.

I<For example, preference file entry:>

C<add_header all Spammy _SPAMMYTOKENS(2,long)_>

I<Results in message header:>

C<X-Spam-Spammy: 0.989-6--0h-4s--4d--remove.php, 0.988-33--2h-25s--1d--UD:jpg>

In addition to the information provided by the compact option,
the long option shows that the first token appeared in zero
ham messages and four spam messages, and that it was last
seen four days ago.  The second token appeared in two ham messages,
25 spam messages and was last seen one day ago.
(Unlike the C<compact> option, the long option shows declassification
distances that are greater than 9.)

=cut

  return \@cmds;
}

###########################################################################

# settings that were once part of core, but are now in (possibly-optional)
# bundled plugins. these will be warned about, but do not generate a fatal
# error when "spamassassin --lint" is run like a normal syntax error would.

@MIGRATED_SETTINGS = qw{
  ok_languages
};

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my $self = {
    main => shift,
    registered_commands => [],
  }; bless ($self, $class);

  $self->{parser} = Mail::SpamAssassin::Conf::Parser->new($self);
  $self->{parser}->register_commands($self->set_default_commands());

  $self->{errors} = 0;
  $self->{plugins_loaded} = { };

  $self->{tests} = { };
  $self->{test_types} = { };
  $self->{scoreset} = [ {}, {}, {}, {} ];
  $self->{scoreset_current} = 0;
  $self->set_score_set (0);
  $self->{tflags} = { };
  $self->{source_file} = { };

  # keep descriptions in a slow but space-efficient single-string
  # data structure
  tie %{$self->{descriptions}}, 'Mail::SpamAssassin::Util::TieOneStringHash'
    or warn "tie failed";

  # after parsing, tests are refiled into these hashes for each test type.
  # this allows e.g. a full-text test to be rewritten as a body test in
  # the user's user_prefs file.
  $self->{body_tests} = { };
  $self->{uri_tests}  = { };
  $self->{uri_evals}  = { }; # not used/implemented yet
  $self->{head_tests} = { };
  $self->{head_evals} = { };
  $self->{body_evals} = { };
  $self->{full_tests} = { };
  $self->{full_evals} = { };
  $self->{rawbody_tests} = { };
  $self->{rawbody_evals} = { };
  $self->{meta_tests} = { };
  $self->{eval_plugins} = { };
  $self->{duplicate_rules} = { };

  # testing stuff
  $self->{regression_tests} = { };

  $self->{rewrite_header} = { };
  $self->{user_rules_to_compile} = { };
  $self->{user_defined_rules} = { };
  $self->{headers_spam} = { };
  $self->{headers_ham} = { };

  $self->{bayes_ignore_headers} = [ ];
  $self->{bayes_ignore_from} = { };
  $self->{bayes_ignore_to} = { };

  $self->{whitelist_auth} = { };
  $self->{whitelist_from} = { };
  $self->{whitelist_allows_relays} = { };
  $self->{blacklist_from} = { };

  $self->{blacklist_to} = { };
  $self->{whitelist_to} = { };
  $self->{more_spam_to} = { };
  $self->{all_spam_to} = { };

  $self->{trusted_networks} = $self->new_netset();
  $self->{internal_networks} = $self->new_netset();
  $self->{msa_networks} = Mail::SpamAssassin::NetSet->new(); # not new_netset
  $self->{trusted_networks_configured} = 0;
  $self->{internal_networks_configured} = 0;

  # Make sure we add in X-Spam-Checker-Version
  $self->{headers_spam}->{"Checker-Version"} =
                "SpamAssassin _VERSION_ (_SUBVERSION_) on _HOSTNAME_";
  $self->{headers_ham}->{"Checker-Version"} =
                $self->{headers_spam}->{"Checker-Version"};

  # these should potentially be settable by end-users
  # perhaps via plugin?
  $self->{num_check_received} = 9;
  $self->{bayes_expiry_pct} = 0.75;
  $self->{bayes_expiry_period} = 43200;
  $self->{bayes_expiry_max_exponent} = 9;

  $self->{encapsulated_content_description} = 'original message before SpamAssassin';

  $self;
}

sub mtime {
  my $self = shift;
  if (@_) {
    $self->{mtime} = shift;
  }
  return $self->{mtime};
}

###########################################################################

sub parse_scores_only {
  my ($self) = @_;
  $_[0]->{parser}->parse ($_[1], 1);
}

sub parse_rules {
  my ($self) = @_;
  $_[0]->{parser}->parse ($_[1], 0);
}

###########################################################################

sub set_score_set {
  my ($self, $set) = @_;
  $self->{scores} = $self->{scoreset}->[$set];
  $self->{scoreset_current} = $set;
  dbg("config: score set $set chosen.");
}

sub get_score_set {
  my($self) = @_;
  return $self->{scoreset_current};
}

sub get_rule_types {
  my ($self) = @_;
  return @rule_types;
}

sub get_rule_keys {
  my ($self, $test_type, $priority) = @_;

  # special case rbl_evals since they do not have a priority
  if ($test_type eq 'rbl_evals') {
    return keys(%{$self->{$test_type}});
  }

  if (defined($priority)) {
    return keys(%{$self->{$test_type}->{$priority}});
  }
  else {
    my @rules;
    foreach my $pri (keys(%{$self->{priorities}})) {
      push(@rules, keys(%{$self->{$test_type}->{$pri}}));
    }
    return @rules;
  }
}

sub get_rule_value {
  my ($self, $test_type, $rulename, $priority) = @_;

  # special case rbl_evals since they do not have a priority
  if ($test_type eq 'rbl_evals') {
    return keys(%{$self->{$test_type}->{$rulename}});
  }

  if (defined($priority)) {
    return $self->{$test_type}->{$priority}->{$rulename};
  }
  else {
    foreach my $pri (keys(%{$self->{priorities}})) {
      if (exists($self->{$test_type}->{$pri}->{$rulename})) {
        return $self->{$test_type}->{$pri}->{$rulename};
      }
    }
    return undef; # if we get here we didn't find the rule
  }
}

sub delete_rule {
  my ($self, $test_type, $rulename, $priority) = @_;

  # special case rbl_evals since they do not have a priority
  if ($test_type eq 'rbl_evals') {
    return delete($self->{$test_type}->{$rulename});
  }

  if (defined($priority)) {
    return delete($self->{$test_type}->{$priority}->{$rulename});
  }
  else {
    foreach my $pri (keys(%{$self->{priorities}})) {
      if (exists($self->{$test_type}->{$pri}->{$rulename})) {
        return delete($self->{$test_type}->{$pri}->{$rulename});
      }
    }
    return undef; # if we get here we didn't find the rule
  }
}

# trim_rules ($regexp)
#
# Remove all rules that don't match the given regexp (or are sub-rules of
# meta-tests that match the regexp).

sub trim_rules {
  my ($self, $regexp) = @_;

  my @all_rules;
  my $rule_type;

  foreach $rule_type ($self->get_rule_types()) {
    push(@all_rules, $self->get_rule_keys($rule_type));
  }

  my @rules_to_keep = grep(/$regexp/, @all_rules);

  if (@rules_to_keep == 0) {
    die "config: trim_rules: all rules excluded, nothing to test\n";
  }

  my @meta_tests    = grep(/$regexp/, $self->get_rule_keys('meta_tests'));
  foreach my $meta (@meta_tests) {
    push(@rules_to_keep, $self->add_meta_depends($meta))
  }

  my %rules_to_keep_hash = ();

  foreach my $rule (@rules_to_keep) {
    $rules_to_keep_hash{$rule} = 1;
  }

  foreach $rule_type ($self->get_rule_types()) {
    foreach my $rulekey ($self->get_rule_keys($rule_type)) {
      $self->delete_rule($rule_type, $rulekey)
                    if (!$rules_to_keep_hash{$rulekey});
    }
  }
} # trim_rules()

sub add_meta_depends {
  my ($self, $meta) = @_;

  my @rules = ();
  my @tokens = $self->get_rule_value('meta_tests', $meta) =~ m/(\w+)/g;

  @tokens = grep(!/^\d+$/, @tokens);
  # @tokens now only consists of sub-rules

  foreach my $token (@tokens) {
    die "config: meta test $meta depends on itself\n" if $token eq $meta;
    push(@rules, $token);

    # If the sub-rule is a meta-test, recurse
    if ($self->get_rule_value('meta_tests', $token)) {
      push(@rules, $self->add_meta_depends($token));
    }
  } # foreach my $token (@tokens)

  return @rules;
} # add_meta_depends()

sub is_rule_active {
  my ($self, $test_type, $rulename, $priority) = @_;

  # special case rbl_evals since they do not have a priority
  if ($test_type eq 'rbl_evals') {
    return 0 unless ($self->{$test_type}->{$rulename});
    return ($self->{scores}->{$rulename});
  }

  # first determine if the rule is defined
  if (defined($priority)) {
    # we have a specific priority
    return 0 unless ($self->{$test_type}->{$priority}->{$rulename});
  }
  else {
    # no specific priority so we must loop over all currently defined
    # priorities to see if the rule is defined
    my $found_p = 0;
    foreach my $pri (keys %{$self->{priorities}}) {
      if ($self->{$test_type}->{$pri}->{$rulename}) {
        $found_p = 1;
        last;
      }
    }
    return 0 unless ($found_p);
  }

  return ($self->{scores}->{$rulename});
}

###########################################################################

sub add_to_addrlist {
  my $self = shift; $self->{parser}->add_to_addrlist(@_);
}
sub add_to_addrlist_rcvd {
  my $self = shift; $self->{parser}->add_to_addrlist_rcvd(@_);
}
sub remove_from_addrlist {
  my $self = shift; $self->{parser}->remove_from_addrlist(@_);
}
sub remove_from_addrlist_rcvd {
  my $self = shift; $self->{parser}->remove_from_addrlist_rcvd(@_);
}

###########################################################################

sub regression_tests {
  my $self = shift;
  if (@_ == 1) {
    # we specified a symbolic name, return the strings
    my $name = shift;
    my $tests = $self->{regression_tests}->{$name};
    return @$tests;
  }
  else {
    # no name asked for, just return the symbolic names we have tests for
    return keys %{$self->{regression_tests}};
  }
}

###########################################################################

sub finish_parsing {
  my ($self) = shift; $self->{parser}->finish_parsing();
}

###########################################################################

sub get_description_for_rule {
  my ($self, $rule) = @_;
  return $self->{descriptions}->{$rule};
}

###########################################################################

sub maybe_header_only {
  my($self,$rulename) = @_;
  my $type = $self->{test_types}->{$rulename};
  return 0 if (!defined ($type));

  if (($type == $TYPE_HEAD_TESTS) || ($type == $TYPE_HEAD_EVALS)) {
    return 1;

  } elsif ($type == $TYPE_META_TESTS) {
    my $tflags = $self->{tflags}->{$rulename}; $tflags ||= '';
    if ($tflags =~ m/\bnet\b/i) {
      return 0;
    } else {
      return 1;
    }
  }

  return 0;
}

sub maybe_body_only {
  my($self,$rulename) = @_;
  my $type = $self->{test_types}->{$rulename};
  return 0 if (!defined ($type));

  if (($type == $TYPE_BODY_TESTS) || ($type == $TYPE_BODY_EVALS)
        || ($type == $TYPE_URI_TESTS) || ($type == $TYPE_URI_EVALS))
  {
    # some rawbody go off of headers...
    return 1;

  } elsif ($type == $TYPE_META_TESTS) {
    my $tflags = $self->{tflags}->{$rulename}; $tflags ||= '';
    if ($tflags =~ m/\bnet\b/i) {
      return 0;
    } else {
      return 1;
    }
  }

  return 0;
}

###########################################################################

sub load_plugin {
  my ($self, $package, $path, $silent) = @_;
  if ($path) {
    $path = $self->{parser}->fix_path_relative_to_current_file($path);
  }
  $self->{main}->{plugins}->load_plugin ($package, $path, $silent);
}

sub load_plugin_succeeded {
  my ($self, $plugin, $package, $path) = @_;
  $self->{plugins_loaded}->{$package} = 1;
}

sub register_eval_rule {
  my ($self, $pluginobj, $nameofsub) = @_;
  $self->{eval_plugins}->{$nameofsub} = $pluginobj;
}

###########################################################################

sub clone {
  my ($self, $source, $dest) = @_;

  unless (defined $source) {
    $source = $self;
  }
  unless (defined $dest) {
    $dest = $self;
  }

  # keys that should not be copied in ->clone()
  my @NON_COPIED_KEYS = qw(
    main eval_plugins plugins_loaded registered_commands sed_path_cache parser
    scoreset scores
  );

  # keys that should can be copied using a ->clone() method, in ->clone()
  my @CLONABLE_KEYS = qw(
    internal_networks trusted_networks msa_networks 
  );

  my %done = ();

  # special cases.  first, skip anything that cannot be changed
  # by users, and the stuff we take care of here
  foreach my $key (@CLONABLE_KEYS) {
    $dest->{$key} = $source->{$key}->clone();
    $done{$key} = undef;
  }

  foreach my $var (@NON_COPIED_KEYS) {
    $done{$var} = undef;
  }

  # and now, copy over all the rest -- the less complex cases.
  while(my($k,$v) = each %{$source}) {
    next if exists $done{$k};   # we handled it above
    my $i = ref($v);

    # Not a reference, or a scalar?  Just copy the value over.
    if ($i eq '') {
      $dest->{$k} = $v;
    }
    elsif ($i eq 'SCALAR') {
      $dest->{$k} = $$v;
    }
    elsif ($i eq 'ARRAY') {
      @{$dest->{$k}} = @{$v};
    }
    elsif ($i eq 'HASH') {
      %{$dest->{$k}} = %{$v};
    }
    else {
      # throw a warning for debugging -- should never happen in normal usage
      warn "config: dup unknown type $k, $i\n";
    }
  }

  # scoresets
  delete $dest->{scoreset};
  for my $i (0 .. 3) {
    %{$dest->{scoreset}->[$i]} = %{$source->{scoreset}->[$i]};
  }

  # deal with $conf->{scores}, it needs to be a reference into the scoreset
  # hash array dealy.  Do it at the end since scoreset_current isn't set
  # otherwise.
  $dest->{scores} = $dest->{scoreset}->[$dest->{scoreset_current}];

  # ensure we don't copy the path cache from the master
  delete $dest->{sed_path_cache};

  return 1;
}

###########################################################################

sub free_uncompiled_rule_source {
  my ($self) = @_;

  if (!$self->{main}->{keep_config_parsing_metadata} &&
        !$self->{allow_user_rules})
  {
    delete $self->{if_stack};
    delete $self->{source_file};
    delete $self->{meta_dependencies};
  }
}

sub new_netset {
  my ($self) = @_;
  my $set = Mail::SpamAssassin::NetSet->new();
  $set->add_cidr ('127/8');
  return $set;
}

###########################################################################

sub finish {
  my ($self) = @_;
  untie %{$self->{descriptions}};
  %{$self} = ();
}

###########################################################################

sub sa_die { Mail::SpamAssassin::sa_die(@_); }

###########################################################################

1;
__END__

=back

=head1 LOCALI[SZ]ATION

A line starting with the text C<lang xx> will only be interpreted
if the user is in that locale, allowing test descriptions and
templates to be set for that language.

The locales string should specify either both the language and country, e.g.
C<lang pt_BR>, or just the language, e.g. C<lang de>.

=head1 SEE ALSO

C<Mail::SpamAssassin>
C<spamassassin>
C<spamd>

=cut
