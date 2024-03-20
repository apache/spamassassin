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

  https://wiki.apache.org/spamassassin/ImportantInitialConfigItems

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

Test names ("SYMBOLIC_TEST_NAME") can only contain alphanumerics/underscores,
can not start with digit, and must be less than 128 characters.

=head1 USER PREFERENCES

The following options can be used in both site-wide (C<local.cf>) and
user-specific (C<user_prefs>) configuration files to customize how
SpamAssassin handles incoming email messages.

=cut

package Mail::SpamAssassin::Conf;

use strict;
use warnings;
# use bytes;
use re 'taint';

use Mail::SpamAssassin::NetSet;
use Mail::SpamAssassin::Constants qw(:sa :ip);
use Mail::SpamAssassin::Conf::Parser;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(untaint_var idn_to_ascii compile_regexp);
use File::Spec;

our @ISA = qw();

our $COLLECT_REGRESSION_TESTS; # Used only for unit tests.

# odd => eval test.  Not constants so they can be shared with Parser
# TODO: move to Constants.pm?
our $TYPE_HEAD_TESTS    = 0x0008;
our $TYPE_HEAD_EVALS    = 0x0009;
our $TYPE_BODY_TESTS    = 0x000a;
our $TYPE_BODY_EVALS    = 0x000b;
our $TYPE_FULL_TESTS    = 0x000c;
our $TYPE_FULL_EVALS    = 0x000d;
our $TYPE_RAWBODY_TESTS = 0x000e;
our $TYPE_RAWBODY_EVALS = 0x000f;
our $TYPE_URI_TESTS     = 0x0010;
our $TYPE_URI_EVALS     = 0x0011;
our $TYPE_META_TESTS    = 0x0012;
our $TYPE_RBL_EVALS     = 0x0013;
our $TYPE_EMPTY_TESTS   = 0x0014;

my @rule_types = ("body_tests", "uri_tests", "uri_evals",
                  "head_tests", "head_evals", "body_evals", "full_tests",
                  "full_evals", "rawbody_tests", "rawbody_evals",
		  "rbl_evals", "meta_tests");

# Map internal ruletype to descriptive ruletype string
our %TYPE_AS_STRING = (
  $TYPE_HEAD_TESTS => 'header',
  $TYPE_HEAD_EVALS => 'header',
  $TYPE_BODY_TESTS => 'body',
  $TYPE_BODY_EVALS => 'body',
  $TYPE_FULL_TESTS => 'full',
  $TYPE_FULL_EVALS => 'full',
  $TYPE_RAWBODY_TESTS => 'rawbody',
  $TYPE_RAWBODY_EVALS => 'rawbody',
  $TYPE_URI_TESTS => 'uri',
  $TYPE_URI_EVALS => 'uri',
  $TYPE_META_TESTS => 'meta',
  $TYPE_RBL_EVALS => 'header',
  $TYPE_EMPTY_TESTS => 'empty',
);

#Removed $VERSION per BUG 6422
#$VERSION = 'bogus';     # avoid CPAN.pm picking up version strings later

# these are variables instead of constants so that other classes can
# access them; if they're constants, they'd have to go in Constants.pm
# TODO: move to Constants.pm?
our $CONF_TYPE_STRING           =  1;
our $CONF_TYPE_BOOL             =  2;
our $CONF_TYPE_NUMERIC          =  3;
our $CONF_TYPE_HASH_KEY_VALUE   =  4;
our $CONF_TYPE_ADDRLIST         =  5;
our $CONF_TYPE_TEMPLATE         =  6;
our $CONF_TYPE_NOARGS           =  7;
our $CONF_TYPE_STRINGLIST       =  8;
our $CONF_TYPE_IPADDRLIST       =  9;
our $CONF_TYPE_DURATION         = 10;
our $MISSING_REQUIRED_VALUE     = '-99999999999999';  # string expected by parser
our $INVALID_VALUE              = '-99999999999998';
our $INVALID_HEADER_FIELD_NAME  = '-99999999999997';

# set to "1" by the test suite code, to record regression tests
# $Mail::SpamAssassin::Conf::COLLECT_REGRESSION_TESTS = 1;

# search for "sub new {" to find the start of the code
###########################################################################

sub set_default_commands {
  my($self) = @_;

  # see "perldoc Mail::SpamAssassin::Conf::Parser" for details on this fmt.
  # push each config item like this, to avoid a POD bug; it can't just accept
  # ( { ... }, { ... }, { ...} ) otherwise POD parsing dies.
  my @cmds;

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
    aliases => ['required_hits'],       # backward compatible
    default => 5,
    type => $CONF_TYPE_NUMERIC,
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

If no score is given for a test by the end of the configuration,
a default score is assigned: a score of 1.0 is used for all tests,
except those whose names begin with 'T_' (this is used to indicate a
rule in testing) which receive 0.01.

Note that test names which begin with '__' are indirect rules used
to compose meta-match rules and can also act as prerequisites to
other rules.  They are not scored or listed in the 'tests hit'
reports, but assigning a score of 0 to an indirect rule will disable
it from running.

=cut

  push (@cmds, {
    setting => 'score',
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
        local ($1);
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

=back

=head2 WELCOMELIST AND BLOCKLIST OPTIONS

=over 4

=item welcomelist_from user@example.com

Previously whitelist_from which will work interchangeably until 4.1.

Used to welcomelist sender addresses which send mail that is often tagged
(incorrectly) as spam.

Use of this setting is not recommended, since it blindly trusts the message,
which is routinely and easily forged by spammers and phish senders. The
recommended solution is to instead use C<welcomelist_auth> or other authenticated
welcomelisting methods, or C<welcomelist_from_rcvd>.

Welcomelist and blocklist addresses are now file-glob-style patterns, so
C<friend@somewhere.com>, C<*@isp.com>, or C<*.domain.net> will all work.
Specifically, C<*> and C<?> are allowed, but all other metacharacters
are not. Regular expressions are not used for security reasons.
Matching is case-insensitive.

Multiple addresses per line, separated by spaces, is OK.  Multiple
C<welcomelist_from> lines are also OK.

The headers checked for welcomelist addresses are as follows: if C<Resent-From>
is set, use that; otherwise check all addresses taken from the following
set of headers:

	Envelope-Sender
	Resent-Sender
	X-Envelope-From
	From

In addition, the "envelope sender" data, taken from the SMTP envelope data
where this is available, is looked up.  See C<envelope_sender_header>.

e.g.

  welcomelist_from joe@example.com fred@example.com
  welcomelist_from *@example.com

=cut

  push (@cmds, {
    setting => 'welcomelist_from',
    aliases => ['whitelist_from'], # backward compatible - to be removed for 4.1
    type => $CONF_TYPE_ADDRLIST,
  });

=item unwelcomelist_from user@example.com

Previously unwelcomelist_from which will work interchangeably until 4.1.

Used to remove a default welcomelist_from entry, so for example a distribution
welcomelist_from can be overridden in a local.cf file, or an individual user can
override a welcomelist_from entry in their own C<user_prefs> file.
The specified email address has to match exactly (although case-insensitively)
the address previously used in a welcomelist_from line, which implies that a
wildcard only matches literally the same wildcard (not 'any' address).

e.g.

  unwelcomelist_from joe@example.com fred@example.com
  unwelcomelist_from *@example.com

=cut

  push (@cmds, {
    command => 'unwelcomelist_from',
    aliases => ['unwhitelist_from'], # backward compatible - to be removed for 4.1
    setting => 'welcomelist_from',
    type => $CONF_TYPE_ADDRLIST,
    code => \&Mail::SpamAssassin::Conf::Parser::remove_addrlist_value
  });

=item welcomelist_from_rcvd addr@lists.sourceforge.net sourceforge.net

Previously whitelist_from_rcvd which will work interchangeably until 4.1.

Works similarly to welcomelist_from, except that in addition to matching
a sender address, a relay's rDNS name or its IP address must match too
for the welcomelisting rule to fire. The first parameter is a sender's e-mail
address to welcomelist, and the second is a string to match the relay's rDNS,
or its IP address. Matching is case-insensitive.

This second parameter is matched against a TCP-info information field as
provided in a FROM clause of a trace information (i.e. in a Received header
field, see RFC 5321). Only the Received header fields inserted by trusted
hosts are considered. This parameter can either be a full hostname, or a
domain component of that hostname, or an IP address (optionally followed
by a slash and a prefix length) in square brackets. The address prefix
(mask) length with a slash may stand within brackets along with an address,
or may follow the bracketed address. Reverse DNS lookup is done by an MTA,
not by SpamAssassin.

For backward compatibility as an alternative to a CIDR notation, an IPv4
address in brackets may be truncated on classful boundaries to cover whole
subnets, e.g. C<[10.1.2.3]>, C<[10.1.2]>, C<[10.1]>, C<[10]>.

In other words, if the host that connected to your MX had an IP address
192.0.2.123 that mapped to 'sendinghost.example.org', you should specify
C<sendinghost.example.org>, or C<example.org>, or C<[192.0.2.123]>, or
C<[192.0.2.0/24]>, or C<[192.0.2]> here.

Note that this requires that C<internal_networks> be correct.  For simple
cases, it will be, but for a complex network you may get better results
by setting that parameter.

It also requires that your mail exchangers be configured to perform DNS
reverse lookups on the connecting host's IP address, and to record the
result in the generated Received header field according to RFC 5321.

e.g.

  welcomelist_from_rcvd joe@example.com  example.com
  welcomelist_from_rcvd *@*              mail.example.org
  welcomelist_from_rcvd *@axkit.org      [192.0.2.123]
  welcomelist_from_rcvd *@axkit.org      [192.0.2.0/24]
  welcomelist_from_rcvd *@axkit.org      [192.0.2.0]/24
  welcomelist_from_rcvd *@axkit.org      [2001:db8:1234::/48]
  welcomelist_from_rcvd *@axkit.org      [2001:db8:1234::]/48

=item def_welcomelist_from_rcvd addr@lists.sourceforge.net sourceforge.net

Previously def_whitelist_from_rcvd which will work interchangeably until 4.1.

Same as C<welcomelist_from_rcvd>, but used for the default welcomelist entries
in the SpamAssassin distribution.  The welcomelist score is lower, because
these are often targets for spammer spoofing.

=cut

  push (@cmds, {
    setting => 'welcomelist_from_rcvd',
    aliases => ['whitelist_from_rcvd'], # backward compatible - to be removed for 4.1
    type => $CONF_TYPE_ADDRLIST,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
	return $MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^\S+\s+\S+$/) {
	return $INVALID_VALUE;
      }
      $self->{parser}->add_to_addrlist_rcvd ('welcomelist_from_rcvd',
                                        split(/\s+/, $value));
    }
  });

  push (@cmds, {
    setting => 'def_welcomelist_from_rcvd',
    aliases => ['def_whitelist_from_rcvd'], # backward compatible - to be removed for 4.1
    type => $CONF_TYPE_ADDRLIST,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
	return $MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^\S+\s+\S+$/) {
	return $INVALID_VALUE;
      }
      $self->{parser}->add_to_addrlist_rcvd ('def_welcomelist_from_rcvd',
                                        split(/\s+/, $value));
    }
  });

=item welcomelist_allows_relays user@example.com

Previously whitelist_allows_relays which will work interchangeably until 4.1.

Specify addresses which are in C<welcomelist_from_rcvd> that sometimes
send through a mail relay other than the listed ones. By default mail
with a From address that is in C<welcomelist_from_rcvd> that does not match
the relay will trigger a forgery rule. Including the address in
C<welcomelist_allows_relay> prevents that.

Welcomelist and blocklist addresses are now file-glob-style patterns, so
C<friend@somewhere.com>, C<*@isp.com>, or C<*.domain.net> will all work.
Specifically, C<*> and C<?> are allowed, but all other metacharacters
are not. Regular expressions are not used for security reasons.
Matching is case-insensitive.

Multiple addresses per line, separated by spaces, is OK.  Multiple
C<welcomelist_allows_relays> lines are also OK.

The specified email address does not have to match exactly the address
previously used in a welcomelist_from_rcvd line as it is compared to the
address in the header.

e.g.

  welcomelist_allows_relays joe@example.com fred@example.com
  welcomelist_allows_relays *@example.com

=cut

  push (@cmds, {
    setting => 'welcomelist_allows_relays',
    aliases => ['whitelist_allows_relays'], # backward compatible - to be removed for 4.1
    type => $CONF_TYPE_ADDRLIST,
  });

=item unwelcomelist_from_rcvd user@example.com

Previously unwhitelist_from_rcvd which will work interchangeably until 4.1.

Used to remove a default welcomelist_from_rcvd or def_welcomelist_from_rcvd
entry, so for example a distribution welcomelist_from_rcvd can be overridden
in a local.cf file, or an individual user can override a welcomelist_from_rcvd
entry in their own C<user_prefs> file.

The specified email address has to match exactly the address previously
used in a welcomelist_from_rcvd line.

e.g.

  unwelcomelist_from_rcvd joe@example.com fred@example.com
  unwelcomelist_from_rcvd *@axkit.org

=cut

  push (@cmds, {
    setting => 'unwelcomelist_from_rcvd',
    aliases => ['unwhitelist_from_rcvd'], # backward compatible - to be removed for 4.1
    type => $CONF_TYPE_ADDRLIST,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
	return $MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^(?:\S+(?:\s+\S+)*)$/) {
	return $INVALID_VALUE;
      }
      $self->{parser}->remove_from_addrlist_rcvd('welcomelist_from_rcvd',
                                        split (/\s+/, $value));
      $self->{parser}->remove_from_addrlist_rcvd('def_welcomelist_from_rcvd',
                                        split (/\s+/, $value));
    }
  });

=item blocklist_from user@example.com

Used to specify addresses which send mail that is often tagged (incorrectly) as
non-spam, but which the user doesn't want.  Same format as C<welcomelist_from>.

=cut

  push (@cmds, {
    setting => 'blocklist_from',
    aliases => ['blacklist_from'], # backward compatible - to be removed for 4.1
    type => $CONF_TYPE_ADDRLIST,
  });

=item unblocklist_from user@example.com

Previously unblacklist_from which will work interchangeably until 4.1.

Used to remove a default blocklist_from entry, so for example a
distribution blocklist_from can be overridden in a local.cf file, or
an individual user can override a blocklist_from entry in their own
C<user_prefs> file. The specified email address has to match exactly
the address previously used in a blocklist_from line.


e.g.

  unblocklist_from joe@example.com fred@example.com
  unblocklist_from *@spammer.com

=cut


  push (@cmds, {
    command => 'unblocklist_from',
    aliases => ['unblacklist_from'], # backward compatible - to be removed for 4.1
    setting => 'blocklist_from',
    type => $CONF_TYPE_ADDRLIST,
    code => \&Mail::SpamAssassin::Conf::Parser::remove_addrlist_value
  });


=item welcomelist_to user@example.com

Previously whitelist_to which will work interchangeably until 4.1.

If the given address appears as a recipient in the message headers
(Resent-To, To, Cc, obvious envelope recipient, etc.) the mail will
be listed as allowed.  Useful if you're deploying SpamAssassin system-wide,
and don't want some users to have their mail filtered.  Same format
as C<welcomelist_from>.

There are three levels of To-welcomelisting, C<welcomelist_to>, C<more_spam_to>
and C<all_spam_to>.  Users in the first level may still get some spammish
mails blocked, but users in C<all_spam_to> should never get mail blocked.

The headers checked for welcomelist addresses are as follows: if C<Resent-To> or
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

=item more_spam_to user@example.com

See above.

=item all_spam_to user@example.com

See above.

=cut

  push (@cmds, {
    setting => 'welcomelist_to',
    aliases => ['whitelist_to'], # backward compatible - to be removed for 4.1
    type => $CONF_TYPE_ADDRLIST,
  });
  push (@cmds, {
    setting => 'more_spam_to',
    type => $CONF_TYPE_ADDRLIST,
  });
  push (@cmds, {
    setting => 'all_spam_to',
    type => $CONF_TYPE_ADDRLIST,
  });

=item blocklist_to user@example.com

Previously blacklist_auth which will work interchangeably until 4.1.

If the given address appears as a recipient in the message headers
(Resent-To, To, Cc, obvious envelope recipient, etc.) the mail will
be blocklisted.  Same format as C<blocklist_from>.

=cut

  push (@cmds, {
    setting => 'blocklist_to',
    aliases => ['blacklist_to'], # backward compatible - to be removed for 4.1
    type => $CONF_TYPE_ADDRLIST,
  });

=item welcomelist_auth user@example.com

Previously whitelist_auth which will work interchangeably until 4.1.

Used to specify addresses which send mail that is often tagged (incorrectly) as
spam.  This is different from C<welcomelist_from> and C<welcomelist_from_rcvd> in
that it first verifies that the message was sent by an authorized sender for
the address, before welcomelisting.

Authorization is performed using one of the installed sender-authorization
schemes: SPF (using C<Mail::SpamAssassin::Plugin::SPF>), or DKIM (using
C<Mail::SpamAssassin::Plugin::DKIM>).  Note that those plugins must be active,
and working, for this to operate.

Using C<welcomelist_auth> is roughly equivalent to specifying duplicate
C<welcomelist_from_spf>, C<welcomelist_from_dk>, and C<welcomelist_from_dkim> lines
for each of the addresses specified.

e.g.

  welcomelist_auth joe@example.com fred@example.com
  welcomelist_auth *@example.com

=item def_welcomelist_auth user@example.com

Previously def_whitelist_auth which will work interchangeably until 4.1.

Same as C<welcomelist_auth>, but used for the default welcomelist entries
in the SpamAssassin distribution.  The welcomelist score is lower, because
these are often targets for spammer spoofing.

=cut

  push (@cmds, {
    setting => 'welcomelist_auth',
    aliases => ['whitelist_auth'], # backward compatible - to be removed for 4.1
    type => $CONF_TYPE_ADDRLIST,
  });

  push (@cmds, {
    setting => 'def_welcomelist_auth',
    aliases => ['def_whitelist_auth'], # backward compatible - to be removed for 4.1
    type => $CONF_TYPE_ADDRLIST,
  });

=item unwelcomelist_auth user@example.com

Previously unwhitelist_auth which will work interchangeably until 4.1.

Used to remove a C<welcomelist_auth> or C<def_welcomelist_auth> entry. The
specified email address has to match exactly the address previously used.

e.g.

  unwelcomelist_auth joe@example.com fred@example.com
  unwelcomelist_auth *@example.com

=cut

  push (@cmds, {
    setting => 'unwelcomelist_auth',
    aliases => ['unwhitelist_auth'], # backward compatible - to be removed for 4.1
    type => $CONF_TYPE_ADDRLIST,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
        return $MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^(?:\S+(?:\s+\S+)*)$/) {
        return $INVALID_VALUE;
      }
      $self->{parser}->remove_from_addrlist('welcomelist_auth',
                                        split (/\s+/, $value));
      $self->{parser}->remove_from_addrlist('def_welcomelist_auth',
                                        split (/\s+/, $value));
    }
  });


=item enlist_uri_host (listname) host ...

Adds one or more host names or domain names to a named list of URI domains.
The named list can then be consulted through a check_uri_host_listed()
eval rule implemented by the WLBLEval plugin, which takes the list name as
an argument. Parenthesis around a list name are literal - a required syntax.

Host names may optionally be prefixed by an exclamation mark '!', which
produces false as a result if this entry matches. This makes it easier
to exclude some subdomains when their superdomain is listed, for example:

  enlist_uri_host (MYLIST) !sub1.example.com !sub2.example.com example.com

No wildcards are supported, but subdomains do match implicitly. Lists
are independent. Search for each named list starts by looking up the
full hostname first, then leading fields are progressively stripped off
(e.g.: sub.example.com, example.com, com) until a match is found or we run
out of fields. The first matching entry (the most specific) determines if a
lookup yielded a true (no '!' prefix) or a false (with a '!' prefix) result.

If an URL found in a message contains an IP address in place of a host name,
the given list must specify the exact same IP address (instead of a host name)
in order to match.

Use the delist_uri_host directive to neutralize previous enlist_uri_host
settings.

Enlisting to lists named 'BLOCK' and 'WELCOME' have their shorthand directives
blocklist_uri_host and welcomelist_uri_host and corresponding default rules,
but the names 'BLOCK' and 'WELCOME' are otherwise not special or reserved.

=cut

  push (@cmds, {
    command => 'enlist_uri_host',
    setting => 'uri_host_lists',
    type => $CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my($conf, $key, $value, $line) = @_;
      local($1,$2);
      if ($value !~ /^ \( (.+?) \) \s+ (.+) \z/sx) {
        return $MISSING_REQUIRED_VALUE;
      }
      my $listname = $1;  # corresponds to arg in check_uri_host_in_wblist()
      # note: must not factor out dereferencing, as otherwise
      # subhashes would spring up in a copy and be lost
      foreach my $host ( split(/\s+/, lc $2) ) {
        my $v = $host =~ s/^!// ? 0 : 1;
        $conf->{uri_host_lists}{$listname}{$host} = $v;
      }
    }
  });

=item delist_uri_host [ (listname) ] host ...

Removes one or more specified host names from a named list of URI domains.
Removing an unlisted name is ignored (is not an error). Listname is optional,
if specified then just the named list is affected, otherwise hosts are
removed from all URI host lists created so far. Parenthesis around a list
name are a required syntax.

Note that directives in configuration files are processed in sequence,
the delist_uri_host only applies to previously listed entries and has
no effect on enlisted entries in yet-to-be-processed directives.

For convenience (similarity to the enlist_uri_host directive) hostnames
may be prefixed by a an exclamation mark, which is stripped off from each
name and has no meaning here.

=cut

  push (@cmds, {
    command => 'delist_uri_host',
    setting => 'uri_host_lists',
    type => $CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my($conf, $key, $value, $line) = @_;
      local($1,$2);
      if ($value !~ /^ (?: \( (.+?) \) \s+ )? (.+) \z/sx) {
        return $MISSING_REQUIRED_VALUE;
      }
      my @listnames = defined $1 ? $1 : keys %{$conf->{uri_host_lists}};
      my @args = split(/\s+/, lc $2);
      foreach my $listname (@listnames) {
        foreach my $host (@args) {
          my $v = $host =~ s/^!// ? 0 : 1;
          delete $conf->{uri_host_lists}{$listname}{$host};
        }
      }
    }
  });

=item enlist_addrlist (listname) user@example.com

Adds one or more addresses to a named list of addresses.
The named list can then be consulted through a check_from_in_list() or a 
check_to_in_list() eval rule implemented by the WLBLEval plugin, which takes 
the list name as an argument. Parenthesis around a list name are literal - a 
required syntax.

Listed addresses are file-glob-style patterns, so C<friend@somewhere.com>, 
C<*@isp.com>, or C<*.domain.net> will all work.
Specifically, C<*> and C<?> are allowed, but all other metacharacters
are not. Regular expressions are not used for security reasons.
Matching is case-insensitive.

Multiple addresses per line, separated by spaces, is OK.  Multiple
C<enlist_addrlist> lines are also OK.

Enlisting an address to the list named blocklist_to is synonymous to using
the directive blocklist_to.

Enlisting an address to the list named blocklist_from is synonymous to using
the directive blocklist_from.

Enlisting an address to the list named welcomelist_to is synonymous to using
the directive welcomelist_to.

Enlisting an address to the list named welcomelist_from is synonymous to
using the directive welcomelist_from.

e.g.

  enlist_addrlist (PAYPAL_ADDRESS) service@paypal.com
  enlist_addrlist (PAYPAL_ADDRESS) *@paypal.co.uk

=cut

  push (@cmds, {
    setting => 'enlist_addrlist',
    type => $CONF_TYPE_ADDRLIST,
    code => sub {
      my($conf, $key, $value, $line) = @_;
      local($1,$2);
      if ($value !~ /^ \( (.+?) \) \s+ (.+) \z/sx) {
        return $MISSING_REQUIRED_VALUE;
      }
      my $listname = $1;  # corresponds to arg in check_uri_host_in_wblist()
      # note: must not factor out dereferencing, as otherwise
      # subhashes would spring up in a copy and be lost
      $conf->{parser}->add_to_addrlist ($listname, split(/\s+/, $2));
    }
  });

=item blocklist_uri_host host-or-domain ...

Previously blacklist_uri_host which will work interchangeably until 4.1.

Is a shorthand for a directive:  enlist_uri_host (BLOCK) host ...

Please see directives enlist_uri_host and delist_uri_host for details.

=cut

  push (@cmds, {
    command => 'blocklist_uri_host',
    aliases => ['blacklist_uri_host'], # backward compatible - to be removed for 4.1
    setting => 'uri_host_lists',
    type => $CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my($conf, $key, $value, $line) = @_;
      foreach my $host ( split(/\s+/, lc $value) ) {
        my $v = $host =~ s/^!// ? 0 : 1;
        $conf->{uri_host_lists}{'BLOCK'}{$host} = $v;
      }
    }
  });

=item welcomelist_uri_host host-or-domain ...

Previously whitelist_uri_host which will work interchangeably until 4.1.

Is a shorthand for a directive:  enlist_uri_host (WELCOME) host ...

Please see directives enlist_uri_host and delist_uri_host for details.

=cut

  push (@cmds, {
    command => 'welcomelist_uri_host',
    aliases => ['whitelist_uri_host'], # backward compatible - to be removed for 4.1
    setting => 'uri_host_lists',
    type => $CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my($conf, $key, $value, $line) = @_;
      foreach my $host ( split(/\s+/, lc $value) ) {
        my $v = $host =~ s/^!// ? 0 : 1;
        $conf->{uri_host_lists}{'WELCOME'}{$host} = $v;
      }
    }
  });

=back

=head2 BASIC MESSAGE TAGGING OPTIONS

=over 4

=item rewrite_header { subject | from | to } STRING

By default, suspected spam messages will not have the C<Subject>,
C<From> or C<To> lines tagged to indicate spam. By setting this option,
the header will be tagged with C<STRING> to indicate that a message is
spam. For the From or To headers, this will take the form of an RFC 2822
comment following the address in parentheses. For the Subject header,
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
    type => $CONF_TYPE_HASH_KEY_VALUE,
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

=item subjprefix

Add a prefix in emails Subject if a rule is matched.
To enable this option "rewrite_header Subject" config
option must be enabled as well.

The check C<if can(Mail::SpamAssassin::Conf::feature_subjprefix)>
should be used to silence warnings in previous
SpamAssassin versions.

To be able to use this feature a C<add_header all Subjprefix _SUBJPREFIX_>
configuration line could be needed when the glue between the MTA and SpamAssassin
rewrites the email content.

Here is an example on how to use this feature:

	rewrite_header Subject *****SPAM*****
	add_header all Subjprefix _SUBJPREFIX_
	body     OLEMACRO_MALICE eval:check_olemacro_malice()
	describe OLEMACRO_MALICE Dangerous Office Macro
	score    OLEMACRO_MALICE 5.0
	if can(Mail::SpamAssassin::Conf::feature_subjprefix)
	  subjprefix OLEMACRO_MALICE [VIRUS]
	endif

=cut

  push (@cmds, {
    command => 'subjprefix',
    setting => 'subjprefix',
    is_frequent => 1,
    type => $CONF_TYPE_HASH_KEY_VALUE,
  });

=item add_header { spam | ham | all } header_name string

Customized headers can be added to the specified type of messages (spam,
ham, or "all" to add to either).  All headers begin with C<X-Spam->
(so a C<header_name> Foo will generate a header called X-Spam-Foo).
header_name is restricted to the character set [A-Za-z0-9_-].

The order of C<add_header> configuration options is preserved, inserted
headers will follow this order of declarations. When combining C<add_header>
with C<clear_headers> and C<remove_header>, keep in mind that C<add_header>
appends a new header to the current list, after first removing any existing
header fields of the same name. Note also that C<add_header>, C<clear_headers>
and C<remove_header> may appear in multiple .cf files, which are interpreted
in alphabetic order.

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

See also C<clear_headers> and C<remove_header> for removing headers.

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
      local ($1,$2,$3);
      if ($value !~ /^(ham|spam|all)\s+([A-Za-z0-9_-]+)\s+(.*?)\s*$/) {
        return $INVALID_VALUE;
      }

      my ($type, $name, $hline) = ($1, $2, $3);
      if ($hline =~ /^"(.*)"$/) {
        $hline = $1;
      }
      my @line = split(
                  /\\\\/,     # split at double backslashes,
                  $hline."\n" # newline needed to make trailing backslashes work
                );
      foreach (@line) {
        s/\\t/\t/g; # expand tabs
        s/\\n/\n/g; # expand newlines
        s/\\.//g;   # purge all other escapes
      };
      $hline = join("\\", @line);
      chop($hline);  # remove dummy newline again
      if (($type eq "ham") || ($type eq "all")) {
        $self->{headers_ham} =
          [ grep { lc($_->[0]) ne lc($name) } @{$self->{headers_ham}} ];
        push(@{$self->{headers_ham}}, [$name, $hline]);
      }
      if (($type eq "spam") || ($type eq "all")) {
        $self->{headers_spam} =
          [ grep { lc($_->[0]) ne lc($name) } @{$self->{headers_spam}} ];
        push(@{$self->{headers_spam}}, [$name, $hline]);
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
      local ($1,$2);
      if ($value !~ /^(ham|spam|all)\s+([A-Za-z0-9_-]+)\s*$/) {
        return $INVALID_VALUE;
      }

      my ($type, $name) = ($1, $2);
      return if ( $name eq "Checker-Version" );

      $name = lc($name);
      if (($type eq "ham") || ($type eq "all")) {
        $self->{headers_ham} =
          [ grep { lc($_->[0]) ne $name } @{$self->{headers_ham}} ];
      }
      if (($type eq "spam") || ($type eq "all")) {
        $self->{headers_spam} =
          [ grep { lc($_->[0]) ne $name } @{$self->{headers_spam}} ];
      }
    }
  });

=item clear_headers

Clear the list of headers to be added to messages.  You may use this
before any B<add_header> options to prevent the default headers from being
added to the message.

C<add_header>, C<clear_headers> and C<remove_header> may appear in multiple
.cf files, which are interpreted in alphabetic order, so C<clear_headers>
in a later file will remove all added headers from previously interpreted
configuration files, which may or may not be desired.

Note that B<X-Spam-Checker-Version> is not removable because the version
information is needed by mail administrators and developers to debug
problems.  Without at least one header, it might not even be possible to
determine that SpamAssassin is running.

=cut

  push (@cmds, {
    setting => 'clear_headers',
    type => $CONF_TYPE_NOARGS,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (!defined $value || $value eq '') {
        return $INVALID_VALUE;
      }
      my @h = grep { lc($_->[0]) eq "checker-version" }
                   @{$self->{headers_ham}};
      $self->{headers_ham}  = !@h ? [] : [ $h[0] ];
      $self->{headers_spam} = !@h ? [] : [ $h[0] ];
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
    type => $CONF_TYPE_NUMERIC,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $MISSING_REQUIRED_VALUE;
      }
      elsif ($value !~ /^[012]$/) {
        return $INVALID_VALUE;
      }

      $self->{report_safe} = $value+0;
      if (! $self->{report_safe} &&
          ! (grep { lc($_->[0]) eq "report" } @{$self->{headers_spam}}) ) {
        push(@{$self->{headers_spam}}, ["Report", "_REPORT_"]);
      }
    }
  });

=item report_wrap_width (default: 75) 

This option sets the wrap width for description lines in the X-Spam-Report
header, not accounting for tab width. 

=cut

  push (@cmds, {
    setting => 'report_wrap_width',
    default => '75',
    type => $CONF_TYPE_NUMERIC,
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
    type => $CONF_TYPE_STRING,
  });

=item normalize_charset ( 0 | 1 )        (default: 1)

Whether to decode non- UTF-8 and non-ASCII textual parts and recode them
to UTF-8 before the text is given over to rules processing. The character
set used for attempted decoding is primarily based on a declared character
set in a Content-Type header, but if the decoding attempt fails a module
Encode::Detect::Detector is consulted (if available) to provide a guess
based on the actual text, and decoding is re-attempted. Even if the option
is enabled no unnecessary decoding and re-encoding work is done when
possible (like with an all-ASCII text with a US-ASCII or extended ASCII
character set declaration, e.g. UTF-8 or ISO-8859-nn or Windows-nnnn).

Unicode support in old versions of perl or in a core module Encode is likely
to be buggy in places, so if the normalize_charset function is enabled
it is advised to stick to more recent versions of perl (preferably 5.12
or later). The module Encode::Detect::Detector is optional, when necessary
it will be used if it is available.

=cut

  push (@cmds, {
    setting => 'normalize_charset',
    default => 1,
    type => $CONF_TYPE_BOOL,
    code => sub {
	my ($self, $key, $value, $line) = @_;
	unless (defined $value && $value !~ /^$/) {
	    return $MISSING_REQUIRED_VALUE;
	}
        if    (lc $value eq 'yes' || $value eq '1') { $value = 1 }
        elsif (lc $value eq 'no'  || $value eq '0') { $value = 0 }
        else { return $INVALID_VALUE }

	$self->{normalize_charset} = $value;

	unless ($] > 5.008004) {
	    $self->{parser}->lint_warn("config: normalize_charset requires Perl 5.8.5 or later");
	    $self->{normalize_charset} = 0;
	    return $INVALID_VALUE;
	}
	require HTML::Parser;
        #changed to eval to use VERSION so that this version was not incorrectly parsed for CPAN
	unless ( eval { HTML::Parser->VERSION(3.46) } ) {
	    $self->{parser}->lint_warn("config: normalize_charset requires HTML::Parser 3.46 or later");
	    $self->{normalize_charset} = 0;
	    return $INVALID_VALUE;
	}
    }
  });

=back

=head2 NETWORK TEST OPTIONS

=over 4

=item trusted_networks IPaddress[/masklen] ...   (default: none)

What networks or hosts are 'trusted' in your setup.  B<Trusted> in this case
means that relay hosts on these networks are considered to not be potentially
operated by spammers, open relays, or open proxies.  A trusted host could
conceivably relay spam, but will not originate it, and will not forge header
data. DNS blocklist checks will never query for hosts on these networks. 

See C<https://wiki.apache.org/spamassassin/TrustPath> for more information.

MXes for your domain(s) and internal relays should B<also> be specified using
the C<internal_networks> setting. When there are 'trusted' hosts that
are not MXes or internal relays for your domain(s) they should B<only> be
specified in C<trusted_networks>.

The C<IPaddress> can be an IPv4 address (in a dot-quad form), or an IPv6
address optionally enclosed in square brackets. Scoped link-local IPv6
addresses are syntactically recognized but the interface scope is currently
ignored (e.g. [fe80::1234%eth0] ) and should be avoided.

If a C</masklen> is specified, it is considered a CIDR-style 'netmask' length,
specified in bits.  If it is not specified, but less than 4 octets of an IPv4
address are specified with a trailing dot, an implied netmask length covers
all addresses in remaining octets (i.e. implied masklen is /8 or /16 or /24).
If masklen is not specified, and there is not trailing dot, then just a single
IP address specified is used, as if the masklen were C</32> with an IPv4
address, or C</128> in case of an IPv6 address.

If module Net::CIDR::Lite is installed, it's also possible to use dash
separated IP range format (e.g. 192.168.1.1-192.168.255.255).

If a network or host address is prefaced by a C<!> the matching network or
host will be excluded from the list even if a less specific (shorter netmask
length) subnet is later specified in the list. This allows a subset of
a wider network to be exempt. In case of specifying overlapping subnets,
specify more specific subnets first (tighter matching, i.e. with a longer
netmask length), followed by less specific (shorter netmask length) subnets
to get predictable results regardless of the search algorithm used - when
Net::Patricia module is installed the search finds the tightest matching
entry in the list, while a sequential search as used in absence of the
module Net::Patricia will find the first matching entry in the list.

Note: 127.0.0.0/8 and ::1 are always included in trusted_networks, regardless
of your config.

Examples:

   trusted_networks 192.168.0.0/16        # all in 192.168.*.*
   trusted_networks 192.168.              # all in 192.168.*.*
   trusted_networks 212.17.35.15          # just that host
   trusted_networks !10.0.1.5 10.0.1/24   # all in 10.0.1.* but not 10.0.1.5
   trusted_networks 2001:db8:1::1 !2001:db8:1::/64 2001:db8::/32
     # 2001:db8::/32 and 2001:db8:1::1/128, except the rest of 2001:db8:1::/64

This operates additively, so a C<trusted_networks> line after another one
will append new entries to the list of trusted networks.  To clear out the
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
    type => $CONF_TYPE_IPADDRLIST,
  });

=item clear_trusted_networks

Empty the list of trusted networks.

=cut

  push (@cmds, {
    setting => 'clear_trusted_networks',
    type => $CONF_TYPE_NOARGS,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (!defined $value || $value eq '') {
        return $INVALID_VALUE;
      }
      $self->{trusted_networks} = $self->new_netset('trusted_networks',1);
      $self->{trusted_networks_configured} = 0;
    }
  });

=item internal_networks IPaddress[/masklen] ...   (default: none)

What networks or hosts are 'internal' in your setup.   B<Internal> means
that relay hosts on these networks are considered to be MXes for your
domain(s), or internal relays.  This uses the same syntax as
C<trusted_networks>, above - see there for details.

This value is used when checking 'dial-up' or dynamic IP address
blocklists, in order to detect direct-to-MX spamming.

Trusted relays that accept mail directly from dial-up connections
(i.e. are also performing a role of mail submission agents - MSA)
should not be listed in C<internal_networks>. List them only in
C<trusted_networks>.

If C<trusted_networks> is set and C<internal_networks> is not, the value
of C<trusted_networks> will be used for this parameter.

If neither C<trusted_networks> nor C<internal_networks> is set, no addresses
will be considered local; in other words, any relays past the machine where
SpamAssassin is running will be considered external.

Every entry in C<internal_networks> must appear in C<trusted_networks>; in
other words, C<internal_networks> is always a subset of the trusted set.

Note: 127/8 and ::1 are always included in internal_networks, regardless of
your config.

=cut

  push (@cmds, {
    setting => 'internal_networks',
    type => $CONF_TYPE_IPADDRLIST,
  });

=item clear_internal_networks

Empty the list of internal networks.

=cut

  push (@cmds, {
    setting => 'clear_internal_networks',
    type => $CONF_TYPE_NOARGS,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (!defined $value || $value eq '') {
        return $INVALID_VALUE;
      }
      $self->{internal_networks} = $self->new_netset('internal_networks',1);
      $self->{internal_networks_configured} = 0;
    }
  });

=item msa_networks IPaddress[/masklen] ...   (default: none)

The networks or hosts which are acting as MSAs in your setup (but not also
as MX relays). This uses the same syntax as C<trusted_networks>, above - see
there for details.

B<MSA> means that the relay hosts on these networks accept mail from your
own users and authenticates them appropriately.  These relays will never
accept mail from hosts that aren't authenticated in some way. Examples of
authentication include, IP lists, SMTP AUTH, POP-before-SMTP, etc.

All relays found in the message headers after the MSA relay will take
on the same trusted and internal classifications as the MSA relay itself,
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
    type => $CONF_TYPE_IPADDRLIST,
  });

=item clear_msa_networks

Empty the list of msa networks.

=cut

  push (@cmds, {
    setting => 'clear_msa_networks',
    type => $CONF_TYPE_NOARGS,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (!defined $value || $value eq '') {
        return $INVALID_VALUE;
      }
      $self->{msa_networks} =
        $self->new_netset('msa_networks',0);  # no loopback IP
      $self->{msa_networks_configured} = 0;
    }
  });

=item originating_ip_headers header ...   (default: none)

A list of header field names from which an originating IP address can
be obtained. For example, webmail servers may record a client IP address
in X-Originating-IP.

These IP addresses are virtually appended into the Received: chain, so they
are used in RBL checks where appropriate.

Currently the IP addresses are not added into X-Spam-Relays-* header fields,
but they may be in the future.

A default list may be supplied via sa-update, use
C<clear_originating_ip_headers> to clear and override the settings if
needed.

=cut

  push (@cmds, {
    setting => 'originating_ip_headers',
    default => [],
    type => $CONF_TYPE_STRINGLIST,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
	return $MISSING_REQUIRED_VALUE;
      }
      foreach my $hfname (split(/\s+/, $value)) {
        # avoid duplicates, consider header field names case-insensitive
        push(@{$self->{originating_ip_headers}}, $hfname)
          if !grep(lc($_) eq lc($hfname), @{$self->{originating_ip_headers}});
      }
    }
  });

=item clear_originating_ip_headers

Empty the list of 'originating IP address' header field names. Useful if
you want to override the standard list supplied by sa-update.

=cut

  push (@cmds, {
    setting => 'clear_originating_ip_headers',
    type => $CONF_TYPE_NOARGS,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (!defined $value || $value eq '') {
        return $INVALID_VALUE;
      }
      $self->{originating_ip_headers} = [];
    }
  });

=item always_trust_envelope_sender ( 0 | 1 )   (default: 0)

Trust the envelope sender even if the message has been passed through one or
more trusted relays.  See also C<envelope_sender_header>.

=cut

  push (@cmds, {
    setting => 'always_trust_envelope_sender',
    default => 0,
    type => $CONF_TYPE_BOOL,
  });

=item skip_rbl_checks ( 0 | 1 )   (default: 0)

Turning on the skip_rbl_checks setting will disable the DNSEval plugin,
which implements Real-time Block List (or: Blockhole List) (RBL) lookups.

By default, SpamAssassin will run RBL checks. Individual blocklists may
be disabled selectively by setting a score of a corresponding rule to 0.

See also a related configuration parameter skip_uribl_checks,
which controls the URIDNSBL plugin (documented in the URIDNSBL man page).

=cut

  push (@cmds, {
    setting => 'skip_rbl_checks',
    default => 0,
    type => $CONF_TYPE_BOOL,
  });

=item dns_available { yes | no | test[: domain1 domain2...] }   (default: yes)

Tells SpamAssassin whether DNS resolving is available or not. A value I<yes>
indicates DNS resolving is available, a value I<no> indicates DNS resolving
is not available - both of these values apply unconditionally and skip initial
DNS tests, which can be slow or unreliable.

When the option value is a I<test> (with or without arguments), SpamAssassin
will query some domain names on the internet during initialization, attempting
to determine if DNS resolving is working or not. A space-separated list
of domain names may be specified explicitly, or left to a built-in default
of a dozen or so domain names. From an explicit or a default list a subset
of three domain names is picked randomly for checking. The test queries for
NS records of these domain: if at least one query returns a success then
SpamAssassin considers DNS resolving as available, otherwise not.

The problem is that the test can introduce some startup delay if a network
connection is down, and in some cases it can wrongly guess that DNS is
unavailable because a test connection failed, what causes disabling several
DNS-dependent tests.

Please note, the DNS test queries for NS records, so specify domain names,
not host names.

Since version 3.4.0 of SpamAssassin a default setting for option
I<dns_available> is I<yes>. A default in older versions was I<test>.

=cut

  push (@cmds, {
    setting => 'dns_available',
    default => 'yes',
    type => $CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /^test(?::\s*\S.*)?$/) {
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

=item dns_server ip-addr-port  (default: entries provided by Net::DNS)

Specifies an IP address of a DNS server, and optionally its port number.
The I<dns_server> directive may be specified multiple times, each entry
adding to a list of available resolving name servers. The I<ip-addr-port>
argument can either be an IPv4 or IPv6 address, optionally enclosed in
brackets, and optionally followed by a colon and a port number. In absence
of a port number a standard port number 53 is assumed. When an IPv6 address
is specified along with a port number, the address B<must> be enclosed in
brackets to avoid parsing ambiguity regarding a colon separator. A scoped
link-local IP address is allowed (assuming underlying modules allow it).

Examples :
 dns_server 127.0.0.1
 dns_server 127.0.0.1:53
 dns_server [127.0.0.1]:53
 dns_server [::1]:53
 dns_server fe80::1%lo0
 dns_server [fe80::1%lo0]:53

In absence of I<dns_server> directives, the list of name servers is provided
by Net::DNS module, which typically obtains the list from /etc/resolv.conf,
but this may be platform dependent. Please consult the Net::DNS::Resolver
documentation for details.

=cut

  push (@cmds, {
    setting => 'dns_server',
    type => $CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      my($address,$port); local($1,$2,$3);
      if ($value =~ /^(?: \[ ([^\]]*) \] | ([^:]*) ) : (\d+) \z/sx) {
        $address = defined $1 ? $1 : $2;  $port = $3;
      } elsif ($value =~ /^(?: \[ ([^\]]*) \] |
                               ([0-9A-F.:]+ (?: %[A-Z0-9._~-]* )? ) ) \z/six) {
        $address = defined $1 ? $1 : $2;  $port = '53';
      } else {
        return $INVALID_VALUE;
      }
      my $scope = '';  # scoped IP address?
      $scope = $1  if $address =~ s/ ( % [A-Z0-9._~-]* ) \z//xsi;
      if ($address =~ IS_IP_ADDRESS && $port >= 1 && $port <= 65535) {
        $self->{dns_servers} = []  if !$self->{dns_servers};
        # checked, untainted, stored in a normalized form
        push(@{$self->{dns_servers}}, untaint_var("[$address$scope]:$port"));
      } else {
        return $INVALID_VALUE;
      }
    }
  });

=item clear_dns_servers

Empty the list of explicitly configured DNS servers through a I<dns_server>
directive, falling back to Net::DNS -supplied defaults.

=cut

  push (@cmds, {
    setting => 'clear_dns_servers',
    type => $CONF_TYPE_NOARGS,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (!defined $value || $value eq '') {
        return $INVALID_VALUE;
      }
      undef $self->{dns_servers};
    }
  });

=item dns_local_ports_permit ranges...

Add the specified ports or ports ranges to the set of allowed port numbers
that can be used as local port numbers when sending DNS queries to a resolver.

The argument is a whitespace-separated or a comma-separated list of
single port numbers n, or port number pairs (i.e. m-n) delimited by a '-',
representing a range. Allowed port numbers are between 1 and 65535.

Directives I<dns_local_ports_permit> and I<dns_local_ports_avoid> are processed
in order in which they appear in configuration files. Each directive adds
(or subtracts) its subsets of ports to a current set of available ports.
Whatever is left in the set by the end of configuration processing
is made available to a DNS resolving client code.

If the resulting set of port numbers is empty (see also the directive
I<dns_local_ports_none>), then SpamAssassin does not apply its ports
randomization logic, but instead leaves the operating system to choose
a suitable free local port number.

The initial set consists of all port numbers in the range 1024-65535.
Note that system config files already modify the set and remove all the
IANA registered port numbers and some other ranges, so there is rarely
a need to adjust the ranges by site-specific directives.

See also directives I<dns_local_ports_permit> and I<dns_local_ports_none>.

=cut

  push (@cmds, {
    setting => 'dns_local_ports_permit',
    type => $CONF_TYPE_STRING,
    is_admin => 1,
    code => sub {
      my($self, $key, $value, $line) = @_;
      my(@port_ranges); local($1,$2);
      foreach my $range (split(/[ \t,]+/, $value)) {
        if ($range =~ /^(\d{1,5})\z/) {
          # don't allow adding a port number 0
          if ($1 < 1 || $1 > 65535) { return $INVALID_VALUE }
          push(@port_ranges, [$1,$1]);
        } elsif ($range =~ /^(\d{1,5})-(\d{1,5})\z/) {
          if ($1 < 1 || $1 > 65535) { return $INVALID_VALUE }
          if ($2 < 1 || $2 > 65535) { return $INVALID_VALUE }
          push(@port_ranges, [$1,$2]);
        } else {
          return $INVALID_VALUE;
        }
      }
      foreach my $p (@port_ranges) {
        undef $self->{dns_available_portscount};  # invalidate derived data
        set_ports_range(\$self->{dns_available_ports_bitset},
                        $p->[0], $p->[1], 1);
      }
    }
  });

=item dns_local_ports_avoid ranges...

Remove specified ports or ports ranges from the set of allowed port numbers
that can be used as local port numbers when sending DNS queries to a resolver.

Please see directive I<dns_local_ports_permit> for details.

=cut

  push (@cmds, {
    setting => 'dns_local_ports_avoid',
    type => $CONF_TYPE_STRING,
    is_admin => 1,
    code => sub {
      my($self, $key, $value, $line) = @_;
      my(@port_ranges); local($1,$2);
      foreach my $range (split(/[ \t,]+/, $value)) {
        if ($range =~ /^(\d{1,5})\z/) {
          if ($1 > 65535) { return $INVALID_VALUE }
          # don't mind clearing also the port number 0
          push(@port_ranges, [$1,$1]);
        } elsif ($range =~ /^(\d{1,5})-(\d{1,5})\z/) {
          if ($1 > 65535 || $2 > 65535) { return $INVALID_VALUE }
          push(@port_ranges, [$1,$2]);
        } else {
          return $INVALID_VALUE;
        }
      }
      foreach my $p (@port_ranges) {
        undef $self->{dns_available_portscount};  # invalidate derived data
        set_ports_range(\$self->{dns_available_ports_bitset},
                        $p->[0], $p->[1], 0);
      }
    }
  });

=item dns_local_ports_none

Is a fast shorthand for:

  dns_local_ports_avoid 1-65535

leaving the set of available DNS query local port numbers empty. In all
respects (apart from speed) it is equivalent to the shown directive, and can
be freely mixed with I<dns_local_ports_permit> and I<dns_local_ports_avoid>.

If the resulting set of port numbers is empty, then SpamAssassin does not
apply its ports randomization logic, but instead leaves the operating system
to choose a suitable free local port number.

See also directives I<dns_local_ports_permit> and I<dns_local_ports_avoid>.

=cut

  push (@cmds, {
    setting => 'dns_local_ports_none',
    type => $CONF_TYPE_NOARGS,
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (!defined $value || $value eq '') {
        return $INVALID_VALUE;
      }
      undef $self->{dns_available_portscount};  # invalidate derived data
      wipe_ports_range(\$self->{dns_available_ports_bitset}, 0);
    }
  });

=item dns_test_interval n   (default: 600 seconds)

If dns_available is set to I<test>, the dns_test_interval time in number
of seconds will tell SpamAssassin how often to retest for working DNS.
A numeric value is optionally suffixed by a time unit (s, m, h, d, w,
indicating seconds (default), minutes, hours, days, weeks).

=cut

  push (@cmds, {
    setting => 'dns_test_interval',
    default => 600,
    type => $CONF_TYPE_DURATION,
  });

=item dns_options opts   (default: v4, v6, norotate, nodns0x20, edns=4096)

Provides a (whitespace or comma -separated) list of options applying to DNS
resolving.  Available options are: I<v4>, I<v6>, I<rotate>, I<dns0x20> and
I<edns> (or I<edns0>).  Option name may be negated by prepending a I<no>
(e.g.  I<norotate>, I<NoEDNS>) to counteract a previously enabled option. 
Option names are not case-sensitive.  The I<dns_options> directive may
appear in configuration files multiple times, the last setting prevails.

Option I<v4> declares resolver capable of returning IPv4 (A) records. 
Option I<v6> declares resolver capable of returning IPv6 (AAAA) records. 
One would set I<nov6> if the resolver is filtering AAAA responses.  NOTE:
these options only refer to I<resolving capabilies>, there is no other
meaning like whether the IP address of resolver itself is IPv4 or IPv6.

Option I<edns> (or I<edns0>) may take a value which specifies a requestor's
acceptable UDP payload size according to EDNS0 specifications (RFC 6891,
ex RFC 2671) e.g. I<edns=4096>. When EDNS0 is off (I<noedns> or I<edns=512>)
a traditional implied UDP payload size is 512 bytes, which is also a minimum
allowed value for this option. When the option is specified but a value
is not provided, a conservative default of 1220 bytes is implied. It is
recommended to keep I<edns> enabled when using a local recursive DNS server
which supports EDNS0 (like most modern DNS servers do), a suitable setting
in this case is I<edns=4096>, which is also a default. Allowing UDP payload
size larger than 512 bytes can avoid truncation of resource records in large
DNS responses (like in TXT records of some SPF and DKIM responses, or when
an unreasonable number of A records is published by some domain). The option
should be disabled when a recursive DNS server is only reachable through
non- RFC 6891 compliant middleboxes (such as some old-fashioned firewall)
which bans DNS UDP payload sizes larger than 512 bytes. A suitable value
when a non-local recursive DNS server is used and a middlebox B<does> allow
EDNS0 but blocks fragmented IP packets is perhaps 1220 bytes, allowing a
DNS UDP packet to fit within a single IP packet in most cases (a slightly
less conservative range would be 1280-1410 bytes).

Option I<rotate> causes SpamAssassin to choose a DNS server at random
from all servers listed in C</etc/resolv.conf> every I<dns_test_interval>
seconds, effectively spreading the load over all currently available DNS
servers when there are many spamd workers. 

Option I<dns0x20> enables randomization of letters in a DNS query label
according to draft-vixie-dnsext-dns0x20, decreasing a chance of collisions
of responses (by chance or by a malicious intent) by increasing spread
as provided by a 16-bit query ID and up to 16 bits of a port number,
with additional bits as encoded by flipping case (upper/lower) of letters
in a query. The number of additional random bits corresponds to the number
of letters in a query label. Should work reliably with all mainstream
DNS servers - do not turn on if you see frequent info messages
"dns: no callback for id:" in the log, or if RBL or URIDNS lookups
do not work for no apparent reason.

=cut

  push (@cmds, {
    setting => 'dns_options',
    type => $CONF_TYPE_HASH_KEY_VALUE,
    # RFC 6891: A good compromise may be the use of an EDNS maximum payload size
    # of 4096 octets as a starting point.
    default => { 'v4' => 1, 'v6' => 1,
                 'rotate' => 0, 'dns0x20' => 0, 'edns' => 4096 },
    code => sub {
      my ($self, $key, $value, $line) = @_;
      foreach my $option (split (/[\s,]+/, lc $value)) {
        local($1,$2);
        if ($option =~ /^no(rotate|dns0x20|v4|v6)\z/) {
          $self->{dns_options}->{$1} = 0;
        } elsif ($option =~ /^no(edns)0?\z/) {
          $self->{dns_options}->{$1} = 0;
        } elsif ($option =~ /^(rotate|dns0x20|v4|v6)\z/) {
          $self->{dns_options}->{$1} = 1;
        } elsif ($option =~ /^(edns)0? (?: = (\d+) )? \z/x) {
          # RFC 6891 (ex RFC 2671) - EDNS0, value is a requestor's UDP payload
          # size, defaults to some UDP packet size likely to fit into a single
          # IP packet which is more likely to pass firewalls which choke on IP
          # fragments.  RFC 2460: min MTU is 1280 for IPv6, minus 40 bytes for
          # basic header, yielding 1240.  RFC 3226 prescribes a min of 1220 for
          # RFC 2535 compliant servers.  RFC 6891: choosing between 1280 and
          # 1410 bytes for IP (v4 or v6) over Ethernet would be reasonable.
          # 
          $self->{dns_options}->{$1} = $2 || 1220;
          return $INVALID_VALUE  if $self->{dns_options}->{$1} < 512;
        } else {
          return $INVALID_VALUE;
        }
      }
    }
  });

=item dns_query_restriction (allow|deny) domain1 domain2 ...

Option allows disabling of rules which would result in a DNS query to one of
the listed domains. The first argument must be a literal C<allow> or C<deny>,
remaining arguments are domains names.

Most DNS queries (with some exceptions) are subject to dns_query_restriction.
A domain to be queried is successively stripped-off of its leading labels
(thus yielding a series of its parent domains), and on each iteration a
check is made against an associative array generated by dns_query_restriction
options. Search stops at the first match (i.e. the tightest match), and the
matching entry with its C<allow> or C<deny> value then controls whether a
DNS query is allowed to be launched.

If no match is found an implicit default is to allow a query. The purpose of
an explicit C<allow> entry is to be able to override a previously configured
C<deny> on the same domain or to override an entry (possibly yet to be
configured in subsequent config directives) on one of its parent domains.
Thus an 'allow zen.spamhaus.org' with a 'deny spamhaus.org' would permit
DNS queries on a specific DNS BL zone but deny queries to other zones under
the same parent domain.

Domains are matched case-insensitively, no wildcards are recognized,
there should be no leading or trailing dot.

Specifying a block on querying a domain name has a similar effect as setting
a score of corresponding DNSBL and URIBL rules to zero, and can be a handy
alternative to hunting for such rules when a site policy does not allow
certain DNS block lists to be queried.

Special wildcard "dns_query_restriction deny *" is supported to block all
queries except allowed ones.

Example:
  dns_query_restriction deny  dnswl.org surbl.org
  dns_query_restriction allow zen.spamhaus.org
  dns_query_restriction deny  spamhaus.org mailspike.net spamcop.net

=cut

  push (@cmds, {
    setting => 'dns_query_restriction',
    type => $CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      defined $value && $value =~ s/^(allow|deny)\s+//i
        or return $INVALID_VALUE;
      my $blocked = lc($1) eq 'deny' ? 1 : 0;
      foreach my $domain (split(/\s+/, $value)) {
        $domain =~ s/^\.//; $domain =~ s/\.\z//;  # strip dots
        $self->{dns_query_blocked}{lc $domain} = $blocked;
      }
    }
  });

=item clear_dns_query_restriction

The option removes any entries entered by previous 'dns_query_restriction'
options, leaving the list empty, i.e. allowing DNS queries for any domain
(including any DNS BL zone).

=cut

  push (@cmds, {
    setting =>  'clear_dns_query_restriction',
    aliases => ['clear_dns_query_restrictions'],
    type => $CONF_TYPE_NOARGS,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      return $INVALID_VALUE  if defined $value && $value ne '';
      delete $self->{dns_query_blocked};
    }
  });

=item dns_block_rule RULE domain

If rule named RULE is hit, DNS queries to specified domain are
I<temporarily> blocked. Intended to be used with rules that check
RBL return codes for specific blocked status.  For example:

  urirhssub URIBL_BLOCKED multi.uribl.com. A 1
  dns_block_rule URIBL_BLOCKED multi.uribl.com

Block status is maintained across all processes by empty statefile named
"dnsblock_multi.uribl.com" in global state dir:
home_dir_for_helpers/.spamassassin, $HOME/.spamassassin,
/var/lib/spamassassin (localstate), depending which is found and writable.

=cut

  push (@cmds, {
    setting => 'dns_block_rule',
    is_admin => 1,
    type => $CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local($1,$2);
      defined $value && $value =~ /^(\S+)\s+(.+)$/
        or return $INVALID_VALUE;
      my $rule = $1;
      foreach my $domain (split(/\s+/, lc($2))) {
        $domain =~ s/^\.//; $domain =~ s/\.\z//;  # strip dots
        if ($domain !~ /^[a-z0-9_.-]+$/) {
          return $INVALID_VALUE;
        }
        # will end up in filename, do not allow / etc in above regex!
        $domain = untaint_var($domain);
        # Check.pm check_main() uses this
        $self->{dns_block_rule}{$rule}{$domain} = 1;
        # bgsend_and_start_lookup() uses this
        $self->{dns_block_rule_domains}{$domain} = $domain;
      }
    }
  });

=item dns_block_time   (default: 300)

dns_block_rule query blockage will last this many seconds.

=cut

  push (@cmds, {
    setting => 'dns_block_time',
    is_admin => 1,
    default => 300,
    type => $CONF_TYPE_NUMERIC,
  });

=back

=head2 LEARNING OPTIONS

=over 4

=item use_learner ( 0 | 1 )		(default: 1)

Whether to use any machine-learning classifiers with SpamAssassin, such as the
default 'BAYES_*' rules.  Setting this to 0 will disable use of any and all
human-trained classifiers.

=cut

  push (@cmds, {
    setting => 'use_learner',
    default => 1,
    type => $CONF_TYPE_BOOL,
  });

=item use_bayes ( 0 | 1 )		(default: 1)

Whether to use the naive-Bayesian-style classifier built into
SpamAssassin.  This is a master on/off switch for all Bayes-related
operations.

=cut

  push (@cmds, {
    setting => 'use_bayes',
    default => 1,
    type => $CONF_TYPE_BOOL,
  });

=item use_bayes_rules ( 0 | 1 )		(default: 1)

Whether to use rules using the naive-Bayesian-style classifier built
into SpamAssassin.  This allows you to disable the rules while leaving
auto and manual learning enabled.

=cut

  push (@cmds, {
    setting => 'use_bayes_rules',
    default => 1,
    type => $CONF_TYPE_BOOL,
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
    type => $CONF_TYPE_BOOL,
  });

=item bayes_token_sources  (default: header visible invisible uri)

Controls which sources in a mail message can contribute tokens (e.g. words,
phrases, etc.) to a Bayes classifier. The argument is a space-separated list
of keywords: I<header>, I<visible>, I<invisible>, I<uri>, I<mimepart>), each
of which may be prefixed by a I<no> to indicate its exclusion. Additionally
two reserved keywords are allowed: I<all> and I<none> (or: I<noall>). The list
of keywords is processed sequentially: a keyword I<all> adds all available
keywords to a set being built, a I<none> or I<noall> clears the set, other
non-negated keywords are added to the set, and negated keywords are removed
from the set. Keywords are case-insensitive.

The default set is: I<header> I<visible> I<invisible> I<uri>, which is
equivalent for example to: I<All> I<NoMIMEpart>. The reason why I<mimepart>
is not currently in a default set is that it is a newer source (introduced
with SpamAssassin version 3.4.1) and not much experience has yet been gathered
regarding its usefulness.

See also option C<bayes_ignore_header> for a fine-grained control on individual
header fields under the umbrella of a more general keyword I<header> here.

Keywords imply the following data sources:

=over 4

=item I<header> - tokens collected from a message header section

=item I<visible> - words from visible text (plain or HTML) in a message body

=item I<invisible> - hidden/invisible text in HTML parts of a message body

=item I<uri> - URIs collected from a message body

=item I<mimepart> - digests (hashes) of all MIME parts (textual or non-textual) of a message, computed after Base64 and quoted-printable decoding, suffixed by their Content-Type

=item I<all> - adds all the above keywords to the set being assembled

=item I<none> or I<noall> - removes all keywords from the set

=back

The C<bayes_token_sources> directive may appear multiple times, its keywords
are interpreted sequentially, adding or removing items from the final set
as they appear in their order in C<bayes_token_sources> directive(s).

=cut

  push (@cmds, {
    setting => 'bayes_token_sources',
    default => { map(($_,1), qw(header visible invisible uri)) },  # mimepart
    type => $CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      return $MISSING_REQUIRED_VALUE  if $value eq '';
      my $h = ($self->{bayes_token_sources} ||= {});
      my %all_kw = map(($_,1), qw(header visible invisible uri mimepart));
      foreach (split(/\s+/, lc $value)) {
        if (/^(none|noall)\z/) {
          %$h = ();
        } elsif ($_ eq 'all') {
          %$h = %all_kw;
        } elsif (/^(no)?(.+)\z/s && exists $all_kw{$2}) {
          $h->{$2} = defined $1 ? 0 : 1;
        } else {
          return $INVALID_VALUE;
        }
      }
    }
  });

=item bayes_ignore_header header_name

If you receive mail filtered by upstream mail systems, like
a spam-filtering ISP or mailing list, and that service adds
new headers (as most of them do), these headers may provide
inappropriate cues to the Bayesian classifier, allowing it
to take a "short cut". To avoid this, list the headers using this
setting. Header matching is case-insensitive.  Example:

        bayes_ignore_header X-Upstream-Spamfilter
        bayes_ignore_header X-Upstream-SomethingElse

=cut

  push (@cmds, {
    setting => 'bayes_ignore_header',
    type => $CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $MISSING_REQUIRED_VALUE;
      }
      foreach (split(/\s+/, $value)) {
        $self->{bayes_ignore_header}->{lc $_} = 1;
      }
    }
  });

=item bayes_ignore_from user@example.com

Bayesian classification and autolearning will not be performed on mail
from the listed addresses.  Program C<sa-learn> will also ignore the
listed addresses if it is invoked using the C<--use-ignores> option.
One or more addresses can be listed, see C<welcomelist_from>.

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
    type => $CONF_TYPE_ADDRLIST,
  });

=item bayes_ignore_to user@example.com

Bayesian classification and autolearning will not be performed on mail
to the listed addresses.  See C<bayes_ignore_from> for details.

=cut

  push (@cmds, {
    setting => 'bayes_ignore_to',
    type => $CONF_TYPE_ADDRLIST,
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
    type => $CONF_TYPE_NUMERIC,
  });
  push (@cmds, {
    setting => 'bayes_min_spam_num',
    default => 200,
    type => $CONF_TYPE_NUMERIC,
  });

=item bayes_learn_during_report         (Default: 1)

The Bayes system will, by default, learn any reported messages
(C<spamassassin -r>) as spam.  If you do not want this to happen, set
this option to 0.

=cut

  push (@cmds, {
    setting => 'bayes_learn_during_report',
    default => 1,
    type => $CONF_TYPE_BOOL,
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
    type => $CONF_TYPE_STRING,
  });

=item bayes_use_hapaxes		(default: 1)

Should the Bayesian classifier use hapaxes (words/tokens that occur only
once) when classifying?  This produces significantly better hit-rates.

=cut

  push (@cmds, {
    setting => 'bayes_use_hapaxes',
    default => 1,
    type => $CONF_TYPE_BOOL,
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
    type => $CONF_TYPE_NUMERIC,
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
    type => $CONF_TYPE_NUMERIC,
  });

=item bayes_auto_expire       		(default: 1)

If enabled, the Bayes system will try to automatically expire old tokens
from the database.  Auto-expiry occurs when the number of tokens in the
database surpasses the bayes_expiry_max_db_size value. If a bayes datastore
backend does not implement individual key/value expirations, the setting
is silently ignored.

=cut

  push (@cmds, {
    setting => 'bayes_auto_expire',
    default => 1,
    type => $CONF_TYPE_BOOL,
  });

=item bayes_token_ttl       		(default: 3w, i.e. 3 weeks)

Time-to-live / expiration time in seconds for tokens kept in a Bayes database.
A numeric value is optionally suffixed by a time unit (s, m, h, d, w,
indicating seconds (default), minutes, hours, days, weeks).

If bayes_auto_expire is true and a Bayes datastore backend supports it
(currently only Redis), this setting controls deletion of expired tokens
from a bayes database. The value is observed on a best-effort basis, exact
timing promises are not necessarily kept. If a bayes datastore backend
does not implement individual key/value expirations, the setting is silently
ignored.

=cut

  push (@cmds, {
    setting => 'bayes_token_ttl',
    default => 3*7*24*60*60,  # seconds (3 weeks)
    type => $CONF_TYPE_DURATION,
  });

=item bayes_seen_ttl       		(default: 8d, i.e. 8 days)

Time-to-live / expiration time in seconds for 'seen' entries
(i.e. mail message digests with their status) kept in a Bayes database.
A numeric value is optionally suffixed by a time unit (s, m, h, d, w,
indicating seconds (default), minutes, hours, days, weeks).

If bayes_auto_expire is true and a Bayes datastore backend supports it
(currently only Redis), this setting controls deletion of expired 'seen'
entries from a bayes database. The value is observed on a best-effort basis,
exact timing promises are not necessarily kept. If a bayes datastore backend
does not implement individual key/value expirations, the setting is silently
ignored.

=cut

  push (@cmds, {
    setting => 'bayes_seen_ttl',
    default => 8*24*60*60,  # seconds (8 days)
    type => $CONF_TYPE_DURATION,
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
    type => $CONF_TYPE_BOOL,
  });

=back

=head2 MISCELLANEOUS OPTIONS

=over 4

=item time_limit n   (default: 300)

Specifies a limit on elapsed time in seconds that SpamAssassin is allowed
to spend before providing a result. The value may be fractional and must
not be negative, zero is interpreted as unlimited. The default is 300
seconds for consistency with the spamd default setting of --timeout-child .

This is a best-effort advisory setting, processing will not be abruptly
aborted at an arbitrary point in processing when the time limit is exceeded,
but only on reaching one of locations in the program flow equipped with a
time test. Currently equipped with the test are the main checking loop,
asynchronous DNS lookups, plugins which are calling external programs.
Rule evaluation is guarded by starting a timer (alarm) on each set of
compiled rules.

When a message is passed to Mail::SpamAssassin::parse, a deadline time
is established as a sum of current time and the C<time_limit> setting.

This deadline may also be specified by a caller through an option
'master_deadline' in $suppl_attrib on a call to parse(), possibly providing
a more accurate deadline taking into account past and expected future
processing of a message in a mail filtering setup. If both the config
option as well as a 'master_deadline' option in a call are provided,
the shorter time limit of the two is used (since version 3.3.2).
Note that spamd (and possibly third-party callers of SpamAssassin) will
supply the 'master_deadline' option in a call based on its --timeout-child
option (or equivalent), unlike the command line C<spamassassin>, which has
no such command line option.

When a time limit is exceeded, most of the remaining tests will be skipped,
as well as auto-learning. Whatever tests fired so far will determine the
final score. The behaviour is similar to short-circuiting with attribute 'on',
as implemented by a Shortcircuit plugin. A synthetic hit on a rule named
TIME_LIMIT_EXCEEDED with a near-zero default score is generated, so that
the report will reflect the event. A score for TIME_LIMIT_EXCEEDED may
be provided explicitly in a configuration file, for example to achieve
welcomelisting or blocklisting effect for messages with long processing times.

The C<time_limit> option is a useful protection against excessive processing
time on certain degenerate or unusually long or complex mail messages, as well
as against some DoS attacks. It is also needed in time-critical pre-queue
filtering setups (e.g. milter, proxy, integration with MTA), where message
processing must finish before a SMTP client times out.  RFC 5321 prescribes
in section 4.5.3.2.6 the 'DATA Termination' time limit of 10 minutes,
although it is not unusual to see some SMTP clients abort sooner on waiting
for a response. A sensible C<time_limit> for a pre-queue filtering setup is
maybe 50 seconds, assuming that clients are willing to wait at least a minute.

=cut

  push (@cmds, {
    setting => 'time_limit',
    default => 300,
    type => $CONF_TYPE_DURATION,
  });

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
    type => $CONF_TYPE_STRING,
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

By default, headers added by SpamAssassin will be whitespace folded.
In other words, they will be broken up into multiple lines instead of
one very long one and each continuation line will have a tabulator
prepended to mark it as a continuation of the preceding one.

The automatic wrapping can be disabled here.  Note that this can generate very
long lines.  RFC 2822 required that header lines do not exceed 998 characters
(not counting the final CRLF).

=cut

  push (@cmds, {
    setting => 'fold_headers',
    default => 1,
    type => $CONF_TYPE_BOOL,
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
    default => [],
    type => $CONF_TYPE_STRINGLIST,
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
helpful.  Name the header that your MTA or MDA adds to messages containing the
address used at the MAIL FROM step of the SMTP transaction.

If the header in question contains C<E<lt>> or C<E<gt>> characters at the start
and end of the email address in the right-hand side, as in the SMTP
transaction, these will be stripped.

If the header is not found in a message, or if it's value does not contain an
C<@> sign, SpamAssassin will issue a warning in the logs and fall back to its
default heuristics.

(Note for MTA developers: we would prefer if the use of a single header be
avoided in future, since that precludes 'downstream' spam scanning.
C<https://wiki.apache.org/spamassassin/EnvelopeSenderInReceived> details a
better proposal, storing the envelope sender at each hop in the C<Received>
header.)

example:

    envelope_sender_header X-SA-Exim-Mail-From

=cut

  push (@cmds, {
    setting => 'envelope_sender_header',
    default => undef,
    type => $CONF_TYPE_STRING,
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
    type => $CONF_TYPE_HASH_KEY_VALUE,
  });

=item report_charset CHARSET		(default: UTF-8)

Set the MIME Content-Type charset used for the text/plain report which
is attached to spam mail messages.

=cut

  push (@cmds, {
    setting => 'report_charset',
    default => 'UTF-8',
    type => $CONF_TYPE_STRING,
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
    default => '',
    type => $CONF_TYPE_TEMPLATE,
  });

=item clear_report_template

Clear the report template.

=cut

  push (@cmds, {
    command => 'clear_report_template',
    setting => 'report_template',
    type => $CONF_TYPE_NOARGS,
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
    type => $CONF_TYPE_STRING,
  });

=item report_hostname ...hostname to use...

Set what _HOSTNAME_ is replaced with in the above report text.
By default, this is determined dynamically as whatever the host running
SpamAssassin calls itself.

=cut

  push (@cmds, {
    setting => 'report_hostname',
    default => '',
    type => $CONF_TYPE_STRING,
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
    type => $CONF_TYPE_TEMPLATE,
  });

=item clear_unsafe_report_template

Clear the unsafe_report template.

=cut

  push (@cmds, {
    command => 'clear_unsafe_report_template',
    setting => 'unsafe_report_template',
    type => $CONF_TYPE_NOARGS,
    code => \&Mail::SpamAssassin::Conf::Parser::set_template_clear
  });

=item mbox_format_from_regex

Set a specific regular expression to be used for mbox file From separators.

For example, this setting will allow sa-learn to process emails stored in
a kmail 2 mbox:

mbox_format_from_regex /^From \S+  ?[[:upper:]][[:lower:]]{2}(?:, \d\d [[:upper:]][[:lower:]]{2} \d{4} [0-2]\d:\d\d:\d\d [+-]\d{4}| [[:upper:]][[:lower:]]{2} [ 1-3]\d [ 0-2]\d:\d\d:\d\d \d{4})/


=cut

  push (@cmds, {
    setting => 'mbox_format_from_regex',
    type => $CONF_TYPE_STRING
  });


=item parse_dkim_uris ( 0 | 1 ) (default: 1)

If this option is set to 1 and the message contains DKIM headers, the headers will be parsed for URIs to process alongside URIs found in the body with some rules and modules (ex. URIDNSBL)

=cut

  push (@cmds, {
    setting => 'parse_dkim_uris',
    default => 1,
    type => $CONF_TYPE_BOOL,
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
    type => $CONF_TYPE_BOOL,
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
    default => [],
    type => $CONF_TYPE_STRINGLIST,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      $value =~ s/^\s+//;
      if ($value eq '') {
	return $MISSING_REQUIRED_VALUE;
      }
      my ($rec, $err) = compile_regexp($value, 1);
      if (!$rec) {
        dbg("config: invalid redirector_pattern '$value': $err");
	return $INVALID_VALUE;
      }
      push @{$self->{main}->{conf}->{redirector_patterns}}, $rec;
    }
  });

=item header SYMBOLIC_TEST_NAME header op /pattern/modifiers	[if-unset: STRING]

Define a test.  C<SYMBOLIC_TEST_NAME> is a symbolic test name, such as
'FROM_ENDS_IN_NUMS'.  C<header> is the name of a mail header field,
such as 'Subject', 'To', 'From', etc.  Header field names are matched
case-insensitively (conforming to RFC 5322 section 1.2.2), except for
all-capitals metaheader fields such as ALL, MESSAGEID, ALL-TRUSTED.

Appending a modifier C<:raw> to a header field name will inhibit decoding of
quoted-printable or base-64 encoded strings, and will preserve all whitespace
inside the header string.  The C<:raw> may also be applied to pseudo-headers
e.g. C<ALL:raw> will return a pristine (unmodified) header section.

Appending a modifier C<:addr> to a header field name will cause everything
except the first email address to be removed from the header field.  It is
mainly applicable to header fields 'From', 'Sender', 'To', 'Cc' along with
their 'Resent-*' counterparts, and the 'Return-Path'.

Appending a modifier C<:name> to a header field name will cause everything
except the first display name to be removed from the header field. It is
mainly applicable to header fields containing a single mail address: 'From',
'Sender', along with their 'Resent-From' and 'Resent-Sender' counterparts.

It is syntactically permitted to append more than one modifier to a header
field name, although currently most combinations achieve no additional effect,
for example C<From:addr:raw> or C<From:raw:addr> is currently the same as
C<From:addr> .

For example, appending C<:addr> to a header name will result in example@foo
in all of the following cases:

=over 4

=item example@foo

=item example@foo (Foo Blah)

=item example@foo, example@bar

=item display: example@foo (Foo Blah), example@bar ;

=item Foo Blah E<lt>example@fooE<gt>

=item "Foo Blah" E<lt>example@fooE<gt>

=item "'Foo Blah'" E<lt>example@fooE<gt>

=back

For example, appending C<:name> to a header name will result in "Foo Blah"
(without quotes) in all of the following cases:

=over 4

=item example@foo (Foo Blah)

=item example@foo (Foo Blah), example@bar

=item display: example@foo (Foo Blah), example@bar ;

=item Foo Blah E<lt>example@fooE<gt>

=item "Foo Blah" E<lt>example@fooE<gt>

=item "'Foo Blah'" E<lt>example@fooE<gt>

=back

There are several special pseudo-headers that can be specified:

=over 4

=item C<ALL> can be used to mean the text of all the message's headers.
Note that all whitespace inside the headers, at line folds, is currently
compressed into a single space (' ') character. To obtain a pristine
(unmodified) header section, use C<ALL:raw> - the :raw modifier is documented
above. Also similar that return headers added by specific relays: ALL-TRUSTED,
ALL-INTERNAL, ALL-UNTRUSTED, ALL-EXTERNAL.

=item C<ToCc> can be used to mean the contents of both the 'To' and 'Cc'
headers.

=item C<EnvelopeFrom> is the address used in the 'MAIL FROM:' phase of the SMTP
transaction that delivered this message, if this data has been made available
by the SMTP server.  See C<envelope_sender_header> for more information
on how to set this.

=item C<MESSAGEID> is a symbol meaning all Message-Id's found in the message;
some mailing list software moves the real 'Message-Id' to 'Resent-Message-Id'
or to 'X-Message-Id', then uses its own one in the 'Message-Id' header.
The value returned for this symbol is the text from all 3 headers, separated
by newlines.

=item C<X-Spam-Relays-Untrusted>, C<X-Spam-Relays-Trusted>,
C<X-Spam-Relays-Internal> and C<X-Spam-Relays-External> represent a portable,
pre-parsed representation of the message's network path, as recorded in the
Received headers, divided into 'trusted' vs 'untrusted' and 'internal' vs
'external' sets.  See C<https://wiki.apache.org/spamassassin/TrustedRelays> for
more details.

=back

C<op> is either C<=~> (contains regular expression) or C<!~> (does not contain
regular expression), and C<pattern> is a valid Perl regular expression, with
C<modifiers> as regexp modifiers in the usual style.   Note that multi-line
rules are not supported, even if you use C<x> as a modifier.  Also note that
the C<#> character must be escaped (C<\#>) or else it will be considered to be
the start of a comment and not part of the regexp.

If the header specified matches multiple headers, their text will be
concatenated with embedded \n's. Therefore you may wish to use C</m> if you
use C<^> or C<$> in your regular expression.

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

=item header SYMBOLIC_TEST_NAME exists:header_field_name

Define a header field existence test.  C<header_field_name> is the name
of a header field to test for existence.  Not to be confused with a
test for a nonempty header field body, which can be implemented by a
C<header SYMBOLIC_TEST_NAME header =~ /\S/> rule as described above.

=item header SYMBOLIC_TEST_NAME eval:name_of_eval_method([arguments])

Define a header eval test.  C<name_of_eval_method> is the name of
a method registered by a C<Mail::SpamAssassin::Plugin> object.
C<arguments> are optional arguments to the function call.

=item header SYMBOLIC_TEST_NAME eval:check_rbl('set', 'zone' [, 'sub-test'])

Check a DNSBL (a DNS blocklist or welcomelist).  This will retrieve Received:
headers from the message, extract the IP addresses, select which ones are
'untrusted' based on the C<trusted_networks> logic, and query that DNSBL
zone.  There's a few things to note:

=over 4

=item duplicated or private IPs

Duplicated IPs are only queried once and reserved IPs are not queried.
Private IPs are those listed in
C<https://www.iana.org/assignments/ipv4-address-space>, or
C<https://tools.ietf.org/html/rfc5735> as private.

=item the 'set' argument

This is used as a 'zone ID'.  If you want to look up a multiple-meaning zone
like SORBS, you can then query the results from that zone using it;
but all check_rbl_sub() calls must use that zone ID.

Also, if more than one IP address gets a DNSBL hit for a particular rule, it
does not affect the score because rules only trigger once per message.

=item the 'zone' argument

This is the root zone of the DNSBL.

The domain name is considered to be a fully qualified domain name
(i.e. not subject to DNS resolver's search or default domain options).
No trailing period is needed, and will be removed if specified.

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

When checking a 'nice' DNSBL (a DNS welcomelist), you cannot trust the IP
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
See the Wiki page at C<https://wiki.apache.org/spamassassin/TrustedRelays>
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
IPv4 dotted address for RBLs that return multiple A records, or a
non-negative decimal number to specify a bitmask for RBLs that return a
single A record containing a bitmask of results, or a regular expression.

Note: the set name must be exactly the same for as the main query rule,
including selections like '-notfirsthop' appearing at the end of the set
name.

=cut

  push (@cmds, {
    setting => 'header',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local($1);
      if ($value !~ s/^(\S+)\s+//) {
        return $INVALID_VALUE;
      }
      my $rulename = $1;
      if ($value eq '') {
        return $MISSING_REQUIRED_VALUE;
      }
      if ($value =~ /^(?:rbl)?eval:(.*)$/) {
        my $fn = $1;
        if ($fn !~ /^\w+\(.*\)$/) {
          return $INVALID_VALUE;
        }
        if ($fn =~ /^check_(?:rbl|dns)/) {
          $self->{parser}->add_test ($rulename, $fn, $TYPE_RBL_EVALS);
        }
        else {
          $self->{parser}->add_test ($rulename, $fn, $TYPE_HEAD_EVALS);
        }
      }
      else {
        # Detailed parsing in add_test
        $self->{parser}->add_test ($rulename, $value, $TYPE_HEAD_TESTS);
      }
    }
  });

=item body SYMBOLIC_TEST_NAME /pattern/modifiers

Define a body pattern test.  C<pattern> is a Perl regular expression.  Note:
as per the header tests, C<#> must be escaped (C<\#>) or else it is considered
the beginning of a comment.

The 'body' in this case is the textual parts of the message body; any
non-text MIME parts are stripped, and the message decoded from
Quoted-Printable or Base-64-encoded format if necessary.  Parts declared as
text/html will be rendered from HTML to text.

Body is processed as a raw byte string, which means Unicode-specific regex
features like \p{} can NOT be used for matching.  The normalize_charset
setting will also affect how raw bytes are presented.  Rules in .cf files
should be written portably - to match "a with umlaut" character, look for
both LATIN1 and UTF8 raw byte variants: /(?:\xE4|\xC3\xA4)/

All body paragraphs (double-newline-separated blocks text) are turned into a
linebreaks-removed, whitespace-normalized, single line.  Any lines longer
than 2kB are split into shorter separate lines (from a boundary when
possible), this may unexpectedly prevent pattern from matching.  Patterns
are matched independently against each of these lines.

Note that by default the message Subject header is considered part of the
body and becomes the first line when running the rules. If you don't want
to match Subject along with body text, use "tflags RULENAME nosubject".

See C<https://wiki.apache.org/SpamAssassin/WritingRules> for more
information.

=item body SYMBOLIC_TEST_NAME eval:name_of_eval_method([args])

Define a body eval test.  See above.

=cut

  push (@cmds, {
    setting => 'body',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local($1);
      if ($value !~ s/^(\S+)\s+//) {
        return $INVALID_VALUE;
      }
      my $rulename = $1;
      if ($value eq '') {
        return $MISSING_REQUIRED_VALUE;
      }
      if ($value =~ /^eval:(.*)$/) {
        my $fn = $1;
        if ($fn !~ /^\w+\(.*\)$/) {
          return $INVALID_VALUE;
        }
        $self->{parser}->add_test ($rulename, $fn, $TYPE_BODY_EVALS);
      } else {
        $self->{parser}->add_test ($rulename, $value, $TYPE_BODY_TESTS);
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
      local($1);
      if ($value !~ s/^(\S+)\s+//) {
        return $INVALID_VALUE;
      }
      my $rulename = $1;
      if ($value eq '') {
        return $MISSING_REQUIRED_VALUE;
      }
      $self->{parser}->add_test ($rulename, $value, $TYPE_URI_TESTS);
    }
  });

=item rawbody SYMBOLIC_TEST_NAME /pattern/modifiers

Define a raw-body pattern test.  C<pattern> is a Perl regular expression.
Note: as per the header tests, C<#> must be escaped (C<\#>) or else it is
considered the beginning of a comment.

The 'raw body' of a message is the raw data inside all textual parts. The
text will be decoded from base64 or quoted-printable encoding, but HTML
tags and line breaks will still be present.  Multiline expressions will
need to be used to match strings that are broken by line breaks.

Note that the text is split into 2-4kB chunks (from a word boundary when
possible), this may unexpectedly prevent pattern from matching.  Patterns
are matched independently against each of these chunks.

=item rawbody SYMBOLIC_TEST_NAME eval:name_of_eval_method([args])

Define a raw-body eval test.  See above.

=cut

  push (@cmds, {
    setting => 'rawbody',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local($1);
      if ($value !~ s/^(\S+)\s+//) {
        return $INVALID_VALUE;
      }
      my $rulename = $1;
      if ($value eq '') {
        return $MISSING_REQUIRED_VALUE;
      }
      if ($value =~ /^eval:(.*)$/) {
        my $fn = $1;
        if ($fn !~ /^\w+\(.*\)$/) {
          return $INVALID_VALUE;
        }
        $self->{parser}->add_test ($rulename, $fn, $TYPE_RAWBODY_EVALS);
      } else {
        $self->{parser}->add_test ($rulename, $value, $TYPE_RAWBODY_TESTS);
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

Note that CRLF/LF line endings are matched as the original message has them.
For any full rules that match newlines, it's recommended to use \r?$ instead
of plain $, so it works on all systems.

=item full SYMBOLIC_TEST_NAME eval:name_of_eval_method([args])

Define a full message eval test.  See above.

=cut

  push (@cmds, {
    setting => 'full',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local($1);
      if ($value !~ s/^(\S+)\s+//) {
        return $INVALID_VALUE;
      }
      my $rulename = $1;
      if ($value eq '') {
        return $MISSING_REQUIRED_VALUE;
      }
      if ($value =~ /^eval:(.*)$/) {
        my $fn = $1;
        if ($fn !~ /^\w+\(.*\)$/) {
          return $INVALID_VALUE;
        }
        $self->{parser}->add_test ($rulename, $fn, $TYPE_FULL_EVALS);
      } else {
        $self->{parser}->add_test ($rulename, $value, $TYPE_FULL_TESTS);
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

Can also define an arithmetic expression in terms of other tests,
with an unhit test having the value "0" and a hit test having a
nonzero value.  The value of a hit meta test is that of its arithmetic
expression.  The value of a hit eval test is that returned by its
method.  The value of a hit header, body, rawbody, uri, or full test
which has the "multiple" tflag is the number of times the test hit.
The value of any other type of hit test is "1".

For example:

meta META2        (3 * TEST1 - 2 * TEST2) E<gt> 0

Note that Perl builtins and functions, like C<abs()>, B<can't> be
used, and will be treated as rule names.

If you want to define a meta-rule, but do not want its individual sub-rules to
count towards the final score unless the entire meta-rule matches, give the
sub-rules names that start with '__' (two underscores).  SpamAssassin will
ignore these for scoring.

=item meta SYMBOLIC_TEST_NAME ... rules_matching(RULEGLOB) ...

Special function that will expand to list of matching rulenames.  Can be
used anywhere in expressions.  Argument supports glob style rulename
matching (* = anything, ? = one character).  Matching is case-sensitive.

For example, this will hit if at least two __FOO_* rule hits:

 body __FOO_1  /xxx/
 body __FOO_2  /yyy/
 body __FOO_3  /zzz/
 meta FOO_META  rules_matching(__FOO_*) >= 2

Which would be the same as:

 meta FOO_META  (__FOO_1 + __FOO_2 + __FOO_3) >= 2


=cut

  push (@cmds, {
    setting => 'meta',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local($1);
      if ($value !~ s/^(\S+)\s+//) {
        return $INVALID_VALUE;
      }
      my $rulename = $1;
      if ($value eq '') {
        return $MISSING_REQUIRED_VALUE;
      }
      if ($value =~ /\*\s*\*/) {
	info("config: found invalid '**' or '* *' operator in meta command");
        return $INVALID_VALUE;
      }
      $self->{parser}->add_test ($rulename, $value, $TYPE_META_TESTS);
    }
  });

=item reuse SYMBOLIC_TEST_NAME [ OLD_SYMBOLIC_TEST_NAME_1 ... ]

Defines the name of a test that should be "reused" during the scoring
process. If a message has an X-Spam-Status header that shows a hit for
this rule or any of the old rule names given, a hit will be added for
this rule when B<mass-check --reuse> is used. Examples:

C<reuse SPF_PASS>

C<reuse MY_NET_RULE_V2 MY_NET_RULE_V1>

The actual logic for reuse tests is done by
B<Mail::SpamAssassin::Plugin::Reuse>.

=cut

  push (@cmds, {
    setting => 'reuse',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value !~ /\s*(\w+)(?:\s+(?:\w+(?:\s+\w+)*))?\s*$/) {
        return $INVALID_VALUE;
      }
      my $rule_name = $1;
      # don't overwrite tests, just define them so scores, priorities work
      if (!exists $self->{tests}->{$rule_name}) {
        $self->{parser}->add_test($rule_name, undef, $TYPE_EMPTY_TESTS);
      }
    }
  });

=item tflags SYMBOLIC_TEST_NAME flags

Used to set flags on a test. Parameter is a space-separated list of flag
names or flag name = value pairs.
These flags are used in the score-determination back end system for details
of the test's behaviour.  Please see C<bayes_auto_learn> for more information
about tflag interaction with those systems. The following flags can be set:

=over 4

=item  net

The test is a network test, and will not be run in the mass checking system
or if B<-L> is used, therefore its score should not be modified.

=item  nice

The test is intended to compensate for common false positives, and should be
assigned a negative score.

=item  userconf

The test requires user configuration before it can be used (like
language-specific tests).

=item  learn

The test requires training before it can be used.

=item  noautolearn

The test will explicitly be ignored when calculating the score for
learning systems.

=item  autolearn_force

The test will be subject to less stringent autolearn thresholds.

Normally, SpamAssassin will require 3 points from the header and 3
points from the body to be auto-learned as spam. This option keeps
the threshold at 6 points total but changes it to have no regard to the 
source of the points.

=item  noawl

This flag is specific when using AWL plugin.

Normally, AWL plugin normalizes scores via auto-welcomelist. In some scenarios
it works against the system administrator when trying to add some rules to
correct miss-classified email. When AWL plugin searches the email and finds 
the noawl flag it will exit without normalizing the score nor storing the
value in db.

=item  multiple

The test will be evaluated multiple times, for use with meta rules.
Only affects header, body, rawbody, uri, and full tests.

=item  maxhits=N

If B<multiple> is specified, limit the number of hits found to N.
If the rule is used in a meta that counts the hits (e.g. __RULENAME E<gt> 5),
this is a way to avoid wasted extra work (use "tflags multiple maxhits=6").

For example:

  uri      __KAM_COUNT_URIS /^./
  tflags   __KAM_COUNT_URIS multiple maxhits=16
  describe __KAM_COUNT_URIS A multiple match used to count URIs in a message

  meta __KAM_HAS_0_URIS (__KAM_COUNT_URIS == 0)
  meta __KAM_HAS_1_URIS (__KAM_COUNT_URIS >= 1)
  meta __KAM_HAS_2_URIS (__KAM_COUNT_URIS >= 2)
  meta __KAM_HAS_3_URIS (__KAM_COUNT_URIS >= 3)
  meta __KAM_HAS_4_URIS (__KAM_COUNT_URIS >= 4)
  meta __KAM_HAS_5_URIS (__KAM_COUNT_URIS >= 5)
  meta __KAM_HAS_10_URIS (__KAM_COUNT_URIS >= 10)
  meta __KAM_HAS_15_URIS (__KAM_COUNT_URIS >= 15)

=item  nosubject

Used only for B<body> rules.  If specified, Subject header will not be a
part of the matched body text.  See I<body> for more info.

=item  ips_only

This flag is specific to rules invoking an URIDNSBL plugin,
it is documented there.

=item  domains_only

This flag is specific to rules invoking an URIDNSBL plugin,
it is documented there.

=item  ns

This flag is specific to rules invoking an URIDNSBL plugin,
it is documented there.

=item  a

This flag is specific to rules invoking an URIDNSBL plugin,
it is documented there.

=item  notrim

This flag is specific to rules invoking an URIDNSBL plugin,
it is documented there.

=item nolog

This flag will hide (sensitive) rule informations from reports

=back

=cut

  push (@cmds, {
    setting => 'tflags',
    is_priv => 1,
    type => $CONF_TYPE_HASH_KEY_VALUE,
  });

=item priority SYMBOLIC_TEST_NAME n

Assign a specific priority to a test.  All tests, except for DNS and Meta
tests, are run in increasing priority value order (negative priority values
are run before positive priority values). The default test priority is 0
(zero).

The values C<-99999999999999> and C<-99999999999998> have a special meaning
internally, and should not be used.

=cut

  push (@cmds, {
    setting => 'priority',
    is_priv => 1,
    type => $CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      my ($rulename, $priority) = split(/\s+/, $value, 2);
      unless (defined $priority) {
        return $MISSING_REQUIRED_VALUE;
      }
      unless ($rulename =~ IS_RULENAME) {
        return $INVALID_VALUE;
      }
      unless ($priority =~ /^-?\d+$/) {
        return $INVALID_VALUE;
      }
      $self->{priority}->{$rulename} = $priority;
    }
  });

=back

=head2 CAPTURING TAGS USING REGEX NAMED CAPTURE GROUPS

SpamAssassin 4.0 supports capturing template tags from regex rules.  The
captured tags, along with other standard template tags, can be used in other
rules as a matching string.  See B<TEMPLATE TAGS> section for more info on
tags.

Capturing can be done in any body/rawbody/header/uri/full rule that uses a
regex for matching (not eval rules).  Standard Perl named capture group
format C<(?E<lt>NAMEE<gt>pattern)> must be used, as described in
L<https://perldoc.perl.org/perlre#(?%3CNAME%3Epattern)>.

Example, capturing a tag named C<BODY_HELLO_NAME>:

 body __HELLO_NAME /\bHello, (?<BODY_HELLO_NAME>\w+)\b/

The tag can then be used in another rule for matching, using a %{TAGNAME}
template.  This would search the captured name in From-header:

 header HELLO_NAME_IN_FROM From =~ /\b%{BODY_HELLO_NAME}\b/i

If any tag that a rule depends on is not found, then the rule is not run at
all.  To prevent a literal %{NAME} string from being parsed as a template,
it can be escaped with a backslash: \%{NAME}.

Captured tags can also be used in reports and in other plugins like AskDNS,
with the standard C<_BODY_HELLO_NAME_> notation.

Note that at this time there is no automatic dependency tracking for rule
running order.  All rules that use named capture groups are automatically
set to priority -10000, so that the tags should always be ready for any
normal rules to use.  When rule depends on a tag that might be set at later
stage by a plugin for example, it's priority should be set manually to a
higher value.

=head1 ADMINISTRATOR SETTINGS

These settings differ from the ones above, in that they are considered 'more
privileged' -- even more than the ones in the B<PRIVILEGED SETTINGS> section.
No matter what C<allow_user_rules> is set to, these can never be set from a
user's C<user_prefs> file when spamc/spamd is being used.  However, all
settings can be used by local programs run directly by the user.

=over 4

=item version_tag string

This tag is appended to the SA version in the X-Spam-Status header. You should
include it when you modify your ruleset, especially if you plan to distribute it.
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
      return unless defined $COLLECT_REGRESSION_TESTS;
      my ($self, $key, $value, $line) = @_;
      local ($1,$2,$3);
      if ($value !~ /^(\S+)\s+(ok|fail)\s+(.*)$/) { return $INVALID_VALUE; }
      $self->{parser}->add_regression_test($1, $2, $3);
    }
  });

=item body_part_scan_size               (default: 50000)

Per mime-part scan size limit in bytes for "body" type rules.
The decoded/stripped mime-part is truncated approx to this size.
Helps scanning large messages safely, so it's not necessary to
skip them completely. Disabled with 0.

=cut

  push (@cmds, {
    setting => 'body_part_scan_size',
    is_admin => 1,
    default => 50000,
    type => $CONF_TYPE_NUMERIC,
  });


=item rawbody_part_scan_size               (default: 500000)

Like body_part_scan_size, for "rawbody" type rules.

=cut

  push (@cmds, {
    setting => 'rawbody_part_scan_size',
    is_admin => 1,
    default => 500000,
    type => $CONF_TYPE_NUMERIC,
  });
  
=item rbl_timeout t [t_min] [zone]		(default: 15 3)

All DNS queries are made at the beginning of a check and we try to read
the results at the end.  This value specifies the maximum period of time
(in seconds) to wait for a DNS query.  If most of the DNS queries have
succeeded for a particular message, then SpamAssassin will not wait for
the full period to avoid wasting time on unresponsive server(s), but will
shrink the timeout according to a percentage of queries already completed.
As the number of queries remaining approaches 0, the timeout value will
gradually approach a t_min value, which is an optional second parameter
and defaults to 0.2 * t.  If t is smaller than t_min, the initial timeout
is set to t_min.  Here is a chart of queries remaining versus the timeout
in seconds, for the default 15 second / 3 second timeout setting:

  queries left  100%  90%  80%  70%  60%  50%  40%  30%  20%  10%   0%
  timeout        15   14.9 14.5 13.9 13.1 12.0 10.7  9.1  7.3  5.3  3

For example, if 20 queries are made at the beginning of a message check
and 16 queries have returned (leaving 20%), the remaining 4 queries should
finish within 7.3 seconds since their query started or they will be timed out.
Note that timed out queries are only aborted when there is nothing else left
for SpamAssassin to do - long evaluation of other rules may grant queries
additional time.

If a parameter 'zone' is specified (it must end with a letter, which
distinguishes it from other numeric parametrs), then the setting only
applies to DNS queries against the specified DNS domain (host, domain or
RBL (sub)zone).  Matching is case-insensitive, the actual domain may be a
subdomain of the specified zone.

=cut

  push (@cmds, {
    setting => 'rbl_timeout',
    is_admin => 1,
    default => 15,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
	return $MISSING_REQUIRED_VALUE;
      }
      local ($1,$2,$3);
      unless ($value =~ /^        ( \+? \d+ (?: \. \d*)? [smhdw]? )
                          (?: \s+ ( \+? \d+ (?: \. \d*)? [smhdw]? ) )?
                          (?: \s+ (\S* [a-zA-Z]) )? $/xsi) {
	return $INVALID_VALUE;
      }
      my($timeout, $timeout_min, $zone) = ($1, $2, $3);
      foreach ($timeout, $timeout_min) {
        if (defined $_ && s/\s*([smhdw])\z//i) {
          $_ *= { s => 1, m => 60, h => 3600,
                  d => 24*3600, w => 7*24*3600 }->{lc $1};
        }
      }
      if (!defined $zone) {  # a global setting
        $self->{rbl_timeout}     = 0 + $timeout;
        $self->{rbl_timeout_min} = 0 + $timeout_min  if defined $timeout_min;
      }
      else {  # per-zone settings
        $zone =~ s/^\.//;  $zone =~ s/\.\z//;  # strip leading and trailing dot
        $zone = lc $zone;
        $self->{by_zone}{$zone}{rbl_timeout} = 0 + $timeout;
        $self->{by_zone}{$zone}{rbl_timeout_min} =
                                     0 + $timeout_min  if defined $timeout_min;
      }
    },
    type => $CONF_TYPE_DURATION,
  });

=item util_rb_tld tld1 tld2 ...

=encoding utf8

This option maintains a list of valid TLDs in the RegistryBoundaries code. 
Top level domains (TLD) include things like com, net, org, xn--p1ai, рф, ...
International domain names may be specified in ASCII-compatible encoding (ACE),
e.g. xn--p1ai, xn--qxam, or with Unicode labels encoded as UTF-8 octets,
e.g. рф, ελ.

=cut

  push (@cmds, {
    setting => 'util_rb_tld',
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
	return $MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^[^\s.]+(?:\s+[^\s.]+)*$/) {
	return $INVALID_VALUE;
      }
      foreach (split(/\s+/, $value)) {
        $self->{valid_tlds}{idn_to_ascii($_)} = 1;
      }
    }
  });

=item util_rb_2tld 2tld-1.tld 2tld-2.tld ...

This option maintains list of valid 2nd-level TLDs in the RegistryBoundaries
code.  2TLDs include things like co.uk, fed.us, etc.  International domain
names may be specified in ASCII-compatible encoding (ACE), or with Unicode
labels encoded as UTF-8 octets.

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
        $self->{two_level_domains}{idn_to_ascii($_)} = 1;
      }
    }
  });

=item util_rb_3tld 3tld1.some.tld 3tld2.other.tld ...

This option maintains list of valid 3rd-level TLDs in the RegistryBoundaries
code.  3TLDs include things like demon.co.uk, plc.co.im, etc.  International
domain names may be specified in ASCII-compatible encoding (ACE), or with
Unicode labels encoded as UTF-8 octets.

=cut

  push (@cmds, {
    setting => 'util_rb_3tld',
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
	return $MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^[^\s.]+\.[^\s.]+\.[^\s.]+(?:\s+[^\s.]+\.[^\s.]+\.[^\s.]+)*$/) {
	return $INVALID_VALUE;
      }
      foreach (split(/\s+/, $value)) {
        $self->{three_level_domains}{idn_to_ascii($_)} = 1;
      }
    }
  });

=item clear_util_rb

Empty internal list of valid TLDs (including 2nd and 3rd level) which
RegistryBoundaries code uses.  Only useful if you want to override the
standard lists supplied by sa-update.

=cut

  push (@cmds, {
    setting => 'clear_util_rb',
    type => $CONF_TYPE_NOARGS,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (!defined $value || $value eq '') {
        return $INVALID_VALUE;
      }
      undef $self->{valid_tlds};
      undef $self->{two_level_domains};
      undef $self->{three_level_domains};
      dbg("config: cleared tld lists");
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
    type => $CONF_TYPE_STRING,
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
not have any execute bits set (the umask is set to 111). The argument is a
string of octal digits, it is converted to a numeric value internally.

=cut

  push (@cmds, {
    setting => 'bayes_file_mode',
    is_admin => 1,
    default => '0700',
    type => $CONF_TYPE_NUMERIC,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value !~ /^0?[0-7]{3}$/) { return $INVALID_VALUE; }
      $value = '0'.$value if length($value) == 3; # Bug 5771
      $self->{bayes_file_mode} = untaint_var($value);
    }
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
    type => $CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local ($1);
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
    type => $CONF_TYPE_STRING,
  });

=item bayes_sql_username

Used by BayesStore::SQL storage implementation.

This option gives the username used by the above DSN.

=cut

  push (@cmds, {
    setting => 'bayes_sql_username',
    is_admin => 1,
    default => '',
    type => $CONF_TYPE_STRING,
  });

=item bayes_sql_password

Used by BayesStore::SQL storage implementation.

This option gives the password used by the above DSN.

=cut

  push (@cmds, {
    setting => 'bayes_sql_password',
    is_admin => 1,
    default => '',
    type => $CONF_TYPE_STRING,
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
    type => $CONF_TYPE_BOOL,
  });

=item user_scores_dsn DBI:databasetype:databasename:hostname:port

If you load user scores from an SQL database, this will set the DSN
used to connect.  Example: C<DBI:mysql:spamassassin:localhost>

If you load user scores from an LDAP directory, this will set the DSN used to
connect. You have to write the DSN as an LDAP URL, the components being the
host and port to connect to, the base DN for the search, the scope of the
search (base, one or sub), the single attribute being the multivalued attribute
used to hold the configuration data (space separated pairs of key and value,
just as in a file) and finally the filter being the expression used to filter
out the wanted username. Note that the filter expression is being used in a
sprintf statement with the username as the only parameter, thus is can hold a
single __USERNAME__ expression. This will be replaced with the username.

Example: C<ldap://localhost:389/dc=koehntopp,dc=de?saconfig?uid=__USERNAME__>

=cut

  push (@cmds, {
    setting => 'user_scores_dsn',
    is_admin => 1,
    default => '',
    type => $CONF_TYPE_STRING,
  });

=item user_scores_sql_username username

The authorized username to connect to the above DSN.

=cut

  push (@cmds, {
    setting => 'user_scores_sql_username',
    is_admin => 1,
    default => '',
    type => $CONF_TYPE_STRING,
  });

=item user_scores_sql_password password

The password for the database username, for the above DSN.

=cut

  push (@cmds, {
    setting => 'user_scores_sql_password',
    is_admin => 1,
    default => '',
    type => $CONF_TYPE_STRING,
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

The query must be one continuous line in order to parse correctly.

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
    default => undef,
    type => $CONF_TYPE_STRING,
  });

=item user_scores_ldap_username

This is the Bind DN used to connect to the LDAP server.  It defaults
to the empty string (""), allowing anonymous binding to work.

Example: C<cn=master,dc=koehntopp,dc=de>

=cut

  push (@cmds, {
    setting => 'user_scores_ldap_username',
    is_admin => 1,
    default => '',
    type => $CONF_TYPE_STRING,
  });

=item user_scores_ldap_password

This is the password used to connect to the LDAP server.  It defaults
to the empty string ("").

=cut

  push (@cmds, {
    setting => 'user_scores_ldap_password',
    is_admin => 1,
    default => '',
    type => $CONF_TYPE_STRING,
  });

=item user_scores_fallback_to_global        (default: 1)

Fall back to global scores and settings if userprefs can't be loaded
from SQL or LDAP, instead of passing the message through unprocessed.

=cut

  push (@cmds, {
    setting => 'user_scores_fallback_to_global',
    is_admin => 1,
    default => 1,
    type => $CONF_TYPE_BOOL,
  });

=item loadplugin [Mail::SpamAssassin::Plugin::]ModuleName [/path/module.pm]

Load a SpamAssassin plugin module.  The C<ModuleName> is the perl module
name, used to create the plugin object itself.

Module naming is strict, name must only contain alphanumeric characters or
underscores.  File must have .pm extension.

C</path/module.pm> is the file to load, containing the module's perl code;
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
      my ($package, $path);
      local ($1,$2);
      if ($value =~ /^((?:\w+::){0,10}\w+)(?:\s+(\S+\.pm))?$/i) {
        ($package, $path) = ($1, $2);
      } else {
	return $INVALID_VALUE;
      }
      # trunk Dmarc.pm was renamed to DMARC.pm
      # (same check also in Conf/Parser.pm handle_conditional)
      if ($package eq 'Mail::SpamAssassin::Plugin::Dmarc') {
        $package = 'Mail::SpamAssassin::Plugin::DMARC';
      }
      # backwards compatible - removed in 4.1
      # (same check also in Conf/Parser.pm handle_conditional)
      elsif ($package eq 'Mail::SpamAssassin::Plugin::WhiteListSubject') {
        $package = 'Mail::SpamAssassin::Plugin::WelcomeListSubject';
      }
      $self->load_plugin ($package, $path);
    }
  });

=item tryplugin ModuleName [/path/module.pm]

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
      my ($package, $path);
      local ($1,$2);
      if ($value =~ /^((?:\w+::){0,10}\w+)(?:\s+(\S+\.pm))?$/i) {
        ($package, $path) = ($1, $2);
      } else {
	return $INVALID_VALUE;
      }
      $self->load_plugin ($package, $path, 1);
    }
  });

=item ignore_always_matching_regexps         (Default: 0)

Ignore any rule which contains a regexp which always matches.
Currently only catches regexps which contain '||', or which begin or
end with a '|'.  Also ignore rules with C<some> combinatorial explosions.

=cut

  push (@cmds, {
    setting  => 'ignore_always_matching_regexps',
    is_admin => 1,
    default  => 0,
    type     => $CONF_TYPE_BOOL,
  });

=item geodb_module STRING

This option tells SpamAssassin which geolocation module to use. 
If not specified, all supported ones are tried in this order:

Plugins can override this internally if required.

 MaxMind::DB::Reader  (same as GeoIP2::Database::Reader)
 Geo::IP
 IP::Country::DB_File  (not used unless geodb_options path set)
 IP::Country::Fast

=cut

  push (@cmds, {
    setting => 'geodb_module',
    is_admin => 1,
    default => undef,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      $value = lc $value;
      if ($value eq 'maxmind::db::reader' ||
            $value eq 'geoip2::database::reader' || $value eq 'geoip2') {
        $self->{geodb}->{module} = 'geoip2';
      } elsif ($value eq 'geo::ip' || $value eq 'geoip') {
        $self->{geodb}->{module} = 'geoip';
      } elsif ($value eq 'ip::country::db_file' || $value eq 'db_file') {
        $self->{geodb}->{module} = 'dbfile';
      } elsif ($value eq 'ip::country::fast' || $value eq 'fast') {
        $self->{geodb}->{module} = 'fast';
      } else {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
    }
  });

  # support deprecated RelayCountry setting
  push (@cmds, {
    setting => 'country_db_type',
    is_admin => 1,
    default => undef,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      warn("config: deprecated setting used, change country_db_type to geodb_module\n");
      if ($value =~ /GeoIP2/i) {
        $self->{geodb}->{module} = 'geoip2';
      } elsif ($value =~ /Geo/i) {
        $self->{geodb}->{module} = 'geoip';
      } elsif ($value =~ /Fast/i) {
        $self->{geodb}->{module} = 'fast';
      } else {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
    }
  });

=item geodb_options dbtype:/path/to/db ...

Supported dbtypes:

I<city> - use City database
I<country> - use Country database
I<isp> - try loading ISP database
I<asn> - try loading ASN database

Append full database path with colon, for example:
I<isp:/opt/geoip/isp.mmdb>

Plugins can internally request all types they require, geodb_options is only
needed if the default location search (described below) does not work.

GeoIP/GeoIP2 searches these files/directories:

 country:
   GeoIP2-Country.mmdb, GeoLite2-Country.mmdb
   GeoIP.dat (and v6 version)
 city:
   GeoIP2-City.mmdb, GeoLite2-City.mmdb
   GeoIPCity.dat, GeoLiteCity.dat (and v6 versions)
 isp:
   GeoIP2-ISP.mmdb
   GeoIPISP.dat, GeoLiteISP.dat (and v6 versions)
 directories:
   /usr/local/share/GeoIP
   /usr/share/GeoIP
   /var/lib/GeoIP
   /opt/share/GeoIP

=cut

  push (@cmds, {
    setting => 'geodb_options',
    is_admin => 1,
    type => $CONF_TYPE_HASH_KEY_VALUE,
    default => {},
    code => sub {
      my ($self, $key, $value, $line) = @_;
      foreach my $option (split (/\s+/, $value)) {
        my ($option, $db) = split(/:/, $option, 2);
        $option = lc($option);
        if ($option eq 'reset') {
          $self->{geodb}->{options} = {};
        } elsif ($option eq 'country') {
          $self->{geodb}->{options}->{country} = $db || undef;
        } elsif ($option eq 'city') {
          $self->{geodb}->{options}->{city} = $db || undef;
        } elsif ($option eq 'isp') {
          $self->{geodb}->{options}->{isp} = $db || undef;
        } else {
          return $INVALID_VALUE;
        }
      }
    }
  });

=item geodb_search_path /path/to/GeoIP ...

Alternative to geodb_options. Overrides the default list of directories to
search for default filenames.

=cut

  push (@cmds, {
    setting => 'geodb_search_path',
    is_admin => 1,
    default => [],
    type => $CONF_TYPE_STRINGLIST,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq 'reset') {
        $self->{geodb}->{geodb_search_path} = [];
      } elsif ($value eq '') {
        return $MISSING_REQUIRED_VALUE;
      } else {
        push(@{$self->{geodb}->{geodb_search_path}}, split(/\s+/, $value));
      }
    }
  });

  # support deprecated RelayCountry setting
  push (@cmds, {
    setting => 'country_db_path',
    is_admin => 1,
    default => undef,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      warn("config: deprecated setting used, change country_db_path to geodb_options\n");
      if ($value ne '') {
        $self->{geodb}->{options}->{country} = $value;
      } else {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
    }
  });
  # support deprecated URILocalBL setting
  push (@cmds, {
    setting => 'uri_country_db_path',
    is_admin => 1,
    default => undef,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      warn("config: deprecated setting used, change uri_country_db_path to geodb_options\n");
      if ($value ne '') {
        $self->{geodb}->{options}->{country} = $value;
      } else {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
    }
  });
  # support deprecated URILocalBL setting
  push (@cmds, {
    setting => 'uri_country_db_isp_path',
    is_admin => 1,
    default => undef,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      warn("config: deprecated setting used, change uri_country_db_isp_path to geodb_options\n");
      if ($value ne '') {
        $self->{geodb}->{options}->{isp} = $value;
      } else {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
    }
  });

=back

=head1 PREPROCESSING OPTIONS

=over 4

=item include filename

Include configuration lines from C<filename>.   Relative paths are considered
relative to the current configuration file or user preferences file.

=item if (boolean perl expression)

Used to support conditional interpretation of the configuration
file. Lines between this and a corresponding C<else> or C<endif> line
will be ignored unless the expression evaluates as true
(in the perl sense; that is, defined and non-0 and non-empty string).

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
version, and z is maintenance version.  So 3.0.0 is C<3.000000>, and 3.4.80
is C<3.004080>.

=item perl_version

(Introduced in 3.4.1)  This will be replaced with the version number of the
currently-running perl engine.  Note: The version used is in the $] version
format which is C<x.yyyzzz>, where x is major version, y is minor version,
and z is maintenance version.  So 5.8.8 is C<5.008008>, and 5.10.0 is
C<5.010000>. Use to protect rules that incorporate RE syntax elements
introduced in later versions of perl, such as the C<++> non-backtracking
match introduced in perl 5.10. For example:

  # Avoid lint error on older perl installs
  # Check SA version first to avoid warnings on checking perl_version on older SA
  if version > 3.004001 && perl_version >= 5.018000
    body  INVALID_RE_SYNTAX_IN_PERL_BEFORE_5_18  /(?[ \p{Thai} & \p{Digit} ])/
  endif

Note that the above will still generate a warning on perl older than 5.10.0;
to avoid that warning do this instead:

  # Avoid lint error on older perl installs
  if can(Mail::SpamAssassin::Conf::perl_min_version_5010000)
    body  INVALID_RE_SYNTAX_IN_PERL_5_8  /\w++/
  endif

Warning: a can() test is only defined for perl 5.10.0!


=item plugin(Name::Of::Plugin)

This is a function call that returns C<1> if the plugin named
C<Name::Of::Plugin> is loaded, or C<undef> otherwise.

=item has(Name::Of::Package::function_name)

This is a function call that returns C<1> if the perl package named
C<Name::Of::Package> includes a function called C<function_name>, or C<undef>
otherwise.  Note that packages can be SpamAssassin plugins or built-in classes,
there's no difference in this respect.  Internally this invokes UNIVERSAL::can.

=item can(Name::Of::Package::function_name)

This is a function call that returns C<1> if the perl package named
C<Name::Of::Package> includes a function called C<function_name>
B<and> that function returns a true value when called with no arguments,
otherwise C<undef> is returned.

Is similar to C<has>, except that it also calls the named function,
testing its return value (unlike the perl function UNIVERSAL::can).
This makes it possible for a 'feature' function to determine its result
value at run time.

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
(in the perl sense; that is, not defined and not 0 and non-empty string).

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
    type => $CONF_TYPE_STRING,
    code => sub {
    }
  });

=item enable_compat xxxxxx

Define a version compatibility flag.

This creates a function named C<Mail::SpamAssassin::Conf::compat_xxxxxx>,
which returns true.  It can be used for example in cf-files, similarly as existing
C<feature_> checks:

  if can(Mail::SpamAssassin::Conf::compat_xxxxxx)

Name can only consist of [a-zA-Z0-9_] characters.

Mainly used by SpamAssassin distribution to handle backwards compatibility
issues.

=cut

  push (@cmds, {
    setting => 'enable_compat',
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $MISSING_REQUIRED_VALUE;
      } elsif ($value !~ /^[a-zA-Z0-9_]{1,128}$/) {
        return $INVALID_VALUE;
      }
      dbg("config: enabling compatibility flag $value");
      # Inject compat method
      { no strict 'refs';
        *{"Mail::SpamAssassin::Conf::compat_$value"} = sub { 1 };
      }
    }
  });

=back

=head1 TEMPLATE TAGS

The following C<tags> can be used as placeholders in certain options.
They will be replaced by the corresponding value when they are used.

Some tags can take an argument (in parentheses). The argument is
optional, and the default is shown below.

 _YESNO_           "Yes" for spam, "No" for nonspam (=ham)
 _YESNO(spam_str,ham_str)_  returns the first argument ("Yes" if missing)
                   for spam, and the second argument ("No" if missing) for ham
 _YESNOCAPS_       "YES" for spam, "NO" for nonspam (=ham)
 _YESNOCAPS(spam_str,ham_str)_  same as _YESNO(...)_, but uppercased
 _SCORE(PAD)_      message score, if PAD is included and is either spaces or
                   zeroes, then pad scores with that many spaces or zeroes
		   (default, none)  ie: _SCORE(0)_ makes 2.4 become 02.4,
		   _SCORE(00)_ is 002.4.  12.3 would be 12.3 and 012.3
		   respectively.
 _REQD_            message threshold
 _VERSION_         version (eg. 3.0.0 or 3.1.0-r26142-foo1)
 _SUBVERSION_      sub-version/code revision date (eg. 2004-01-10)
 _RULESVERSION_    comma-separated list of rules versions, retrieved from
                   an '# UPDATE version' comment in rules files; if there is
                   more than one set of rules (update channels) the order
                   is unspecified (currently sorted by names of files);
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
 _SENDERDOMAIN_    a domain name of the envelope sender address, lowercased
 _AUTHORDOMAIN_    a domain name of the author address (the From header
                   field), lowercased;  note that RFC 5322 allows a mail
                   message to have multiple authors - currently only the
                   domain name of the first email address is returned
 _RELAYSTRUSTED_   relays used and deemed to be trusted (see the 
                   'X-Spam-Relays-Trusted' pseudo-header)
 _RELAYSUNTRUSTED_ relays used that can not be trusted (see the 
                   'X-Spam-Relays-Untrusted' pseudo-header)
 _RELAYSINTERNAL_  relays used and deemed to be internal (see the 
                   'X-Spam-Relays-Internal' pseudo-header)
 _RELAYSEXTERNAL_  relays used and deemed to be external (see the 
                   'X-Spam-Relays-External' pseudo-header)
 _FIRSTTRUSTEDIP_  IP address of first trusted client (see RELAYSTRUSTED)
 _FIRSTTRUSTEDREVIP_  IP address of first trusted client (in reversed
                   format suitable for RBL queries)
 _LASTEXTERNALIP_  IP address of client in the external-to-internal
                   SMTP handover
 _LASTEXTERNALREVIP_  IP address of client in the external-to-internal
                   SMTP handover (in reversed format suitable for RBL
                   queries)
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
 _SUBTESTSCOLLAPSED(,)_ subtests (start with "__") hit separated by ","
                   (or other separator) with duplicated rules collapsed
 _DCCB_            DCC's "Brand"
 _DCCR_            DCC's results
 _PYZOR_           Pyzor results
 _RBL_             full results for positive RBL queries in DNS URI format
 _LANGUAGES_       possible languages of mail
 _PREVIEW_         content preview
 _REPORT_          terse report of tests hit (for header reports)
 _SUBJPREFIX_      subject prefix based on rules, to be prepended to Subject
                   header by SpamAssassin caller
 _SUMMARY_         summary of tests hit for standard report (for body reports)
 _CONTACTADDRESS_  contents of the 'report_contact' setting
 _HEADER(NAME)_    includes the value of a message header.  value is the same
                   as is found for header rules (see elsewhere in this doc)
 _TIMING_          timing breakdown report
 _ADDEDHEADERHAM_  resulting header fields as requested by add_header for spam
 _ADDEDHEADERSPAM_ resulting header fields as requested by add_header for ham
 _ADDEDHEADER_     same as ADDEDHEADERHAM for ham or ADDEDHEADERSPAM for spam

If a tag reference uses the name of a tag which is not in this list or defined
by a loaded plugin, the reference will be left intact and not replaced by any
value.

All template tag names must consist of only uppercase character set
[A-Z0-9_] and not contain consecutive underscores (__).

Additional, plugin specific, template tags can be found in the documentation for
the following plugins:

 L<Mail::SpamAssassin::Plugin::ASN>
 L<Mail::SpamAssassin::Plugin::AWL>
 L<Mail::SpamAssassin::Plugin::TxRep>

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

=back

=cut

  return \@cmds;
}

###########################################################################

# settings that were once part of core, but are now in (possibly-optional)
# bundled plugins. These will be warned about, but do not generate a fatal
# error when "spamassassin --lint" is run like a normal syntax error would.

our @MIGRATED_SETTINGS = qw{
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
  # NOTE: Deprecated usage of TieOneStringHash as of 10/2018, it's an
  # absolute pig, doubling config parsing time, while benchmarks indicate
  # no difference in resident memory size!
  $self->{descriptions} = { };
  #tie %{$self->{descriptions}}, 'Mail::SpamAssassin::Util::TieOneStringHash'
  #  or warn "tie failed";
  $self->{subjprefix} = { };

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
  $self->{eval_plugins_types} = { };

  # meta dependencies
  $self->{meta_dependencies} = {};
  $self->{meta_deprules} = {};
  $self->{meta_nodeps} = {};

  # map eval function names to rulenames
  $self->{eval_to_rule} = {};

  # regex capture template rules
  $self->{capture_rules} = {};
  $self->{capture_template_rules} = {};

  # testing stuff
  $self->{regression_tests} = { };

  $self->{rewrite_header} = { };
  $self->{want_rebuild_for_type} = { };
  $self->{user_defined_rules} = { };
  $self->{headers_spam} = [ ];
  $self->{headers_ham} = [ ];

  $self->{bayes_ignore_header} = { };
  $self->{bayes_ignore_from} = { };
  $self->{bayes_ignore_to} = { };

  $self->{welcomelist_auth} = { };
  $self->{def_welcomelist_auth} = { };
  $self->{welcomelist_from} = { };
  $self->{welcomelist_allows_relays} = { };
  $self->{welcomelist_from_rcvd} = { };
  $self->{def_welcomelist_from_rcvd} = { };

  $self->{blocklist_to} = { };
  $self->{welcomelist_to} = { };
  $self->{more_spam_to} = { };
  $self->{all_spam_to} = { };

  $self->{trusted_networks} = $self->new_netset('trusted_networks',1);
  $self->{internal_networks} = $self->new_netset('internal_networks',1);
  $self->{msa_networks} = $self->new_netset('msa_networks',0); # no loopback IP
  $self->{trusted_networks_configured} = 0;
  $self->{internal_networks_configured} = 0;

  # Make sure we add in X-Spam-Checker-Version
  { my $r = [ "Checker-Version",
              "SpamAssassin _VERSION_ (_SUBVERSION_) on _HOSTNAME_" ];
    push(@{$self->{headers_spam}}, $r);
    push(@{$self->{headers_ham}},  $r);
  }

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
  $self->{parser}->parse ($_[1], 1);
}

sub parse_rules {
  my ($self) = @_;
  $self->{parser}->parse ($_[1], 0);
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
    return @{$self->{$test_type}->{$rulename}};
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
    return;  # if we get here we didn't find the rule
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
    return;  # if we get here we didn't find the rule
  }
}

# trim_rules ($regexp)
#
# Remove all rules that don't match the given regexp (or are sub-rules of
# meta-tests that match the regexp).

sub trim_rules {
  my ($self, $regexp) = @_;

  my ($rec, $err) = compile_regexp($regexp, 0);
  if (!$rec) {
    die "config: trim_rules: invalid regexp '$regexp': $err";
  }

  my @all_rules;

  foreach my $rule_type ($self->get_rule_types()) {
    push(@all_rules, $self->get_rule_keys($rule_type));
  }

  my @rules_to_keep = grep(/$rec/o, @all_rules);

  if (@rules_to_keep == 0) {
    die "config: trim_rules: all rules excluded, nothing to test\n";
  }

  my @meta_tests    = grep(/$rec/o, $self->get_rule_keys('meta_tests'));
  foreach my $meta (@meta_tests) {
    push(@rules_to_keep, $self->add_meta_depends($meta))
  }

  my %rules_to_keep_hash;

  foreach my $rule (@rules_to_keep) {
    $rules_to_keep_hash{$rule} = 1;
  }

  foreach my $rule_type ($self->get_rule_types()) {
    foreach my $rulekey ($self->get_rule_keys($rule_type)) {
      $self->delete_rule($rule_type, $rulekey)
                    if (!$rules_to_keep_hash{$rulekey});
    }
  }
} # trim_rules()

sub add_meta_depends {
  my ($self, $meta) = @_;

  my @rules;
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

# treats a bitset argument as a bit vector of all possible port numbers (8 kB)
# and sets bit values to $value (0 or 1) in the specified range of port numbers
#
sub set_ports_range {
  my($bitset_ref, $port_range_lo, $port_range_hi, $value) = @_;
  $port_range_lo = 0      if $port_range_lo < 0;
  $port_range_hi = 65535  if $port_range_hi > 65535;
  if (!defined $$bitset_ref) {  # provide a sensible default
    wipe_ports_range($bitset_ref, 1);  # turn on all bits 0..65535
    vec($$bitset_ref,$_,1) = 0  for 0..1023;  # avoid 0 and privileged ports
  } elsif ($$bitset_ref eq '') {  # repopulate the bitset (late configuration)
    wipe_ports_range($bitset_ref, 0);  # turn off all bits 0..65535
  }
  $value = !$value ? 0 : 1;
  for (my $j = $port_range_lo; $j <= $port_range_hi; $j++) {
    vec($$bitset_ref,$j,1) = $value;
  }
}

sub wipe_ports_range {
  my($bitset_ref, $value) = @_;
  $value = !$value ? "\000" : "\377";
  $$bitset_ref = $value x 8192;  # quickly turn all bits 0..65535 on or off
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
  my ($self, $user) = @_;
  $self->{parser}->finish_parsing($user);
}

###########################################################################

sub found_any_rules {
  my ($self) = @_;
  if (!defined $self->{found_any_rules}) {
    $self->{found_any_rules} = (scalar keys %{$self->{tests}} > 0);
  }
  return $self->{found_any_rules};
}

###########################################################################

sub get_description_for_rule {
  my ($self, $rule) = @_;
  # as silly as it looks, localized $1 here prevents an outer $1 from getting
  # tainted by the expression or assignment in the next line, bug 6148
  local($1);
  my $rule_descr = $self->{descriptions}->{$rule};
  return $rule_descr;
}

###########################################################################

# Deprecated since Bug 7905/7906
sub maybe_header_only { warn "Deprecated Conf::maybe_header_only() called"; }
sub maybe_body_only { warn "Deprecated Conf::maybe_body_only() called"; }

###########################################################################

sub load_plugin {
  my ($self, $package, $path, $silent) = @_;
  $self->{main}->{plugins}->load_plugin($package, $path, $silent);
}

sub load_plugin_succeeded {
  my ($self, $plugin, $package, $path) = @_;
  $self->{plugins_loaded}->{$package} = 1;
}

sub register_eval_rule {
  my ($self, $pluginobj, $nameofsub, $ruletype) = @_;
  if (exists $self->{eval_plugins}->{$nameofsub}) {
    warn("config: eval function '$nameofsub' already exists, overwriting\n");
  }
  $self->{eval_plugins}->{$nameofsub} = $pluginobj;
  if (defined $ruletype) {
    if (defined $TYPE_AS_STRING{$ruletype}) {
      $self->{eval_plugins_types}->{$nameofsub} = $ruletype;
    } else {
      $self->{parser}->lint_warn("config: invalid ruletype for eval $nameofsub");
    }
  }
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

  my %done;

  # keys that should not be copied in ->clone().
  # bug 4179: include want_rebuild_for_type, so that if a user rule
  # is defined, its method will be recompiled for future scans in
  # order to *remove* the generated method calls
  my @NON_COPIED_KEYS = qw(
    main eval_plugins eval_plugins_types plugins_loaded registered_commands
    sed_path_cache parser scoreset scores want_rebuild_for_type
  );

  # special cases.  first, skip anything that cannot be changed
  # by users, and the stuff we take care of here
  foreach my $var (@NON_COPIED_KEYS) {
    $done{$var} = undef;
  }

  # keys that should can be copied using a ->clone() method, in ->clone()
  my @CLONABLE_KEYS = qw(
    internal_networks trusted_networks msa_networks 
  );

  foreach my $key (@CLONABLE_KEYS) {
    $dest->{$key} = $source->{$key}->clone();
    $done{$key} = undef;
  }

  # two-level hashes
  foreach my $key (qw(uri_host_lists askdns)) {
    my $v = $source->{$key};
    my $dest_key_ref = $dest->{$key} = {};  # must start from scratch!
    while(my($k2,$v2) = each %{$v}) {
      %{$dest_key_ref->{$k2}} = %{$v2};
    }
    $done{$key} = undef;
  }

  # bug 4179: be smarter about cloning the rule-type structures;
  # some are like this: $self->{type}->{priority}->{name} = 'value';
  # which is an extra level that the below code won't deal with
  foreach my $t (@rule_types) {
    foreach my $k (keys %{$source->{$t}}) {
      my $v = $source->{$t}->{$k};
      my $i = ref $v;
      if ($i eq 'HASH') {
        %{$dest->{$t}->{$k}} = %{$v};
      }
      elsif ($i eq 'ARRAY') {
        @{$dest->{$t}->{$k}} = @{$v};
      }
      else {
        $dest->{$t}->{$k} = $v;
      }
    }
    $done{$t} = undef;
  }

  # and now, copy over all the rest -- the less complex cases.
  while(my($k,$v) = each %{$source}) {
    next if exists $done{$k};   # we handled it above
    $done{$k} = undef;
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
    elsif ($i eq 'Regexp') {
      $dest->{$k} = $v;
    }
    else {
      # throw a warning for debugging -- should never happen in normal usage
      warn "config: dup unknown type $k, $i\n";
    }
  }

  foreach my $cmd (@{$self->{registered_commands}}) {
    my $k = $cmd->{setting};
    next if exists $done{$k};   # we handled it above
    $done{$k} = undef;
    $dest->{$k} = $source->{$k};
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
    #delete $self->{if_stack}; # it's Parser not Conf?
    #delete $self->{source_file};
  }
}

sub new_netset {
  my ($self, $netset_name, $add_loopback) = @_;
  my $set = Mail::SpamAssassin::NetSet->new($netset_name);
  if ($add_loopback) {
    $set->add_cidr('127.0.0.0/8');
    $set->add_cidr('::1');
  }
  return $set;
}

###########################################################################

sub finish {
  my ($self) = @_;
  #untie %{$self->{descriptions}};
  %{$self} = ();
}

###########################################################################

sub sa_die { Mail::SpamAssassin::sa_die(@_); }

###########################################################################

# subroutines available to conditionalize rules, for example:
#   if (can(Mail::SpamAssassin::Conf::feature_originating_ip_headers))

sub feature_originating_ip_headers { 1 }
sub feature_dns_local_ports_permit_avoid { 1 }
sub feature_bayes_auto_learn_on_error { 1 }
sub feature_uri_host_listed { 1 }
sub feature_yesno_takes_args { 1 }
sub feature_bug6558_free { 1 }
sub feature_edns { 1 }  # supports 'dns_options edns' config option
sub feature_dns_query_restriction { 1 }  # supported config option
sub feature_registryboundaries { 1 } # replaces deprecated registrarboundaries
sub feature_geodb { 1 } # if needed for some reason
sub feature_dns_block_rule { 1 } # supports 'dns_block_rule' config option
sub feature_compile_regexp { 1 } # Util::compile_regexp
sub feature_meta_rules_matching { 1 } # meta rules_matching() expression
sub feature_subjprefix { 1 } # add subject prefixes rule option
sub feature_bayes_stopwords { 1 } # multi language stopwords in Bayes
sub feature_get_host { 1 } # $pms->get() :host :domain :ip :revip # was implemented together with AskDNS::has_tag_header # Bug 7734
sub feature_blocklist_welcomelist { 1 } # bz 7826 - do not use, for backwards compatibility
sub feature_welcomelist_blocklist { 1 } # bz 7826 - this is the actual feature_ to use, everything is renamed at this point
sub feature_header_address_parser { 1 } # improved header address parsing using Email::Address::XS, $pms->get() list context
sub feature_local_tests_only { 1 } # Config parser supports "if (local_tests_only)"
sub feature_header_first_last { 1 } # Can actually use :first :last modifiers in rules
sub feature_header_match_many { 1 } # Can actually match all :addr :name etc results, before only first one was used
sub feature_capture_rules { 1 } # Can capture and use tags with regex in body/rawbody/full/uri/header rules # Bug 7992
sub has_tflags_nosubject { 1 } # tflags nosubject
sub has_tflags_nolog { 1 } # tflags nolog
sub perl_min_version_5010000 { return $] >= 5.010000 }  # perl version check ("perl_version" not neatly backwards-compatible)

###########################################################################

1;
__END__

=head1 LOCALISATION

A line starting with the text C<lang xx> will only be interpreted if
SpamAssassin is running in that locale, allowing test descriptions and
templates to be set for that language.

Current locale is determined from LANGUAGE, LC_ALL, LC_MESSAGES or LANG
environment variables, first found is used.

The locales string should specify either both the language and country, e.g.
C<lang pt_BR>, or just the language, e.g. C<lang de>.

Example:

 lang de describe EXAMPLE_RULE Beispielregel

=head1 SEE ALSO

Mail::SpamAssassin(3)
spamassassin(1)
spamd(1)

=cut
