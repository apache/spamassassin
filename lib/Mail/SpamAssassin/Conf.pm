=head1 NAME

Mail::SpamAssassin::Conf - SpamAssassin configuration file

=head1 SYNOPSIS

  # a comment

  rewrite_subject                 1

  full PARA_A_2_C_OF_1618         /Paragraph .a.{0,10}2.{0,10}C. of S. 1618/i
  describe PARA_A_2_C_OF_1618     Claims compliance with senate bill 1618

  header FROM_HAS_MIXED_NUMS      From =~ /\d+[a-z]+\d+\S*@/i
  describe FROM_HAS_MIXED_NUMS    From: contains numbers mixed in with letters

  score A_HREF_TO_REMOVE          2.0

  lang es describe FROM_FORGED_HOTMAIL Forzado From: simula ser de hotmail.com

=head1 DESCRIPTION

SpamAssassin is configured using some traditional UNIX-style configuration
files, loaded from the /usr/share/spamassassin and /etc/mail/spamassassin
directories.

The C<#> character starts a comment, which continues until end of line,
and whitespace in the files is not significant.

Paths can use C<~> to refer to the user's home directory.

Where appropriate, default values are listed in parentheses.

=head1 USER PREFERENCES

=over 4

=cut

package Mail::SpamAssassin::Conf;

use Carp;
use strict;

use vars	qw{
  	@ISA $type_body_tests $type_head_tests $type_head_evals
	$type_body_evals $type_full_tests $type_full_evals
	$type_rawbody_tests $type_rawbody_evals
    $type_uri_tests $type_uri_evals
};

@ISA = qw();

$type_head_tests = 101;
$type_head_evals = 102;
$type_body_tests = 103;
$type_body_evals = 104;
$type_full_tests = 105;
$type_full_evals = 106;
$type_rawbody_tests = 107;
$type_rawbody_evals = 108;
$type_uri_tests  = 109;
$type_uri_evals  = 110;

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my $self = { }; bless ($self, $class);

  my $main = shift;     # do not add to class, avoid circular ref

  $self->{tests} = { };
  $self->{descriptions} = { };
  $self->{test_types} = { };
  $self->{scores} = { };

  # after parsing, tests are refiled into these hashes for each test type.
  # this allows e.g. a full-text test to be rewritten as a body test in
  # the user's ~/.spamassassin.cf file.
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

  # testing stuff
  $self->{regression_tests} = { };

  $self->{required_hits} = 5.0;
  $self->{auto_report_threshold} = 25.0;
  $self->{report_template} = '';
  $self->{terse_report_template} = '';
  $self->{spamtrap_template} = '';

  $self->{razor_config} = $main->sed_path ("~/razor.conf");

  # this will be sedded by whitelist implementations, so ~ is OK
  $self->{auto_whitelist_path} = "~/.spamassassin/auto-whitelist";
  $self->{auto_whitelist_file_mode} = '0600';	# as string, with --x bits
  $self->{auto_whitelist_factor} = 0.5;

  $self->{rewrite_subject} = 1;
  $self->{spam_level_stars} = 1;
  $self->{subject_tag} = '*****SPAM*****';
  $self->{report_header} = 0;
  $self->{use_terse_report} = 0;
  $self->{defang_mime} = 1;
  $self->{skip_rbl_checks} = 0;
  $self->{check_mx_attempts} = 2;
  $self->{check_mx_delay} = 5;
  $self->{ok_locales} = '';
  $self->{allow_user_rules} = 0;

  $self->{whitelist_from} = { };
  $self->{blacklist_from} = { };

  $self->{whitelist_to} = { };
  $self->{more_spam_to} = { };
  $self->{all_spam_to} = { };

  $self->{spamphrase} = { };
  $self->{spamphrase_highest_score} = 0;

  # this will hold the database connection params
  $self->{user_scores_dsn} = '';
  $self->{user_scores_sql_username} = '';
  $self->{user_scores_sql_passowrd} = '';

  $self->{_unnamed_counter} = 'aaaaa';

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
  my ($self, $rules) = @_;
  $self->_parse ($rules, 1);
}

sub parse_rules {
  my ($self, $rules) = @_;
  $self->_parse ($rules, 0);
}

sub _parse {
  my ($self, $rules, $scoresonly) = @_;
  local ($_);

  my $lang = $ENV{'LC_ALL'};
  $lang ||= $ENV{'LANGUAGE'};
  $lang ||= $ENV{'LC_MESSAGES'};
  $lang ||= $ENV{'LANG'};
  $lang ||= 'C';

  if ($lang eq 'C') { $lang = 'en_US'; }
  $lang =~ s/[\.\@].*$//;	# .utf8 or @euro

  foreach $_ (split (/\n/, $rules)) {
    s/\r//g; s/(^|(?<!\\))\#.*$/$1/;
    s/^\s+//; s/\s+$//; /^$/ and next;

    # handle i18n
    if (s/^lang\s+(\S\S_\S\S)\s+//) { next if ($lang ne $1); }
    if (s/^lang\s+(\S\S)\s+//) { my $l = $1; next if ($lang !~ /${l}$/i); }

    # note: no eval'd code should be loaded before the SECURITY line below.
###########################################################################

=item whitelist_from add@ress.com

Used to specify addresses which send mail that is often tagged (incorrectly) as
spam; it also helps if they are addresses of big companies with lots of
lawyers.  This way, if spammers impersonate them, they'll get into big trouble,
so it doesn't provide a shortcut around SpamAssassin.

Whitelist and blacklist addresses are now file-glob-style patterns, so
C<friend@somewhere.com>, C<*@isp.com>, or C<*.domain.net> will all work.
Regular expressions are not used for security reasons.

Multiple addresses per line is OK.  Multiple C<whitelist_from> lines is also
OK.

=cut

    if (/^whitelist[-_]from\s+(.+)\s*$/) {
      $self->add_to_addrlist ('whitelist_from', split (' ', $1)); next;
    }

=item blacklist_from add@ress.com

Used to specify addresses which send mail that is often tagged (incorrectly) as
non-spam, but which the user doesn't want.  Same format as C<whitelist_from>.

=cut

    if (/^blacklist[-_]from\s+(.+)\s*$/) {
      $self->add_to_addrlist ('blacklist_from', split (' ', $1)); next;
    }

=item whitelist_to add@ress.com

If the given address appears in the C<To:> or C<Cc:> headers, mail will be
whitelisted.  Useful if you're deploying SpamAssassin system-wide, and don't
want some users to have their mail filtered.  Same format as C<whitelist_from>.

There are three levels of To-whitelisting, C<whitelist_to>, C<more_spam_to>
and C<all_spam_to>.  Users in the first level may still get some spammish
mails blocked, but users in C<all_spam_to> should never get mail blocked.

=item more_spam_to add@ress.com

See above.

=item all_spam_to add@ress.com

See above.

=cut

    if (/^whitelist[-_]to\s+(.+)\s*$/) {
      $self->add_to_addrlist ('whitelist_to', split (' ', $1)); next;
    }
    if (/^more[-_]spam[-_]to\s+(.+)\s*$/) {
      $self->add_to_addrlist ('more_spam_to', split (' ', $1)); next;
    }
    if (/^all[-_]spam[-_]to\s+(.+)\s*$/) {
      $self->add_to_addrlist ('all_spam_to', split (' ', $1)); next;
    }

=item required_hits n.nn   (default: 5)

Set the number of hits required before a mail is considered spam.  C<n.nn> can
be an integer or a real number.

=cut

    if (/^required[-_]hits\s+(\S+)$/) {
      $self->{required_hits} = $1+0.0; next;
    }

=item auto_report_threshold n.nn   (default: 30)

How many hits before a mail is automatically reported to blacklisting services
like Razor.  Be very careful with this; you really should manually verify the
spamminess of a mail before reporting it.

=cut

    if (/^auto[-_]report[-_]threshold\s+(\S+)$/) {
      $self->{auto_report_threshold} = $1+0; next;
    }

=item score SYMBOLIC_TEST_NAME n.nn

Assign a score to a given test.  Scores can be positive or negative real
numbers or integers.  C<SYMBOLIC_TEST_NAME> is the symbolic name used by
SpamAssassin as a handle for that test; for example, 'FROM_ENDS_IN_NUMS'.

=cut

    if (/^score\s+(\S+)\s+(\-*[\d\.]+)$/) {
      $self->{scores}->{$1} = $2+0.0; next;
    }

=item rewrite_subject { 0 | 1 }        (default: 1)

By default, the subject lines of suspected spam will be tagged.  This can be
disabled here.

=cut

    if (/^rewrite[-_]subject\s+(\d+)$/) {
      $self->{rewrite_subject} = $1+0; next;
    }

=item spam_level_stars { 0 | 1 }        (default: 1)

By default, a header field called "X-Spam-Level" will be added to the message,
with its value set to a number of asterisks equal to the score of the message.
In other words, for a message scoring 7.2 points:

X-Spam-Level: *******

This can be useful for MUA rule creation.

=cut

   if(/^spam[-_]level[-_]stars\s+(\d+)$/) {
      $self->{spam_level_stars} = $1+0; next;
   }

=item subject_tag STRING ... 		(default: *****SPAM*****)

Text added to the C<Subject:> line of mails that are considered spam,
if C<rewrite_subject> is 1.  _HITS_ in the tag will be replace with the calculated
score for this message. _REQD_ will be replaced with the threshold.

=cut

    if (/^subject[-_]tag\s+(.+?)\s*$/) {
      $self->{subject_tag} = $1; next;
    }

=item report_header { 0 | 1 }	(default: 0)

By default, SpamAssassin will include its report in the body of suspected spam.
Enabling this causes the report to go in the headers instead. Using
'use_terse_report' with this is recommended.

=cut

    if (/^report[-_]header\s+(\d+)$/) {
      $self->{report_header} = $1+0; next;
    }

=item use_terse_report { 0 | 1 }   (default: 0)

By default, SpamAssassin uses a fairly long report format.  Enabling this uses
a shorter format which includes all the information in the normal one, but
without the superfluous explanations.

=cut

    if (/^use[-_]terse[-_]report\s+(\d+)$/) {
      $self->{use_terse_report} = $1+0; next;
    }

=item defang_mime { 0 | 1 }   (default: 1)

By default, SpamAssassin will change the Content-type: header of suspected spam
to "text/plain". This is a safety feature. If you prefer to leave the
Content-type header alone, set this to 0.

=cut

    if (/^defang[-_]mime\s+(\d+)$/) {
      $self->{defang_mime} = $1+0; next;
    }

=item skip_rbl_checks { 0 | 1 }   (default: 0)

By default, SpamAssassin will run RBL checks.  If your ISP already does this
for you, set this to 1.

=cut

    if (/^skip[-_]rbl[-_]checks\s+(\d+)$/) {
      $self->{skip_rbl_checks} = $1+0; next;
    }

=item check_mx_attempts n	(default: 3)

By default, SpamAssassin checks the From: address for a valid MX three times,
waiting 5 seconds each time.

=cut

    if (/^check[-_]mx[-_]attempts\s+(\S+)$/) {
      $self->{check_mx_attempts} = $1+0; next;
    }

=item check_mx_delay n		(default 5)

How many seconds to wait before retrying an MX check.

=cut

    if (/^check[-_]mx[-_]delay\s+(\S+)$/) {
      $self->{check_mx_delay} = $1+0; next;
    }

=item ok_locales xx [ yy zz ... ]		(default: en)

Which locales (country codes) are considered OK to receive mail from.  Mail
using character sets used by languages in these countries, will not be marked
as possibly being spam in a foreign language.

SpamAssassin will try to determine the local locale, in order to determine
which charsets should be allowed by default, but on some OSes it may not be
able to do this effectively, requiring customisation.

All ISO-8859-* character sets, and Windows code page character sets, are
already permitted by default.

The following locales use additional character sets, and are supported:

=over 4

=item ja

Japanese

=item ko

Korea

=item ru

Cyrillic charsets

=item th

Thai

=item zh

Chinese (both simplified and traditional)

=back

So to simply allow all character sets through without giving them points, use

	ok_locales	ja ko ru th zh

=cut

    if (/^ok[-_]locales\s+(.+)$/) {
      $self->{ok_locales} = $1; next;
    }

=item auto_whitelist_factor n	(default: 0.5, range [0..1])

How much towards the long-term mean for the sender to regress a message.  Basically,
the algorithm is to track the long-term mean score of messages for the sender (C<mean>),
and then once we have otherwise fully calculated the score for this message (C<score>),
we calculate the final score for the message as:

C<finalscore> = C<score> +  (C<mean> - C<score>) * C<factor>

So if C<factor> = 0.5, then we'll move to half way between the calculated score and the mean.
If C<factor> = 0.3, then we'll move about 1/3 of the way from the score toward the mean.
C<factor> = 1 means just use the long-term mean; C<factor> = 0 mean just use the calculated score.

=cut
    if (/^auto[-_]whitelist[-_]threshold\s*(.*)\s*$/) {
      $self->{auto_whitelist_threshold} = $1; next;
    }

=item describe SYMBOLIC_TEST_NAME description ...

Used to describe a test.  This text is shown to users in the detailed report.

=cut

    if (/^describe\s+(\S+)\s+(.*)$/) {
      $self->{descriptions}->{$1} = $2; next;
    }

=item report ...some text for a report...

Set the report template which is attached to spam mail messages.  See the
C<10_misc.cf> configuration file in C</usr/share/spamassassin> for an
example.

If you change this, try to keep it under 76 columns (inside the the dots
below).  Bear in mind that EVERY line will be prefixed with "SPAM: " in order
to make it clear what's been added, and allow other filters to B<remove>
spamfilter modifications, so you lose 6 columns right there.  Each C<report>
line appends to the existing template, so use C<clear-report-template> to
restart.

The following template items are supported, and will be filled out by
SpamAssassin:

=over 4

=item  _HITS_: the number of hits the message triggered

=item  _REQD_: the required hits to be considered spam

=item  _SUMMARY_: the full details of what hits were triggered

=item  _VER_: SpamAssassin version

=item  _HOME_: SpamAssassin home URL

=back

=cut

    if (/^report\b\s*(.*?)$/) {
      $self->{report_template} .= $1."\n"; next;
    }

=item clear_report_template

Clear the report template.

=cut

    if (/^clear[-_]report[-_]template$/) {
      $self->{report_template} = ''; next;
    }

=item terse_report ...some text for a report...

Set the report template which is attached to spam mail messages, for the
terse-report format.  See the C<10_misc.cf> configuration file in
C</usr/share/spamassassin> for an example.

=cut

    if (/^terse[-_]report\b\s*(.*?)$/) {
      $self->{terse_report_template} .= $1."\n"; next;
    }

=item clear-terse-report-template

Clear the terse-report template.

=cut

    if (/^clear[-_]terse[-_]report[-_]template$/) {
      $self->{terse_report_template} = ''; next;
    }

=item spamtrap ...some text for spamtrap reply mail...

A template for spam-trap responses.  If the first few lines begin with
C<Xxxxxx: yyy> where Xxxxxx is a header and yyy is some text, they'll be used
as headers.  See the C<10_misc.cf> configuration file in
C</usr/share/spamassassin> for an example.

=cut

    if (/^spamtrap\s*(.*?)$/) {
      $self->{spamtrap_template} .= $1."\n"; next;
    }

=item clear_spamtrap_template

Clear the spamtrap template.

=cut

    if (/^clear[-_]spamtrap[-_]template$/) {
      $self->{spamtrap_template} = ''; next;
    }

###########################################################################
    # SECURITY: no eval'd code should be loaded before this line.
    #
    if ($scoresonly && !$self->{allow_user_rules}) { goto failed_line; }

=back

=head1 SETTINGS

These settings differ from the ones above, in that they are considered
'privileged'.  Only users running C<spamassassin> from their procmailrc's or
forward files, or sysadmins editing a file in C</etc/mail/spamassassin>, can
use them.   C<spamd> users cannot use them in their C<user_prefs> files, for
security and efficiency reasons, unless allow_user_rules is enabled (and
then, they may only add rules from below).

=over 4

=item allow_user_rules { 0 | 1 }		(default: 0)

This setting allows users to create rules (and only rules) in their C<user_prefs> files for
use with C<spamd>. It defaults to off, because this could be a
severe security hole. It may be possible for users to gain root level access
if C<spamd> is run as root. It is NOT a good idea, unless you have some
other way of ensuring that users' tests are safe. Don't use this unless you
are certain you know what you are doing.

=cut


    if (/^allow[-_]user[-_]rules\s+(\d+)$/) {
      $self->{allow_user_rules} = $1+0; next;
    }



=item header SYMBOLIC_TEST_NAME header op /pattern/modifiers	[if-unset: STRING]

Define a test.  C<SYMBOLIC_TEST_NAME> is a symbolic test name, such as
'FROM_ENDS_IN_NUMS'.  C<header> is the name of a mail header, such as
'Subject', 'To', etc. 'ALL' can be used to mean the text of all the message's
headers.

C<op> is either C<=~> (contains regular expression) or C<!~> (does not contain
regular expression), and C<pattern> is a valid Perl regular expression, with
C<modifiers> as regexp modifiers in the usual style.

If the C<[if-unset: STRING]> tag is present, then C<STRING> will
be used if the header is not found in the mail message.

=item header SYMBOLIC_TEST_NAME eval:name_of_eval_method([arguments])

Define a header eval test.  C<name_of_eval_method> is the name of 
a method on the C<Mail::SpamAssassin::EvalTests> object.  C<arguments>
are optional arguments to the function call.

=cut
    if (/^header\s+(\S+)\s+eval:(.*)$/) {
      $self->add_test ($1, $2, $type_head_evals); next;
    }
    if (/^header\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, $type_head_tests); next;
    }

=item body SYMBOLIC_TEST_NAME /pattern/modifiers

Define a body pattern test.  C<pattern> is a Perl regular expression.

The 'body' in this case is the textual parts of the message body; any non-text
MIME parts are stripped, and the message decoded from Quoted-Printable or
Base-64-encoded format if necessary.  All HTML tags and line breaks will be
removed before matching.

=item body SYMBOLIC_TEST_NAME eval:name_of_eval_method([args])

Define a body eval test.  See above.

=cut
    if (/^body\s+(\S+)\s+eval:(.*)$/) {
      $self->add_test ($1, $2, $type_body_evals); next;
    }
    if (/^body\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, $type_body_tests); next;
    }

=item uri SYMBOLIC_TEST_NAME /pattern/modifiers

Define a uri pattern test.  C<pattern> is a Perl regular expression.

The 'uri' in this case is a list of all the URIs in the body of the email,
and the test will be run on each and every one of those URIs, adjusting the
score if a match is found. Use this test instead of one of the body tests
when you need to match a URI, as it is more accurately bound to the start/end
points of the URI, and will also be faster.

=cut
# we don't do URI evals yet - maybe later
#    if (/^uri\s+(\S+)\s+eval:(.*)$/) {
#      $self->add_test ($1, $2, $type_uri_evals); next;
#    }
    if (/^uri\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, $type_uri_tests); next;
    }

=item rawbody SYMBOLIC_TEST_NAME /pattern/modifiers

Define a raw-body pattern test.  C<pattern> is a Perl regular expression.

The 'raw body' of a message is the text, including all textual parts.
The text will be decoded from base64 or quoted-printable encoding, but
HTML tags and line breaks will still be present.

=item rawbody SYMBOLIC_TEST_NAME eval:name_of_eval_method([args])

Define a raw-body eval test.  See above.

=cut
    if (/^rawbody\s+(\S+)\s+eval:(.*)$/) {
      $self->add_test ($1, $2, $type_rawbody_evals); next;
    }
    if (/^rawbody\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, $type_rawbody_tests); next;
    }

=item full SYMBOLIC_TEST_NAME /pattern/modifiers

Define a full-body pattern test.  C<pattern> is a Perl regular expression.

The 'full body' of a message is the un-decoded text, including all parts
(including images or other attachments).  SpamAssassin no longer tests
full tests against decoded text; use C<rawbody> for that.

=item full SYMBOLIC_TEST_NAME eval:name_of_eval_method([args])

Define a full-body eval test.  See above.

=cut
    if (/^full\s+(\S+)\s+eval:(.*)$/) {
      $self->add_test ($1, $2, $type_full_evals); next;
    }
    if (/^full\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, $type_full_tests); next;
    }

###########################################################################
    # SECURITY: allow_user_prefs is only in affect until here.
    #
    if ($scoresonly) { goto failed_line; }


=item test SYMBOLIC_TEST_NAME (ok|fail) Some string to test against

Define a regression testing string. You can have more than one regression test string
per symbolic test name. Simply specify a string that you wish the test to match.

These tests are only run as part of the test suite - they should not affect the general
running of SpamAssassin.

=cut

    if (/^test\s+(\S+)\s+(ok|fail)\s+(.*)$/) {
      $self->add_regression_test($1, $2, $3); next;
    }

=item razor_config filename

Define the filename used to store Razor's configuration settings.
Currently this is the same value Razor itself uses: C<~/razor.conf>.

=cut

    if (/^razor[-_]config\s*(.*)\s*$/) {
      $self->{razor_config} = $1; next;
    }

=item auto_whitelist_path /path/to/file	(default: ~/.spamassassin/auto-whitelist)

Automatic-whitelist directory or file.  By default, each user has their own, in
their C<~/.spamassassin> directory with mode 0700, but for system-wide
SpamAssassin use, you may want to share this across all users.

=cut

    if (/^auto[-_]whitelist[-_]path\s*(.*)\s*$/) {
      $self->{auto_whitelist_path} = $1; next;
    }

=item auto_whitelist_file_mode		(default: 0700)

The file mode bits used for the automatic-whitelist directory or file.
Make sure this has the relevant execute-bits set (--x), otherwise
things will go wrong.

=cut
    if (/^auto[-_]whitelist[-_]file[-_]mode\s*(.*)\s*$/) {
      $self->{auto_whitelist_file_mode} = $1; next;
    }

=item user-scores-dsn DBI:databasetype:databasename:hostname:port

If you load user scores from an SQL database, this will set the DSN
used to connect.  Example: C<DBI:mysql:spamassassin:localhost>

=cut

    if (/^user[-_]scores[-_]dsn\s+(\S+)$/) {
      $self->{user_scores_dsn} = $1; next;
    }

=item user_scores_sql_username username

The authorized username to connect to the above DSN.

=cut
    if(/^user[-_]scores[-_]sql[-_]username\s+(\S+)$/) {
      $self->{user_scores_sql_username} = $1; next;
    }

=item user_scores_sql_password password

The password for the database username, for the above DSN.

=cut
    if(/^user[-_]scores[-_]sql[-_]password\s+(\S+)$/) {
      $self->{user_scores_sql_password} = $1; next;
    }

=item spamphrase score phrase ...

A 2-word spam phrase, for the FREQ_SPAM_PHRASE test.

=cut
    if(/^spamphrase\s+(\d+)\s+(\S+ \S+)$/) {
      $self->{spamphrase}->{$2} = $1; next;
    }

=item spamphrase-highest-score nnnnn

The highest score of any of the spamphrases.  Used for scaling.

=cut
    if(/^spamphrase[-_]highest[-_]score\s+(\d+)$/) {
      $self->{spamphrase_highest_score} = $1+0; next;
    }

###########################################################################

failed_line:
    dbg ("Failed to parse line in SpamAssassin configuration, skipping: $_");
  }
}

sub add_test {
  my ($self, $name, $text, $type) = @_;
  if ($name eq '.') { $name = ($self->{_unnamed_counter}++); }
  $self->{tests}->{$name} = $text;
  $self->{test_types}->{$name} = $type;
  $self->{scores}->{$name} ||= 1.0;
}

sub add_regression_test {
  my ($self, $name, $ok_or_fail, $string) = @_;
  if ($self->{regression_tests}->{$name}) {
    push @{$self->{regression_tests}->{$name}}, [$ok_or_fail, $string];
  }
  else {
    # initialize the array, and create one element
    $self->{regression_tests}->{$name} = [ [$ok_or_fail, $string] ];
  }
}

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

sub finish_parsing {
  my ($self) = @_;

  foreach my $name (keys %{$self->{tests}}) {
    my $type = $self->{test_types}->{$name};
    my $text = $self->{tests}->{$name};

    if ($type == $type_body_tests) { $self->{body_tests}->{$name} = $text; }
    elsif ($type == $type_head_tests) { $self->{head_tests}->{$name} = $text; }
    elsif ($type == $type_head_evals) { $self->{head_evals}->{$name} = $text; }
    elsif ($type == $type_body_evals) { $self->{body_evals}->{$name} = $text; }
    elsif ($type == $type_rawbody_tests) { $self->{rawbody_tests}->{$name} = $text; }
    elsif ($type == $type_rawbody_evals) { $self->{rawbody_evals}->{$name} = $text; }
    elsif ($type == $type_full_tests) { $self->{full_tests}->{$name} = $text; }
    elsif ($type == $type_full_evals) { $self->{full_evals}->{$name} = $text; }
    elsif ($type == $type_uri_tests)  { $self->{uri_tests}->{$name} = $text; }
    # elsif ($type == $type_uri_evals)  { $self->{uri_evals}->{$name} = $text; }
    else {
      # 70 == SA_SOFTWARE
      sa_die (70, "unknown type $type for $name: $text");
    }
  }

  delete $self->{tests};		# free it up
}

sub add_to_addrlist {
  my ($self, $singlelist, @addrs) = @_;

  foreach my $addr (@addrs) {
    my $re = lc $addr;
    $re =~ s/[\000\\\(]/_/gs;			# paranoia
    $re =~ s/([^\*_a-zA-Z0-9])/\\$1/g;		# escape any possible metachars
    $re =~ s/\*/\.\*/g;				# "*" -> "any string"
    $self->{$singlelist}->{$addr} = qr/^${re}$/;
  }
}

sub dbg { Mail::SpamAssassin::dbg (@_); }
sub sa_die { Mail::SpamAssassin::sa_die (@_); }

###########################################################################

1;
__END__

=back

=head1 LOCALI[SZ]ATION

A line starting with the text C<lang xx> will only be interpreted
if the user is in that locale, allowing test descriptions and
templates to be set for that language.

=head1 SEE ALSO

C<Mail::SpamAssassin>
C<spamassassin>
C<spamd>

