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

The C<#> character starts a comment, which continues until end of line.

Whitespace in the files is not significant, but please note that starting a
line with whitespace is deprecated, as we reserve its use for multi-line rule
definitions, at some point in the future.

Paths can use C<~> to refer to the user's home directory.

Where appropriate, default values are listed in parentheses.

=head1 USER PREFERENCES

=over 4

=cut

package Mail::SpamAssassin::Conf;

use strict;
eval "use bytes";

use vars	qw{
  	@ISA $type_body_tests $type_head_tests $type_head_evals
	$type_body_evals $type_full_tests $type_full_evals
	$type_rawbody_tests $type_rawbody_evals 
	$type_uri_tests $type_uri_evals
	$type_rbl_evals $type_rbl_res_evals $type_meta_tests
        $VERSION
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
$type_rbl_evals  = 120;
$type_rbl_res_evals  = 121;
$type_meta_tests = 122;

$VERSION = 'bogus';     # avoid CPAN.pm picking up version strings later

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my $self = { }; bless ($self, $class);

  $self->{errors} = 0;
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
  $self->{meta_tests} = { };

  # testing stuff
  $self->{regression_tests} = { };

  $self->{required_hits} = 5.0;
  $self->{report_template} = '';
  $self->{terse_report_template} = '';
  $self->{spamtrap_template} = '';

  # What different RBLs consider a dialup IP -- Marc
  $self->{dialup_codes} = { 
			    "dialups.mail-abuse.org." => "127.0.0.3",
			   # For DUL + other codes, we ignore that it's on DUL
			    "rbl-plus.mail-abuse.org." => "127.0.0.2",
			    "relays.osirusoft.com." => "127.0.0.3",
			  };

  $self->{num_check_received} = 2;

  $self->{razor_config} = undef;
  $self->{razor_timeout} = 10;
  $self->{rbl_timeout} = 30;

  # this will be sedded by implementation code, so ~ is OK.
  # using "__userstate__" is recommended for defaults, as it allows
  # Mail::SpamAssassin module users who set that configuration setting,
  # to receive the correct values.

  $self->{auto_whitelist_path} = "__userstate__/auto-whitelist";
  $self->{auto_whitelist_file_mode} = '0600';	# as string, with --x bits
  $self->{auto_whitelist_factor} = 0.5;

  $self->{auto_learn} = 0;

  $self->{rewrite_subject} = 0;
  $self->{spam_level_stars} = 1;
  $self->{spam_level_char} = '*';
  $self->{subject_tag} = '*****SPAM*****';
  $self->{report_header} = 1;
  $self->{use_terse_report} = 1;
  $self->{defang_mime} = 0;
  $self->{skip_rbl_checks} = 0;
  $self->{dns_available} = "test";
  $self->{check_mx_attempts} = 2;
  $self->{check_mx_delay} = 5;
  $self->{ok_locales} = 'all';
  $self->{ok_languages} = 'all';
  $self->{allow_user_rules} = 0;
  $self->{user_rules_to_compile} = 0;
  $self->{fold_headers} = 1;

  $self->{dcc_path} = undef; # Browse PATH
  $self->{dcc_body_max} = 999999;
  $self->{dcc_fuz1_max} = 999999;
  $self->{dcc_fuz2_max} = 999999;
  $self->{dcc_add_header} = 0;
  $self->{dcc_timeout} = 10;
  $self->{dcc_options} = '-R';

  $self->{pyzor_path} = undef; # Browse PATH
  $self->{pyzor_max} = 5;
  $self->{pyzor_add_header} = 0;
  $self->{pyzor_timeout} = 10;

  $self->{bayes_path} = "__userstate__/bayes";
  $self->{bayes_file_mode} = "0700";	# as string, with --x bits
  $self->{bayes_use_hapaxes} = 1;
  $self->{bayes_use_chi2_combining} = 0;
  $self->{bayes_expiry_min_db_size} = 100000;
  $self->{bayes_expiry_use_scan_count} = 0;
  $self->{bayes_expiry_days} = 30;
  $self->{bayes_expiry_scan_count} = 5000;
  $self->{bayes_ignore_headers} = [ ];

  $self->{whitelist_from} = { };
  $self->{blacklist_from} = { };

  $self->{whitelist_to} = { };
  $self->{more_spam_to} = { };
  $self->{all_spam_to} = { };

  # this will hold the database connection params
  $self->{user_scores_dsn} = '';
  $self->{user_scores_sql_username} = '';
  $self->{user_scores_sql_password} = '';
  $self->{user_scores_sql_table} = 'userpref'; # Morgan - default to userpref for backwords compatibility

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
  my ($self) = @_;
  $self->_parse ($_[1], 1); # don't copy $rules!
}

sub parse_rules {
  my ($self) = @_;
  $self->_parse ($_[1], 0); # don't copy $rules!
}

sub _parse {
  my ($self, undef, $scoresonly) = @_; # leave $rules in $_[1]
  local ($_);

  my $lang = $ENV{'LC_ALL'};
  $lang ||= $ENV{'LANGUAGE'};
  $lang ||= $ENV{'LC_MESSAGES'};
  $lang ||= $ENV{'LANG'};
  $lang ||= 'C';

  if ($lang eq 'C') { $lang = 'en_US'; }
  $lang =~ s/[\.\@].*$//;	# .utf8 or @euro

  my $currentfile = '(no file)';
  my $skipfile = 0;

  foreach (split (/\n/, $_[1])) {
    s/(?<!\\)#.*$//; # remove comments
    s/^\s+|\s+$//g;  # remove leading and trailing spaces (including newlines)
    next unless($_); # skip empty lines

    # handle i18n
    if (s/^lang\s+(\S+)\s+//) { next if ($lang !~ /^$1/i); }
    
    # Versioning assertions
    if (/^file\s+start\s+(.+)$/) { $currentfile = $1; next; }
    if (/^file\s+end/) {
      $currentfile = '(no file)';
      $skipfile = 0;
      next;
    }

=item require_version n.nn

Indicates that the entire file, from this line on, requires a certain version
of SpamAssassin to run.  If an older or newer version of SpamAssassin tries to
read configuration from this file, it will output a warning instead, and
ignore it.

=cut

    if (/^require[-_]version\s+(.*)$/) {
      my $req_version = $1;
      $req_version =~ s/^\@\@VERSION\@\@$/$Mail::SpamAssassin::VERSION/;
      if ($Mail::SpamAssassin::VERSION != $req_version) {
        warn "configuration file \"$currentfile\" requires version ".
                "$req_version of SpamAssassin, but this is code version ".
                "$Mail::SpamAssassin::VERSION. Maybe you need to use ".
                "the -c switch, or remove the old config files? ".
                "Skipping this file";
        $skipfile = 1;
        $self->{errors}++;
      }
      next;
    }

    if ($skipfile) { next; }

=item version_tag string

This tag is appended to the SA version in the X-Spam-Status header. You should
include it when modify your ruleset, especially if you plan to distribute it.
A good choice for I<string> is your last name or your initials followed by a
number which you increase with each change.

e.g.

  version_tag myrules1    # version=2.41-myrules1

=cut

    if(/^version[-_]tag\s+(.*)$/) {
      my $tag = lc($1);
      $tag =~ tr/a-z0-9./_/c;
      foreach (@Mail::SpamAssassin::EXTRA_VERSION) {
        if($_ eq $tag) {
          $tag = undef;
          last;
        }
      }
      push(@Mail::SpamAssassin::EXTRA_VERSION, $tag) if($tag);
      next;
    }

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

Multiple addresses per line, separated by spaces, is OK.  Multiple C<whitelist_from> lines is also
OK.

e.g.

  whitelist_from joe@example.com fred@example.com
  whitelist_from simon@example.com

=cut

    if (/^whitelist[-_]from\s+(.+)$/) {
      $self->add_to_addrlist ('whitelist_from', split (' ', $1)); next;
    }

=item unwhitelist_from add@ress.com

Used to override a default whitelist_from entry, so for example a distribution whitelist_from
can be overriden in a local.cf file, or an individual user can override a whitelist_from entry
in their own C<user_prefs> file.

e.g.

  unwhitelist_from joe@example.com fred@example.com
  unwhitelist_from *@amazon.com

=cut

    if (/^unwhitelist[-_]from\s+(.+)$/) {
      $self->remove_from_addrlist ('whitelist_from', split (' ', $1)); next;
    }

=item whitelist_from_rcvd lists.sourceforge.net sourceforge.net

Use this to supplement the whitelist_from addresses with a check against the
Received headers. The first parameter is the address to whitelist, and the
second is a domain to match in the received headers.

e.g.

  whitelist_from_rcvd joe@example.com  example.com
  whitelist_from_rcvd axkit.org        sergeant.org

=cut

    if (/^whitelist[-_]from[-_]rcvd\s+(\S+)\s+(\S+)$/) {
      $self->add_to_addrlist_rcvd ('whitelist_from_rcvd', $1, $2);
      next;
    }

=item unwhitelist_from_rcvd add@ress.com

Used to override a default whitelist_from_rcvd entry, so for example a
distribution whitelist_from_rcvd can be overriden in a local.cf file,
or an individual user can override a whitelist_from_rcvd entry in
their own C<user_prefs> file.

e.g.

  unwhitelist_from_rcvd joe@example.com fred@example.com
  unwhitelist_from_rcvd amazon.com

=cut

    if (/^unwhitelist[-_]from\s+(.+)$/) {
      $self->remove_from_addrlist_rcvd('whitelist_from_rcvd', split (' ', $1));
      next;
    }

=item blacklist_from add@ress.com

Used to specify addresses which send mail that is often tagged (incorrectly) as
non-spam, but which the user doesn't want.  Same format as C<whitelist_from>.

=cut

    if (/^blacklist[-_]from\s+(.+)$/) {
      $self->add_to_addrlist ('blacklist_from', split (' ', $1)); next;
    }

=item unblacklist_from add@ress.com

Used to override a default blacklist_from entry, so for example a distribution blacklist_from
can be overriden in a local.cf file, or an individual user can override a blacklist_from entry
in their own C<user_prefs> file.

e.g.

  unblacklist_from joe@example.com fred@example.com
  unblacklist_from *@spammer.com

=cut

    if (/^unblacklist[-_]from\s+(.+)$/) {
      $self->remove_from_addrlist ('blacklist_from', split (' ', $1)); next;
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

    if (/^whitelist[-_]to\s+(.+)$/) {
      $self->add_to_addrlist ('whitelist_to', split (' ', $1)); next;
    }
    if (/^more[-_]spam[-_]to\s+(.+)$/) {
      $self->add_to_addrlist ('more_spam_to', split (' ', $1)); next;
    }
    if (/^all[-_]spam[-_]to\s+(.+)$/) {
      $self->add_to_addrlist ('all_spam_to', split (' ', $1)); next;
    }

=item required_hits n.nn   (default: 5)

Set the number of hits required before a mail is considered spam.  C<n.nn> can
be an integer or a real number.  5.0 is the default setting, and is quite
aggressive; it would be suitable for a single-user setup, but if you're an ISP
installing SpamAssassin, you should probably set the default to be something
much more conservative, like 8.0 or 10.0.  Experience has shown that you
B<will> get plenty of user complaints otherwise!

=cut

    if (/^required[-_]hits\s+(\S+)$/) {
      $self->{required_hits} = $1+0.0; next;
    }

=item score SYMBOLIC_TEST_NAME n.nn

Assign a score to a given test.  Scores can be positive or negative real
numbers or integers.  C<SYMBOLIC_TEST_NAME> is the symbolic name used by
SpamAssassin as a handle for that test; for example, 'FROM_ENDS_IN_NUMS'.

Note that test names which begin with '__' are reserved for meta-match
sub-rules, and are not scored or listed in the 'tests hit' reports.

Test names should not start with a number, and must contain only alphanumerics
and underscores.  It is suggested that lower-case characters not be used, as an
informal convention.

=cut

    if (/^score\s+(\S+)\s+(\-*[\d\.]+)$/) {
      $self->{scores}->{$1} = $2+0.0; next;
    }

=item rewrite_subject { 0 | 1 }        (default: 0)

By default, the subject lines of suspected spam will not be tagged.  This can
be enabled here.

=cut

    if (/^rewrite[-_]subject\s+(\d+)$/) {
      $self->{rewrite_subject} = $1+0; next;
    }

=item fold_headers { 0 | 1 }        (default: 1)

By default, the X-Spam-Status header will be whitespace folded, in other words,
it will be broken up into multiple lines instead of one very long one.
This can be disabled here.

=cut

   if (/^fold[-_]headers\s+(\d+)$/) {
     $self->{fold_headers} = $1+0; next;
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

=item spam_level_char { x (some character, unquoted) }        (default: *)

By default, the "X-Spam-Level" header will use a '*' character with its length
equal to the score of the message. Some people don't like escaping *s though, 
so you can set the character to anything with this option.

In other words, for a message scoring 7.2 points with this option set to .

X-Spam-Level: .......

=cut

   if(/^spam[-_]level[-_]char\s+(.)$/) {
      $self->{spam_level_char} = $1; next;
   }

=item subject_tag STRING ... 		(default: *****SPAM*****)

Text added to the C<Subject:> line of mails that are considered spam,
if C<rewrite_subject> is 1.  _HITS_ in the tag will be replace with the calculated
score for this message. _REQD_ will be replaced with the threshold.

=cut

    if (/^subject[-_]tag\s+(.+)$/) {
      $self->{subject_tag} = $1; next;
    }

=item report_header { 0 | 1 }	(default: 1)

By default, SpamAssassin will include its report in the headers of suspected
spam.  Disabling this causes the report to go in the body instead. Using
'use_terse_report' when this is enabled, is recommended.

=cut

    if (/^report[-_]header\s+(\d+)$/) {
      $self->{report_header} = $1+0; next;
    }

=item use_terse_report { 0 | 1 }   (default: 1)

By default, SpamAssassin uses a short report format.  Disabling this uses
a longer format which includes all the information in the normal one,
with the addition of some explanations and formatting.

=cut

    if (/^use[-_]terse[-_]report\s+(\d+)$/) {
      $self->{use_terse_report} = $1+0; next;
    }

=item defang_mime { 0 | 1 }   (default: 0)

If this is enabled, SpamAssassin will change the Content-type: header of
suspected spam to "text/plain". This is a safety feature.

=cut

    if (/^defang[-_]mime\s+(\d+)$/) {
      $self->{defang_mime} = $1+0; next;
    }

=item dns_available { yes | test[: name1 name2...] | no }   (default: test)

By default, SpamAssassin will query some default hosts on the internet to
attempt to check if DNS is working on not. The problem is that it can introduce
some delay if your network connection is down, and in some cases it can wrongly
guess that DNS is unavailable because the test connections failed.
SpamAssassin includes a default set of 13 servers, among which 3 are picked
randomly.

You can however specify your own list by specifying

dns_available test: server1.tld server2.tld server3.tld

=cut

    if (/^dns[-_]available\s+(yes|no|test|test:\s+.+)$/) {
      $self->{dns_available} = ($1 or "test"); next;
    }

=item skip_rbl_checks { 0 | 1 }   (default: 0)

By default, SpamAssassin will run RBL checks.  If your ISP already does this
for you, set this to 1.

=cut

    if (/^skip[-_]rbl[-_]checks\s+(\d+)$/) {
      $self->{skip_rbl_checks} = $1+0; next;
    }

=item check_mx_attempts n	(default: 2)

By default, SpamAssassin checks the From: address for a valid MX this many
times, waiting 5 seconds each time.

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

=item ok_languages xx [ yy zz ... ]		(default: all)

Which languages are considered OK to receive mail from.  Mail using
character sets used by these languages will not be marked as possibly
being spam in an undesired language.

The following languages are recognized.  In your configuration, you must
use the language specifier located in the first column, not the English
name for the language.  You may also specify "all" if your language is
not listed or if you want to allow any language.

=over 4

=item af	afrikaans

=item am	amharic

=item ar	arabic

=item be	byelorussian

=item bg	bulgarian

=item bs	bosnian

=item ca	catalan

=item cs	czech

=item cy	welsh

=item da	danish

=item de	german

=item el	greek

=item en	english

=item eo	esperanto

=item es	spanish

=item et	estonian

=item eu	basque

=item fa	persian

=item fi	finnish

=item fr	french

=item fy	frisian

=item ga	irish

=item gd	scots

=item he	hebrew

=item hi	hindi

=item hr	croatian

=item hu	hungarian

=item hy	armenian

=item id	indonesian

=item is	icelandic

=item it	italian

=item ja	japanese

=item ka	georgian

=item ko	korean

=item la	latin

=item lt	lithuanian

=item lv	latvian

=item mr	marathi

=item ms	malay

=item ne	nepali

=item nl	dutch

=item no	norwegian

=item pl	polish

=item pt	portuguese

=item qu	quechua

=item rm	rhaeto-romance

=item ro	romanian

=item ru	russian

=item sa	sanskrit

=item sco	scots

=item sk	slovak

=item sl	slovenian

=item sq	albanian

=item sr	serbian

=item sv	swedish

=item sw	swahili

=item ta	tamil

=item th	thai

=item tl	tagalog

=item tr	turkish

=item uk	ukrainian

=item vi	vietnamese

=item yi	yiddish

=item zh	chinese

=back

Note that the language cannot always be recognized.  In that case, no
points will be assigned.

=cut

    if (/^ok[-_]languages\s+(.+)$/) {
      $self->{ok_languages} = $1; next;
    }

=item rbl_timeout n		(default 30)

All RBL queries are started at the beginning and we try to read the results
at the end. In case some of them are hanging or not returning, you can specify
here how long you're willing to wait for them before deciding that they timed
out

=cut

    if (/^rbl[-_]timeout\s+(\d+)$/) {
      $self->{rbl_timeout} = $1+0; next;
    }

=item ok_locales xx [ yy zz ... ]		(default: all)

Which locales (country codes) are considered OK to receive mail from.  Mail
using character sets used by languages in these countries, will not be marked
as possibly being spam in a foreign language.

Note that all ISO-8859-* character sets, and Windows code page character sets,
are always permitted by default anyway.

If you wish SpamAssassin to block spam in foreign languages, set this to
the locale which matches your preference, from the list below:

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
    if (/^auto[-_]whitelist[-_]factor\s+(.*)$/) {
      $self->{auto_whitelist_factor} = $1; next;
    }

=item auto_learn ( 0 | 1 )	(default: 1)

Whether SpamAssassin should automatically feed high-scoring mails (or
low-scoring mails, for non-spam) into its learning systems.  The only learning
system supported currently, is a naive Bayesian classifier.

=cut

    if (/^auto[-_]learn\s+(.*)$/) {
      $self->{auto_learn} = $1+0; next;
    }

=item describe SYMBOLIC_TEST_NAME description ...

Used to describe a test.  This text is shown to users in the detailed report.

Note that test names which begin with '__' are reserved for meta-match
sub-rules, and are not scored or listed in the 'tests hit' reports.

=cut

    if (/^describe\s+(\S+)\s+(.*)$/) {
      $self->{descriptions}->{$1} = $2; next;
    }

=item tflags SYMBOLIC_TEST_NAME [ { net | nice } ... ]

Used to set flags on a test.  These flags are used in the score-determination back
end system for details of the test's behaviour.  The following flags can be set:

=over 4

=item  net

The test is a network test, and will not be run in the mass checking system
or if B<-L> is used, therefore its score should not be modified.

=item  nice

The test is intended to compensate for common false positives, and should be
assigned a negative score.

=back

=cut

    if (/^tflags\s/) {
      next;     # ignored in SpamAssassin modules
    }

=item report ...some text for a report...

Set the report template which is attached to spam mail messages.  See the
C<10_misc.cf> configuration file in C</usr/share/spamassassin> for an
example.

If you change this, try to keep it under 76 columns (inside the the dots
below).  Bear in mind that EVERY line will be prefixed with "SPAM: " in order
to make it clear what's been added, and allow other filters to B<remove>
spamfilter modifications, so you lose 6 columns right there. Also note that the
first line of the report must start with 4 dashes, for the same reason. Each
C<report> line appends to the existing template, so use
C<clear-report-template> to restart.

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

=item dcc_path STRING

This option tells SpamAssassin specifically where to find the C<dccproc>
client instead of relying on SpamAssassin to find it in the current PATH.
Note that if I<taint mode> is enabled in the Perl interpreter, you should
use this, as the current PATH will have been cleared.

=cut

    if (/^dcc[-_]path\s+(.+)$/) {
      $self->{dcc_path} = $1; next;
    }

=item dcc_body_max NUMBER

=item dcc_fuz1_max NUMBER

=item dcc_fuz2_max NUMBER

DCC (Distributed Checksum Clearinghouse) is a system similar to Razor.
This option sets how often a message's body/fuz1/fuz2 checksum must have been
reported to the DCC server before SpamAssassin will consider the DCC check as
matched.

As nearly all DCC clients are auto-reporting these checksums you should set 
this to a relatively high value, e.g. 999999 (this is DCC's MANY count).

The default is 999999 for all these options.

=cut

    if (/^dcc[-_]body[-_]max\s+(\d+)/) {
      $self->{dcc_body_max} = $1+0; next;
    }

    if (/^dcc[-_]fuz1[-_]max\s+(\d+)/) {
      $self->{dcc_fuz1_max} = $1+0; next;
    }

    if (/^dcc[-_]fuz2[-_]max\s+(\d+)/) {
      $self->{dcc_fuz2_max} = $1+0; next;
    }

=item dcc_add_header { 0 | 1 }   (default: 0)

DCC processing creates a message header containing the statistics for the
message.  This option sets whether SpamAssassin will add the heading to
messages it processes.

The default is to not add the header.

=cut

    if (/^dcc[-_]add[-_]header\s+(\d+)$/) {
      $self->{dcc_add_header} = $1+0; next;
    }

=item dcc_timeout n              (default: 10)

How many seconds you wait for dcc to complete before you go on without 
the results

=cut

    if (/^dcc[-_]timeout\s+(\d+)$/) {
      $self->{dcc_timeout} = $1+0; next;
    }

=item pyzor_path STRING

This option tells SpamAssassin specifically where to find the C<pyzor> client
instead of relying on SpamAssassin to find it in the current PATH.
Note that if I<taint mode> is enabled in the Perl interpreter, you should
use this, as the current PATH will have been cleared.

=cut

    if (/^pyzor[-_]path\s+(.+)$/) {
      $self->{pyzor_path} = $1; next;
    }

=item pyzor_max NUMBER

Pyzor is a system similar to Razor.  This option sets how often a message's
body checksum must have been reported to the Pyzor server before SpamAssassin
will consider the Pyzor check as matched.

The default is 5.

=cut

    if (/^pyzor[-_]max\s+(\d+)/) {
      $self->{pyzor_max} = $1+0; next;
    }

=item pyzor_add_header { 0 | 1 }   (default: 0)

Pyzor processing creates a message header containing the statistics for the
message.  This option sets whether SpamAssassin will add the heading to
messages it processes.

The default is to not add the header.

=cut

    if (/^pyzor[-_]add[-_]header\s+(\d+)$/) {
      $self->{pyzor_add_header} = $1+0; next;
    }

=item pyzor_timeout n              (default: 10)

How many seconds you wait for pyzor to complete before you go on without 
the results

=cut

    if (/^pyzor[-_]timeout\s+(\d+)$/) {
      $self->{pyzor_timeout} = $1+0; next;
    }


=item razor_timeout n		(default 10)

How many seconds you wait for razor to complete before you go on without 
the results

=cut

    if (/^razor[-_]timeout\s+(\d+)$/) {
      $self->{razor_timeout} = $1; next;
    }



=item num_check_received { integer }   (default: 2)

How many received lines from and including the original mail relay
do we check in RBLs (you'd want at least 1 or 2).
Note that for checking against dialup lists, you can call check_rbl
with a special set name of "set-firsthop" and this rule will only
be matched against the first hop if there is more than one hop, so 
that you can set a negative score to not penalize people who properly
relayed through their ISP.
See dialup_codes for more details and an example

=cut

    if (/^num[-_]check[-_]received\s+(\d+)$/) {
      $self->{num_check_received} = $1+0; next;
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

=cut


    if (/^allow[-_]user[-_]rules\s+(\d+)$/) {
      $self->{allow_user_rules} = $1+0; 
      dbg("Allowing user rules!"); next;
    }



# If you think, this is complex, you should have seen the four previous
# implementations that I scratched :-)
# Once you understand this, you'll see it's actually quite flexible -- Marc

=item dialup_codes { "domain1" => "127.0.x.y", "domain2" => "127.0.a.b" }

Default:
{ "dialups.mail-abuse.org." => "127.0.0.3", 
# For DUL + other codes, we ignore that it's on DUL
  "rbl-plus.mail-abuse.org." => "127.0.0.2",
  "relays.osirusoft.com." => "127.0.0.3" };

WARNING!!! When passing a reference to a hash, you need to put the whole hash in
one line for the parser to read it correctly (you can check with 
C<< spamassassin -D < mesg >>)

Set this to what your RBLs return for dialup IPs
It is used by dialup-firsthop and relay-firsthop rules so that you can match
DUL codes and compensate DUL checks with a negative score if the IP is a dialup
IP the mail originated from and it was properly relayed by a hop before reaching
you (hopefully not your secondary MX :-)
The trailing "-firsthop" is magic, it's what triggers the RBL to only be run
on the originating hop
The idea is to not penalize (or penalize less) people who properly relayed
through their ISP's mail server

Here's an example showing the use of Osirusoft and MAPS DUL, as well as the use
of check_two_rbl_results to compensate for a match in both RBLs

header RCVD_IN_DUL		rbleval:check_rbl('dialup', 'dialups.mail-abuse.org.')
describe RCVD_IN_DUL		Received from dialup, see http://www.mail-abuse.org/dul/
score RCVD_IN_DUL		4

header X_RCVD_IN_DUL_FH		rbleval:check_rbl('dialup-firsthop', 'dialups.mail-abuse.org.')
describe X_RCVD_IN_DUL_FH	Received from first hop dialup, see http://www.mail-abuse.org/dul/
score X_RCVD_IN_DUL_FH		-3

header RCVD_IN_OSIRUSOFT_COM    rbleval:check_rbl('osirusoft', 'relays.osirusoft.com.')
describe RCVD_IN_OSIRUSOFT_COM  Received via an IP flagged in relays.osirusoft.com

header X_OSIRU_SPAM_SRC         rbleval:check_rbl_results_for('osirusoft', '127.0.0.4')
describe X_OSIRU_SPAM_SRC       DNSBL: sender is Confirmed Spam Source, penalizing further
score X_OSIRU_SPAM_SRC          3.0

header X_OSIRU_SPAMWARE_SITE    rbleval:check_rbl_results_for('osirusoft', '127.0.0.6')
describe X_OSIRU_SPAMWARE_SITE  DNSBL: sender is a Spamware site or vendor, penalizing further
score X_OSIRU_SPAMWARE_SITE     5.0

header X_OSIRU_DUL_FH		rbleval:check_rbl('osirusoft-dul-firsthop', 'relays.osirusoft.com.')
describe X_OSIRU_DUL_FH		Received from first hop dialup listed in relays.osirusoft.com
score X_OSIRU_DUL_FH		-1.5

header Z_FUDGE_DUL_MAPS_OSIRU	rblreseval:check_two_rbl_results('osirusoft', "127.0.0.3", 'dialup', "127.0.0.3")
describe Z_FUDGE_DUL_MAPS_OSIRU	Do not double penalize for MAPS DUL and Osirusoft DUL
score Z_FUDGE_DUL_MAPS_OSIRU	-2

header Z_FUDGE_RELAY_OSIRU	rblreseval:check_two_rbl_results('osirusoft', "127.0.0.2", 'relay', "127.0.0.2")
describe Z_FUDGE_RELAY_OSIRU	Do not double penalize for being an open relay on Osirusoft and another DNSBL
score Z_FUDGE_RELAY_OSIRU	-2

header Z_FUDGE_DUL_OSIRU_FH	rblreseval:check_two_rbl_results('osirusoft-dul-firsthop', "127.0.0.3", 'dialup-firsthop', "127.0.0.3")
describe Z_FUDGE_DUL_OSIRU_FH	Do not double compensate for MAPS DUL and Osirusoft DUL first hop dialup
score Z_FUDGE_DUL_OSIRU_FH	1.5

=cut

    if (/^dialup[-_]codes\s+(.*)$/) {
	$self->{dialup_codes} = eval $1;
	next;
    }


    if ($scoresonly) { dbg("Checking privileged commands in user config"); }


=item header SYMBOLIC_TEST_NAME header op /pattern/modifiers	[if-unset: STRING]

Define a test.  C<SYMBOLIC_TEST_NAME> is a symbolic test name, such as
'FROM_ENDS_IN_NUMS'.  C<header> is the name of a mail header, such as
'Subject', 'To', etc.

'ALL' can be used to mean the text of all the message's headers.  'ToCc' can
be used to mean the contents of both the 'To' and 'Cc' headers.

'MESSAGEID' is a symbol meaning all Message-Id's found in the message; some
mailing list software moves the I<real> Message-Id to 'Resent-Message-Id' or
'X-Message-Id', then uses its own one in the 'Message-Id' header.  The value
returned for this symbol is the text from all 3 headers, separated by newlines.

C<op> is either C<=~> (contains regular expression) or C<!~> (does not contain
regular expression), and C<pattern> is a valid Perl regular expression, with
C<modifiers> as regexp modifiers in the usual style.

If the C<[if-unset: STRING]> tag is present, then C<STRING> will
be used if the header is not found in the mail message.

Note that test names which begin with '__' are reserved for meta-match
sub-rules, and are not scored or listed in the 'tests hit' reports.

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

=cut
    if (/^header\s+(\S+)\s+rbleval:(.*)$/) {
      $self->add_test ($1, $2, $type_rbl_evals); next;
    }
    if (/^header\s+(\S+)\s+rblreseval:(.*)$/) {
      $self->add_test ($1, $2, $type_rbl_res_evals); next;
    }
    if (/^header\s+(\S+)\s+eval:(.*)$/) {
      my ($name,$rule) = ($1, $2);
      # Backward compatibility with old rule names -- Marc
      if ($name =~ /^RCVD_IN/) {
        $self->add_test ($name, $rule, $type_rbl_evals); next;
      } else {
       $self->add_test ($name, $rule, $type_head_evals); next;
      }
      $self->{user_rules_to_compile} = 1 if $scoresonly;
      next;
    }
    if (/^header\s+(\S+)\s+exists:(.*)$/) {
      $self->add_test ($1, "$2 =~ /./", $type_head_tests);
      $self->{descriptions}->{$1} = "Found a $2 header";
      next;
    }
    if (/^header\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, $type_head_tests);
      $self->{user_rules_to_compile} = 1 if $scoresonly;
      next;
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
      $self->add_test ($1, $2, $type_body_evals);
      $self->{user_rules_to_compile} = 1 if $scoresonly;
      next;
    }
    if (/^body\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, $type_body_tests);
      $self->{user_rules_to_compile} = 1 if $scoresonly;
      next;
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
#      $self->add_test ($1, $2, $type_uri_evals);
#      $self->{user_rules_to_compile} = 1 if $scoresonly;
#      next;
#    }
    if (/^uri\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, $type_uri_tests);
      $self->{user_rules_to_compile} = 1 if $scoresonly;
      next;
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
      $self->add_test ($1, $2, $type_rawbody_evals);
      $self->{user_rules_to_compile} = 1 if $scoresonly;
      next;
    }
    if (/^rawbody\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, $type_rawbody_tests);
      $self->{user_rules_to_compile} = 1 if $scoresonly;
      next;
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
      $self->add_test ($1, $2, $type_full_evals);
      $self->{user_rules_to_compile} = 1 if $scoresonly;
      next;
    }
    if (/^full\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, $type_full_tests);
      $self->{user_rules_to_compile} = 1 if $scoresonly;
      next;
    }

=item meta SYMBOLIC_TEST_NAME boolean expression

Define a boolean expression test in terms of other tests that have
been hit or not hit.  For example:

meta META1        TEST1 && !(TEST2 || TEST3)

Note that English language operators ("and", "or") will be treated as
rule names, and that there is no C<XOR> operator.

=item meta SYMBOLIC_TEST_NAME boolean arithmetic expression

Can also define a boolean arithmetic expression in terms of other
tests, with a hit test having the value "1" and an unhit test having
the value "0".  For example:

meta META2        (3 * TEST1 - 2 * TEST2) > 0

Note that Perl builtins and functions, like C<abs()>, B<can't> be
used, and will be treated as rule names.

=item meta SYMBOLIC_TEST_NAME regular expression

Finally, parts of a meta rule may be defined by a regexp followed by
an operator.  All rules matching the regular expression will be strung
together, with the given operator between each expression.  The rule
compiler will add "^" and "$" before and after each regexp, so the
regexp must match the entire rule; a rule name begining with a "." or
a "[" will be treated as a regexp.

As an example:

meta TOO_MANY_UA      ( (USER_AGENT.* +) > 1)

Will expand to:

meta TOO_MANY_UA    ( USER_AGENT_PINE + USER_AGENT_MUTT + USER_AGENT_MOZILLA_UA + USER_AGENT_MOZILLA_XM + USER_AGENT_MACOE + USER_AGENT_ENTOURAGE + USER_AGENT_KMAIL + USER_AGENT_IMP + USER_AGENT_TONLINE + USER_AGENT_APPLEMAIL + USER_AGENT_GNUS_UA + USER_AGENT_GNUS_XM > 1 )

If you want to define a meta-rule, but do not want its individual sub-rules to
count towards the final score unless the entire meta-rule matches, give the
sub-rules names that start with '__' (two underscores).  SpamAssassin will
ignore these for scoring.

=cut

    if (/^meta\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, $type_meta_tests);
      $self->{user_rules_to_compile} = 1 if $scoresonly;
      next;
    }

###########################################################################
    # SECURITY: allow_user_rules is only in affect until here.
    #
    if ($scoresonly) { goto failed_line; }

=back

=head1 PRIVILEGED SETTINGS

These settings differ from the ones above, in that they are considered 'more
privileged' -- even more than the ones in the SETTINGS section.  No matter what
C<allow_user_rules> is set to, these can never be set from a user's
C<user_prefs> file.

=over 4


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
Currently this is left to Razor to decide.

=cut

    if (/^razor[-_]config\s+(.*)$/) {
      $self->{razor_config} = $1; next;
    }

=item dcc_options options

Specify additional options to the dccproc(8) command. Please note that only
[A-Z -] is allowed (security).

The default is C<-R>

=cut

    if (/^dcc[-_]options\s+[A-Z -]+/) {
      $self->{dcc_options} = $1; next;
    }

=item auto_whitelist_path /path/to/file	(default: ~/.spamassassin/auto-whitelist)

Automatic-whitelist directory or file.  By default, each user has their own, in
their C<~/.spamassassin> directory with mode 0700, but for system-wide
SpamAssassin use, you may want to share this across all users.

=cut

    if (/^auto[-_]whitelist[-_]path\s+(.*)$/) {
      $self->{auto_whitelist_path} = $1; next;
    }

=item bayes_path /path/to/file	(default: ~/.spamassassin/bayes)

Path for Bayesian probabilities databases.  Several databases will be created,
with this as the base, with _count, _probs etc. appended to this filename.

By default, each user has their own, in their C<~/.spamassassin> directory
with mode 0700, but for system-wide SpamAssassin use, you may want to share
this across all users.  However it should be noted that Bayesian filtering may
work better with a database per user.

=cut

    if (/^bayes[-_]path\s+(.*)$/) {
      $self->{bayes_path} = $1; next;
    }

=item timelog_path /path/to/dir		(default: NULL)

If you set this value, razor will try to create logfiles for each message I
processes and dump information on how fast it ran, and in which parts of the
code the time was spent.
The files will be named: unixdate_mesgid (i.e 1023257504_chuvn31gdu@4ax.com)

Make sure  SA can write  the log file, if  you're not sure  what permissions
needed, make the log directory chmod'ed 1777, and adjust later.

=cut

    if (/^timelog[-_]path\s+(.*)$/) {
      $Mail::SpamAssassin::TIMELOG->{logpath}=$1; next;
    }

=item auto_whitelist_file_mode		(default: 0700)

The file mode bits used for the automatic-whitelist directory or file.
Make sure this has the relevant execute-bits set (--x), otherwise
things will go wrong.

=cut
    if (/^auto[-_]whitelist[-_]file[-_]mode\s+(.*)$/) {
      $self->{auto_whitelist_file_mode} = $1; next;
    }

=item bayes_file_mode		(default: 0700)

The file mode bits used for the Bayesian filtering database files.
Make sure this has the relevant execute-bits set (--x), otherwise
things will go wrong.

=cut
    if (/^bayes[-_]file[-_]mode\s+(.*)$/) {
      $self->{bayes_file_mode} = $1; next;
    }

=item bayes_ignore_header	

If you receive mail filtered by upstream mail systems, like
a spam-filtering ISP or mailing list, and that service adds
new headers (as most of them do), these headers may provide
inappropriate cues to the Bayesian classifier, allowing it
to take a "short cut". To avoid this, list the headers using this
setting.  Example:

	bayes_ignore_header X-Upstream-Spamfilter
	bayes_ignore_header X-Upstream-SomethingElse

=cut
    if (/^bayes[-_]ignore[-_]header\s+(.*)$/) {
      push (@{$self->{bayes_ignore_headers}}, $1); next;
    }

=item bayes_use_hapaxes		(default: 1)

Should the Bayesian classifier use hapaxes (words/tokens that occur only
once) when classifying?  This produces significantly better hit-rates, but
increases database size by about a factor of 8 to 10.

=cut
    if (/^bayes[-_]use[-_]hapaxes\s+(.*)$/) {
      $self->{bayes_use_hapaxes} = $1; next;
    }

=item bayes_use_chi2_combining		(default: 1)

Should the Bayesian classifier use chi-squared combining, instead of
Robinson/Graham-style naive Bayesian combining?  Chi-squared produces
more 'extreme' output results, but may be more resistant to changes
in corpus size etc.

=cut
    if (/^bayes[-_]use[-_]chi2[-_]combining\s+(.*)$/) {
      $self->{bayes_use_chi2_combining} = $1; next;
    }

=item bayes_expiry_min_db_size		(default: 100000)

What should be the minimum size of the Bayes tokens database?  The
database will never be shrunk below this many entries. 100k entries
is roughly equivalent to a 5Mb database file.

=cut
    if (/^bayes[-_]expiry[-_]min[-_]db[-_]size\s+(.*)$/) {
      $self->{bayes_expiry_min_db_size} = $1; next;
    }

=item bayes_expiry_use_scan_count		(default: 0)

Should we use the number of scans that have occured for expiration, or the
time elapsed?  Number of scans works better for test runs, but requires
another file to be used to store the messagecount, which slows things down
considerably.  Unless you're testing expiration, you do not want to use
this.

=cut
    if (/^bayes[-_]expiry[-_]use[-_]scan[-_]count\s+(.*)$/) {
      $self->{bayes_expiry_use_scan_count} = $1; next;
    }

=item bayes_expiry_days		(default: 30)

When expiring old entries from the Bayes databases, tokens which have not
been read in this many days will be removed (unless to do so would shrink
the database below the C<bayes_expiry_min_db_size> size).  (Requires
C<bayes_expiry_use_scan_count> be 0.)

=cut
    if (/^bayes[-_]expiry[-_]days\s+(.*)$/) {
      $self->{bayes_expiry_days} = $1; next;
    }

=item bayes_expiry_scan_count		(default: 5000)

When expiring old entries from the Bayes databases, tokens which have not
been read in this many messages will be removed (unless to do so would
shrink the database below the C<bayes_expiry_min_db_size> size).
(Requires C<bayes_expiry_use_scan_count> be 1.)

=cut
    if (/^bayes[-_]expiry[-_]scan[-_]count\s+(.*)$/) {
      $self->{bayes_expiry_scan_count} = $1; next;
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

=item user_scores_sql_table tablename

The table user preferences are stored in, for the above DSN.

=cut
    if(/^user[-_]scores[-_]sql[-_]table\s+(\S+)$/) {
      $self->{user_scores_sql_table} = $1; next;
    }

###########################################################################

failed_line:
    my $msg = "Failed to parse line in SpamAssassin configuration, ".
                        "skipping: $_";

    if ($self->{lint_rules}) {
      warn $msg."\n";
    } else {
      dbg ($msg);
    }
    $self->{errors}++;
  }
}

sub add_test {
  my ($self, $name, $text, $type) = @_;
  if ($name eq '.') { $name = ($self->{_unnamed_counter}++); }
  $self->{tests}->{$name} = $text;
  $self->{test_types}->{$name} = $type;

  # T_ rules (in a testing probationary period) get low, low scores
  if ($name =~ /^T_/) {
    $self->{scores}->{$name} ||= 0.01;
  } else {
    $self->{scores}->{$name} ||= 1.0;
  }
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
    elsif ($type == $type_rbl_evals) { $self->{rbl_evals}->{$name} = $text; }
    elsif ($type == $type_rbl_res_evals) { $self->{rbl_res_evals}->{$name} = $text; }
    elsif ($type == $type_head_tests) { $self->{head_tests}->{$name} = $text; }
    elsif ($type == $type_head_evals) { $self->{head_evals}->{$name} = $text; }
    elsif ($type == $type_body_evals) { $self->{body_evals}->{$name} = $text; }
    elsif ($type == $type_rawbody_tests) { $self->{rawbody_tests}->{$name} = $text; }
    elsif ($type == $type_rawbody_evals) { $self->{rawbody_evals}->{$name} = $text; }
    elsif ($type == $type_full_tests) { $self->{full_tests}->{$name} = $text; }
    elsif ($type == $type_full_evals) { $self->{full_evals}->{$name} = $text; }
    elsif ($type == $type_uri_tests)  { $self->{uri_tests}->{$name} = $text; }
    # elsif ($type == $type_uri_evals)  { $self->{uri_evals}->{$name} = $text; }
    elsif ($type == $type_meta_tests) { $self->{meta_tests}->{$name} = $text; }
    else {
      # 70 == SA_SOFTWARE
      $self->{errors}++;
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
    $re =~ s/([^\*\?_a-zA-Z0-9])/\\$1/g;		# escape any possible metachars
    $re =~ s/\?/\./g;                           # "?" -> "."
    $re =~ s/\*/\.\*/g;				# "*" -> "any string"
    $self->{$singlelist}->{$addr} = qr/^${re}$/;
  }
}

sub add_to_addrlist_rcvd {
  my ($self, $listname, $addr, $domain) = @_;
  
  my $re = lc $addr;
  $re =~ s/[\000\\\(]/_/gs;			# paranoia
  $re =~ s/([^\*\?_a-zA-Z0-9])/\\$1/g;		# escape any possible metachars
  $re =~ s/\?/\./g;                             # "?" -> "."
  $re =~ s/\*/\.\*/g;				# "*" -> "any string"
  $self->{$listname}->{$addr}{re} = qr/^${re}$/;
  $self->{$listname}->{$addr}{domain} = $domain;
}

sub remove_from_addrlist {
  my ($self, $singlelist, @addrs) = @_;
  
  foreach my $addr (@addrs) {
	delete($self->{$singlelist}->{$addr});
  }
}

sub remove_from_addrlist_rcvd {
  my ($self, $listname, @addrs) = @_;
  foreach my $addr (@addrs) {
    delete($self->{$listname}->{$addr});
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

