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

=head1 TAGS

The following C<tags> can be used as placeholders in certain options
specified below. They will be replaced by the corresponding value when
they are used.

Some tags can take an argument (in parentheses). The argument is
optional, and the default is shown below.

 _YESNOCAPS_       "YES"/"NO" for is/isn't spam
 _YESNO_           "Yes"/"No" for is/isn't spam
 _HITS_            message score
 _REQD_            message threshold
 _VERSION_         version (eg. 2.55)
 _SUBVERSION_      sub-version (eg. 1.187-2003-05-15-exp)
 _HOSTNAME_        hostname
 _BAYES_           bayes score
 _AWL_             AWL modifier
 _DATE_            rfc-2822 date of scan
 _STARS(*)_        score represented in terms of * (any character can be chosen)
 _RELAYSTRUSTED_   relays used and deemed to be trusted
 _RELAYSUNTRUSTED_ relays used that can not be trusted
 _AUTOLEARN_       autolearn status ("ham", "no", "spam")
 _TESTS(,)_        tests hit separated by , (or other separator)
 _TESTSSCORES(,)_  as above, except with scores appended (eg. AWL=-3.0,...)
 _DCCB_            DCC's "Brand"
 _DCCR_            DCC's results
 _PYZOR_           Pyzor results
 _LANGUAGES_       possible languages of mail
 _PREVIEW_         content preview
 _REPORT_          report of tests hits (in terse format, ideal for in headers)
 _SUMMARY_         summary of tests hit for standard report
 _CONTACTADDRESS_  contents of the 'report_contact' setting

=head1 USER PREFERENCES

=over 4

=cut

package Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::Util;
use Mail::SpamAssassin::NetSet;

use strict;
use bytes;

use vars qw{
  @ISA $VERSION
};

@ISA = qw();

# odd => eval test
use constant TYPE_HEAD_TESTS    => 0x0008;
use constant TYPE_HEAD_EVALS    => 0x0009;
use constant TYPE_BODY_TESTS    => 0x000a;
use constant TYPE_BODY_EVALS    => 0x000b;
use constant TYPE_FULL_TESTS    => 0x000c;
use constant TYPE_FULL_EVALS    => 0x000d;
use constant TYPE_RAWBODY_TESTS => 0x000e;
use constant TYPE_RAWBODY_EVALS => 0x000f;
use constant TYPE_URI_TESTS     => 0x0010;
use constant TYPE_URI_EVALS     => 0x0011;
use constant TYPE_META_TESTS    => 0x0012;
use constant TYPE_RBL_EVALS     => 0x0013;

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
  $self->{scoreset} = [ {}, {}, {}, {} ];
  $self->{scoreset_current} = 0;
  $self->set_score_set (0);
  $self->{tflags} = { };
  $self->{source_file} = { };

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
  $self->{report_charset} = '';
  $self->{report_template} = '';
  $self->{unsafe_report_template} = '';
  $self->{spamtrap_template} = '';

  $self->{num_check_received} = 9;

  $self->{use_razor2} = 1;
  $self->{razor_config} = undef;
  $self->{razor_timeout} = 10;

  $self->{rbl_timeout} = 15;

  # this will be sedded by implementation code, so ~ is OK.
  # using "__userstate__" is recommended for defaults, as it allows
  # Mail::SpamAssassin module users who set that configuration setting,
  # to receive the correct values.

  $self->{auto_whitelist_path} = "__userstate__/auto-whitelist";
  $self->{auto_whitelist_file_mode} = '0700';
  $self->{auto_whitelist_factor} = 0.5;

  $self->{rewrite_subject} = 0;
  $self->{subject_tag} = '*****SPAM*****';
  $self->{report_safe} = 1;
  $self->{report_contact} = 'the administrator of that system';
  $self->{skip_rbl_checks} = 0;
  $self->{dns_available} = "test";
  $self->{check_mx_attempts} = 2;
  $self->{check_mx_delay} = 5;
  $self->{ok_locales} = 'all';
  $self->{ok_languages} = 'all';
  $self->{allow_user_rules} = 0;
  $self->{user_rules_to_compile} = 0;
  $self->{fold_headers} = 1;
  $self->{headers_spam} = { };
  $self->{headers_ham} = { };

  $self->{use_dcc} = 1;
  $self->{dcc_path} = undef; # Browse PATH
  $self->{dcc_body_max} = 999999;
  $self->{dcc_fuz1_max} = 999999;
  $self->{dcc_fuz2_max} = 999999;
  $self->{dcc_timeout} = 10;
  $self->{dcc_options} = '-R';

  $self->{use_pyzor} = 1;
  $self->{pyzor_path} = undef; # Browse PATH
  $self->{pyzor_max} = 5;
  $self->{pyzor_timeout} = 10;
  $self->{pyzor_options} = '';

  $self->{use_bayes} = 1;
  $self->{bayes_auto_learn} = 1;
  $self->{bayes_auto_learn_threshold_nonspam} = -2.0;
  $self->{bayes_auto_learn_threshold_spam} = 15.0;
  $self->{bayes_auto_learn_journal} = 0;
  $self->{bayes_path} = "__userstate__/bayes";
  $self->{bayes_file_mode} = "0700";
  $self->{bayes_use_hapaxes} = 1;
  $self->{bayes_use_chi2_combining} = 1;
  $self->{bayes_expiry_max_db_size} = 150000;
  $self->{bayes_auto_expire} = 1;
  $self->{bayes_journal_max_size} = 102400;
  $self->{bayes_ignore_headers} = [ ];
  $self->{bayes_min_ham_num} = 200;
  $self->{bayes_min_spam_num} = 200;
  $self->{bayes_learn_during_report} = 1;

  $self->{whitelist_from} = { };
  $self->{blacklist_from} = { };

  $self->{blacklist_to} = { };
  $self->{whitelist_to} = { };
  $self->{more_spam_to} = { };
  $self->{all_spam_to} = { };

  $self->{trusted_networks} = Mail::SpamAssassin::NetSet->new();

  # this will hold the database connection params
  $self->{user_scores_dsn} = '';
  $self->{user_scores_sql_username} = '';
  $self->{user_scores_sql_password} = '';
  $self->{user_scores_sql_table} = 'userpref'; # Morgan - default to userpref for backwords compatibility
# Michael 'Moose' Dinn, <dinn@twistedpair.ca>
# For integration with Horde's preference storage
# 20020831
  $self->{user_scores_sql_field_username} = 'username';
  $self->{user_scores_sql_field_preference} = 'preference';
  $self->{user_scores_sql_field_value} = 'value';
  $self->{user_scores_sql_field_scope} = 'spamassassin'; # probably shouldn't change this

  # for backwards compatibility, we need to set the default headers
  # remove this for 2.70 (?)

  # unfortunately this backwards compatibility isn't 100% functional.
  # For example, if a user has the following config (consider user and
  # site config...)
  # always_add_headers 0
  # always_add_headers 1
  # Then the 2nd option will do nothing.

  $self->{headers_spam}->{"Flag"} = "_YESNOCAPS_";
  $self->{headers_spam}->{"Status"} = "_YESNO_, hits=_HITS_ required=_REQD_ tests=_TESTS_ autolearn=_AUTOLEARN_ version=_VERSION_";
  $self->{headers_spam}->{"Level"} = "_STARS(*)_";
  $self->{headers_spam}->{"Checker-Version"} = "SpamAssassin _VERSION_ (_SUBVERSION_)";

  $self->{headers_ham}->{"Status"} = $self->{headers_spam}->{"Status"};
  $self->{headers_ham}->{"Level"} = $self->{headers_spam}->{"Level"};
  $self->{headers_ham}->{"Checker-Version"} = $self->{headers_spam}->{"Checker-Version"};

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

sub set_score_set {
  my ($self, $set) = @_;
  $self->{scores} = $self->{scoreset}->[$set];
  $self->{scoreset_current} = $set;
  dbg("Score set $set chosen.");
}

sub get_score_set {
  my($self) = @_;
  return $self->{scoreset_current};
}

sub _parse {
  my ($self, undef, $scoresonly) = @_; # leave $rules in $_[1]
  local ($_);

  # Language selection:
  # See http://www.gnu.org/manual/glibc-2.2.5/html_node/Locale-Categories.html
  # and http://www.gnu.org/manual/glibc-2.2.5/html_node/Using-gettextized-software.html
  my $lang = $ENV{'LANGUAGE'}; # LANGUAGE has the highest precedence but has a 
  if ($lang) {                 # special format: The user may specify more than
    $lang =~ s/:.*$//;         # one language here, colon separated. We use the 
  }                            # first one only (lazy bums we are :o)
  $lang ||= $ENV{'LC_ALL'};
  $lang ||= $ENV{'LC_MESSAGES'};
  $lang ||= $ENV{'LANG'};
  $lang ||= 'C';               # Nothing set means C/POSIX

  if ($lang =~ /^(C|POSIX)$/) {
    $lang = 'en_US';           # Our default language
  } else {
    $lang =~ s/[@.+,].*$//;    # Strip codeset, modifier/audience, etc. 
  }                            # (eg. .utf8 or @euro)

  $self->{currentfile} = '(no file)';
  my $skipfile = 0;

  foreach (split (/\n/, $_[1])) {
    s/(?<!\\)#.*$//; # remove comments
    s/^\s+|\s+$//g;  # remove leading and trailing spaces (including newlines)
    next unless($_); # skip empty lines

    # handle i18n
    if (s/^lang\s+(\S+)\s+//) { next if ($lang !~ /^$1/i); }
    
    # Versioning assertions
    if (/^file\s+start\s+(.+)$/) { $self->{currentfile} = $1; next; }
    if (/^file\s+end/) {
      $self->{currentfile} = '(no file)';
      $skipfile = 0;
      next;
    }

    # convert all dashes in setting name to underscores.
    # Simplifies regexps below...
    1 while s/^(\S+)\-(\S+)/$1_$2/g;

=item require_version n.nn

Indicates that the entire file, from this line on, requires a certain version
of SpamAssassin to run.  If an older or newer version of SpamAssassin tries to
read configuration from this file, it will output a warning instead, and
ignore it.

=cut

    if (/^require_version\s+(.*)$/) {
      my $req_version = $1;
      $req_version =~ s/^\@\@VERSION\@\@$/$Mail::SpamAssassin::VERSION/;
      if ($Mail::SpamAssassin::VERSION != $req_version) {
        warn "configuration file \"$self->{currentfile}\" requires version ".
                "$req_version of SpamAssassin, but this is code version ".
                "$Mail::SpamAssassin::VERSION. Maybe you need to use ".
                "the -C switch, or remove the old config files? ".
                "Skipping this file";
        $skipfile = 1;
        $self->{errors}++;
      }
      next;
    }

    if ($skipfile) { next; }

    # note: no eval'd code should be loaded before the SECURITY line below.
###########################################################################

=item version_tag string

This tag is appended to the SA version in the X-Spam-Status header. You should
include it when modify your ruleset, especially if you plan to distribute it.
A good choice for I<string> is your last name or your initials followed by a
number which you increase with each change.

e.g.

  version_tag myrules1    # version=2.41-myrules1

=cut

    if(/^version_tag\s+(.*)$/) {
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

=item whitelist_from add@ress.com

Used to specify addresses which send mail that is often tagged (incorrectly) as
spam; it also helps if they are addresses of big companies with lots of
lawyers.  This way, if spammers impersonate them, they'll get into big trouble,
so it doesn't provide a shortcut around SpamAssassin.

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

e.g.

  whitelist_from joe@example.com fred@example.com
  whitelist_from *@example.com

=cut

    if (/^whitelist_from\s+(.+)$/) {
      $self->add_to_addrlist ('whitelist_from', split (' ', $1)); next;
    }

=item unwhitelist_from add@ress.com

Used to override a default whitelist_from entry, so for example a distribution
whitelist_from can be overriden in a local.cf file, or an individual user can
override a whitelist_from entry in their own C<user_prefs> file.
The specified email address has to match exactly the address previously
used in a whitelist_from line.

e.g.

  unwhitelist_from joe@example.com fred@example.com
  unwhitelist_from *@example.com

=cut

    if (/^unwhitelist_from\s+(.+)$/) {
      $self->remove_from_addrlist ('whitelist_from', split (' ', $1)); next;
    }

=item whitelist_from_rcvd addr@lists.sourceforge.net sourceforge.net

Use this to supplement the whitelist_from addresses with a check against the
Received headers. The first parameter is the address to whitelist, and the
second is a string to match the relay's rDNS.

This string is matched against the reverse DNS lookup used during the handover
from the untrusted internet to your trusted network's mail exchangers.  It can
either be the full hostname, or the domain component of that hostname.  In
other words, if the host that connected to your MX had an IP address that
mapped to 'sendinghost.spamassassin.org', you should specify
C<sendinghost.spamassassin.org> or just C<spamassassin.org> here.

Note that this requires that C<trusted_networks> be correct.  For simple
cases, it will be, but for a complex network, you may get better results
by setting that parameter.

e.g.

  whitelist_from_rcvd joe@example.com  example.com
  whitelist_from_rcvd *@axkit.org      sergeant.org

=item def_whitelist_from_rcvd addr@lists.sourceforge.net sourceforge.net

Same as C<whitelist_from_rcvd>, but used for the default whitelist entries
in the SpamAssassin distribution.  The whitelist score is lower, because
these are often targets for spammer spoofing.

=cut

    if (/^whitelist_from_rcvd\s+(\S+)\s+(\S+)$/) {
      $self->add_to_addrlist_rcvd ('whitelist_from_rcvd', $1, $2);
      next;
    }
    if (/^def_whitelist_from_rcvd\s+(\S+)\s+(\S+)$/) {
      $self->add_to_addrlist_rcvd ('def_whitelist_from_rcvd', $1, $2);
      next;
    }

=item unwhitelist_from_rcvd add@ress.com

Used to override a default whitelist_from_rcvd entry, so for example a
distribution whitelist_from_rcvd can be overriden in a local.cf file,
or an individual user can override a whitelist_from_rcvd entry in
their own C<user_prefs> file.

The specified email address has to match exactly the address previously
used in a whitelist_from_rcvd line.

e.g.

  unwhitelist_from_rcvd joe@example.com fred@example.com
  unwhitelist_from_rcvd *@axkit.org

=cut

    if (/^unwhitelist_from_rcvd\s+(.+)$/) {
      $self->remove_from_addrlist_rcvd('whitelist_from_rcvd', split (' ', $1));
      $self->remove_from_addrlist_rcvd('def_whitelist_from_rcvd', split (' ', $1));
      next;
    }

=item blacklist_from add@ress.com

Used to specify addresses which send mail that is often tagged (incorrectly) as
non-spam, but which the user doesn't want.  Same format as C<whitelist_from>.

=cut

    if (/^blacklist_from\s+(.+)$/) {
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

    if (/^unblacklist_from\s+(.+)$/) {
      $self->remove_from_addrlist ('blacklist_from', split (' ', $1)); next;
    }


=item whitelist_to add@ress.com

If the given address appears as a recipient in the message headers
(Resent-To, To, Cc, obvious envelope receipient, etc,) the mail will
be whitelisted.  Useful if you're deploying SpamAssassin system-wide,
and don't want some users to have their mail filtered.  Same format
as C<whitelist_from>.

There are three levels of To-whitelisting, C<whitelist_to>, C<more_spam_to>
and C<all_spam_to>.  Users in the first level may still get some spammish
mails blocked, but users in C<all_spam_to> should never get mail blocked.

=item more_spam_to add@ress.com

See above.

=item all_spam_to add@ress.com

See above.

=cut

    if (/^whitelist_to\s+(.+)$/) {
      $self->add_to_addrlist ('whitelist_to', split (' ', $1)); next;
    }
    if (/^more_spam_to\s+(.+)$/) {
      $self->add_to_addrlist ('more_spam_to', split (' ', $1)); next;
    }
    if (/^all_spam_to\s+(.+)$/) {
      $self->add_to_addrlist ('all_spam_to', split (' ', $1)); next;
    }

=item blacklist_to add@ress.com

If the given address appears as a recipient in the message headers
(Resent-To, To, Cc, obvious envelope receipient, etc,) the mail will
be blacklisted.  Same format as C<blacklist_from>.

=cut

    if (/^blacklist_to\s+(.+)$/) {
      $self->add_to_addrlist ('blacklist_to', split (' ', $1)); next;
    }

=item required_hits n.nn   (default: 5)

Set the number of hits required before a mail is considered spam.  C<n.nn> can
be an integer or a real number.  5.0 is the default setting, and is quite
aggressive; it would be suitable for a single-user setup, but if you're an ISP
installing SpamAssassin, you should probably set the default to be more
conservative, like 8.0 or 10.0.  It is not recommended to automatically delete
or discard messages marked as spam, as your users B<will> complain, but if you
choose to do so, only delete messages with an exceptionally high score such as
15.0 or higher.

=cut

    if (/^required_hits\s+(\S+)$/) {
      $self->{required_hits} = $1+0.0; next;
    }

=item score SYMBOLIC_TEST_NAME n.nn [ n.nn n.nn n.nn ]

Assign scores (the number of points for a hit) to a given test. Scores can
be positive or negative real numbers or integers. C<SYMBOLIC_TEST_NAME> is
the symbolic name used by SpamAssassin for that test; for example,
'FROM_ENDS_IN_NUMS'.

If only one valid score is listed, then that score is always used for a
test.

If four valid scores are listed, then the score that is used depends on how
SpamAssassin is being used. The first score is used when both Bayes and
network tests are disabled. The second score is used when Bayes is disabled,
but network tests are enabled. The third score is used when Bayes is enabled
and network tests are disabled. The fourth score is used when Bayes is
enabled and network tests are enabled.

Setting a rule's score to 0 will disable that rule from running.

Note that test names which begin with '__' are reserved for meta-match
sub-rules, and are not scored or listed in the 'tests hit' reports.

If no score is given for a test, the default score is 1.0, or 0.01 for
tests whose names begin with 'T_' (this is used to indicate a rule in
testing).

By convention, rule names are be all uppercase and have a length of no
more than 22 characters.

=cut

  if (my ($rule, $scores) = /^score\s+(\S+)\s+(.*)$/) {
    my @scores = ($scores =~ /(\-*[\d\.]+)(?:\s+|$)/g);
    if (scalar @scores == 4) {
      for my $index (0..3) {
	$self->{scoreset}->[$index]->{$rule} = $scores[$index] + 0.0;
      }
    }
    elsif (scalar @scores > 0) {
      for my $index (0..3) {
	$self->{scoreset}->[$index]->{$rule} = $scores[0] + 0.0;
      }
    }
    next;
  }

=item rewrite_subject { 0 | 1 }        (default: 0)

By default, the subject lines of suspected spam will not be tagged.  This can
be enabled here.

=cut

    if (/^rewrite_subject\s+(\d+)$/) {
      $self->{rewrite_subject} = $1+0; next;
    }

=item fold_headers { 0 | 1 }        (default: 1)

By default, headers added by SpamAssassin will be whitespace folded,
in other words, they will be broken up into multiple lines instead of
one very long one. This can be disabled here.

=cut

   if (/^fold_headers\s+(\d+)$/) {
     $self->{fold_headers} = $1+0; next;
   }

=item add_header header_name { ham | spam | all } string

Customized headers can be added to ham, spam or both, giving various
bits of information. All headers added will begin with X-Spam- (so
C<header_name> will be appended to X-Spam-).

C<string> can contain tags as explained above. Headers will be folded
if fold_headers is set to C<1>.

For backwards compatibility, some headers are (still) added by
default. Please use the clear_headers option before adding headers of
your own.

Examples (these were all default prior to 2.60):
 add_header Flag spam _YESNOCAPS_
 add_header Status all _YESNO_, hits=_HITS_ required=_REQD_ tests=_TESTS_ autolearn=_AUTOLEARN_ version=_VERSION_
 add_header Level all _STARS(*)_
 add_header Checker-Version all SpamAssassin _VERSION_ (_SUBVERSION_)


=cut

    if (/^add_header\s+([A-Za-z0-9_-]+)\s+(ham|spam|all)\s+(.*?)\s*$/) {
      my ($name, $type, $line) = ($1, $2, $3);
      if ($line =~ /^"(.*)"$/) {
	$line = $1;
      }
      $line =~ s/\\t/\t/;
      $line =~ s/\\n/\n/;
      if (($type eq "ham") || ($type eq "all")) {
	$self->{headers_ham}->{$name} = $line;
      }
      if (($type eq "spam") || ($type eq "all")) {
	$self->{headers_spam}->{$name} = $line;
      }
      next;
    }

=item clear_headers

Clear list of headers to be added to mail. You should use this before
any add_header options to prevent all the default headers from being
added to mail.

=cut

    if (/^clear_headers\s*$/) {
      $self->{headers_ham} = { };
      $self->{headers_spam} = { };
      next;
    }

=item report_safe_copy_headers { header_name }

If using report_safe, a few of the headers from the original message
are copied into the wrapper header (From, To, Cc, Subject, Date, etc.)
If you want to have other headers copied as well, you can add them
using this option.  You can specify multiple headers on the same line,
seperated by spaces, or you can just use multiple lines.

=cut

   if (/^report_safe_copy_headers\s+(.+?)\s*$/) {
     push(@{$self->{report_safe_copy_headers}}, split(/\s+/, $1));
     next;
   }

=item subject_tag STRING ... 		(default: *****SPAM*****)

Text added to the C<Subject:> line of mails that are considered spam,
if C<rewrite_subject> is 1. Tags can be used here as with the
add_header option. If report_safe is not used (see below), you may
only use the _HITS_ and _REQD_ tags, or SpamAssassin will not be able
to remove this markup from your message.

=cut

    if (/^subject_tag\s+(.+)$/) {
      $self->{subject_tag} = $1; next;
    }

=item report_safe { 0 | 1 | 2 }	(default: 1)

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
some headers and no changes will be made to the body.

=cut

    if (/^report_safe\s+(\d+)$/) {
      $self->{report_safe} = $1+0; next;
    }

=item skip_rbl_checks { 0 | 1 }   (default: 0)

By default, SpamAssassin will run RBL checks.  If your ISP already does this
for you, set this to 1.

=cut

    if (/^skip_rbl_checks\s+(\d+)$/) {
      $self->{skip_rbl_checks} = $1+0; next;
    }

=item ok_languages xx [ yy zz ... ]		(default: all)

Which languages are considered OK to receive mail in.  SpamAssassin will try to
detect the language used in the message text.

Note that the language cannot always be recognized reliably.  In that case, no
points will be assigned.

The rule C<UNDESIRED_LANGUAGE_BODY> is triggered based on how this is set.

The following languages are recognized.  In your configuration, you must use
the language specifier located in the first column, not the English name for
the language.  You may also specify C<all> if your language is not listed, or
if you want to allow any language.  The default setting is C<all>.

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

=item ga	irish gaelic

=item gd	scottish gaelic

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

examples:

  ok_languages all         (allow all languages)
  ok_languages en          (only allow English)
  ok_languages en ja zh    (allow English, Japanese, and Chinese)

Note: if there are multiple ok_languages lines, only the last one is used.

=cut

    if (/^ok_languages\s+(.+)$/) {
      $self->{ok_languages} = $1; next;
    }

=item ok_locales xx [ yy zz ... ]		(default: all)

Which locales (country codes) are considered OK to receive mail from.  Mail
using B<character sets> used by languages in these countries, will not be
marked as possibly being spam in a foreign language.

If you receive lots of spam in foreign languages, and never get any non-spam in
these languages, this may help.  Note that all ISO-8859-* character sets, and
Windows code page character sets, are always permitted by default.

Set this to C<all> to allow all character sets.  This is the default.

The rules C<CHARSET_FARAWAY>, C<CHARSET_FARAWAY_BODY>, and
C<CHARSET_FARAWAY_HEADERS> are triggered based on how this is set.

Select the locales to allow from the list below:

=over 4

=item en

Western character sets in general

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

examples:

  ok_locales all         (allow all locales)
  ok_locales en          (only allow English)
  ok_locales en ja zh    (allow English, Japanese, and Chinese)

Note: if there are multiple ok_locales lines, only the last one is used.

=cut

    if (/^ok_locales\s+(.+)$/) {
      $self->{ok_locales} = $1; next;
    }

=item describe SYMBOLIC_TEST_NAME description ...

Used to describe a test.  This text is shown to users in the detailed report.

Note that test names which begin with '__' are reserved for meta-match
sub-rules, and are not scored or listed in the 'tests hit' reports.

Also note that by convention, rule descriptions should be limited in
length to no more than 50 characters.

=cut

    if (/^describe\s+(\S+)\s+(.*)$/) {
      $self->{descriptions}->{$1} = $2; next;
    }

=item tflags SYMBOLIC_TEST_NAME [ { net | nice | learn | userconf } ... ]

Used to set flags on a test.  These flags are used in the score-determination
back end system for details of the test's behaviour.  The following flags can
be set:

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

=back

=cut

    if (/^tflags\s+(\S+)\s+(.+)$/) {
      $self->{tflags}->{$1} = $2; next;
      next;     # ignored in SpamAssassin modules
    }


=item report_charset CHARSET		(default: unset)

Set the MIME Content-Type charset used for the text/plain report which
is attached to spam mail messages.

=cut

    if (/^report_charset\s*(.*)$/) {
      $self->{report_charset} = $1; next;
    }

=item report ...some text for a report...

Set the report template which is attached to spam mail messages.  See the
C<10_misc.cf> configuration file in C</usr/share/spamassassin> for an
example.

If you change this, try to keep it under 78 columns. Each C<report>
line appends to the existing template, so use C<clear_report_template>
to restart.

Tags can be included as explained above.

=cut

    if (/^report\b\s*(.*?)\s*$/) {
      my $report = $1;
      if ( $report =~ /^"(.*?)"$/ ) {
        $report = $1;
      }

      $self->{report_template} .= "$report\n"; next;
    }

=item clear_report_template

Clear the report template.

=cut

    if (/^clear_report_template$/) {
      $self->{report_template} = ''; next;
    }

=item report_contact ...text of contact address...

Set what _CONTACTADDRESS_ is replaced with in the above report text.
By default, this is 'the administrator of that system', since the hostname
of the system the scanner is running on is also included.

=cut

    if (/^report_contact\s+(.*?)\s*$/) {
      $self->{report_contact} = $1; next;
    }

=item unsafe_report ...some text for a report...

Set the report template which is attached to spam mail messages which contain a
non-text/plain part.  See the C<10_misc.cf> configuration file in
C</usr/share/spamassassin> for an example.

Each C<unsafe-report> line appends to the existing template, so use
C<clear_unsafe_report_template> to restart.

Tags can be used in this template (see above for details).

=cut

    if (/^unsafe_report\b\s*(.*?)$/) {
      my $report = $1;
      if ( $report =~ /^"(.*?)"$/ ) {
        $report = $1;
      }

      $self->{unsafe_report_template} .= "$report\n"; next;
    }

=item clear_unsafe_report_template

Clear the unsafe_report template.

=cut

    if (/^clear_unsafe_report_template$/) {
      $self->{unsafe_report_template} = ''; next;
    }

=item spamtrap ...some text for spamtrap reply mail...

A template for spam-trap responses.  If the first few lines begin with
C<Xxxxxx: yyy> where Xxxxxx is a header and yyy is some text, they'll be used
as headers.  See the C<10_misc.cf> configuration file in
C</usr/share/spamassassin> for an example.

Unfortunately tags can not be used with this option.

=cut

    if (/^spamtrap\s*(.*?)$/) {
      my $report = $1;
      if ( $report =~ /^"(.*?)"$/ ) {
        $report = $1;
      }
      $self->{spamtrap_template} .= "$report\n"; next;
    }

=item clear_spamtrap_template

Clear the spamtrap template.

=cut

    if (/^clear_spamtrap_template$/) {
      $self->{spamtrap_template} = ''; next;
    }

=item use_dcc ( 0 | 1 )		(default 1)

Whether to use DCC, if it is available.

=cut

    if (/^use_dcc\s+(\d+)$/) {
      $self->{use_dcc} = $1; next;
    }

=item dcc_timeout n              (default: 10)

How many seconds you wait for dcc to complete before you go on without 
the results

=cut

    if (/^dcc_timeout\s+(\d+)$/) {
      $self->{dcc_timeout} = $1+0; next;
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

    if (/^dcc_body_max\s+(\d+)/) {
      $self->{dcc_body_max} = $1+0; next;
    }

    if (/^dcc_fuz1_max\s+(\d+)/) {
      $self->{dcc_fuz1_max} = $1+0; next;
    }

    if (/^dcc_fuz2_max\s+(\d+)/) {
      $self->{dcc_fuz2_max} = $1+0; next;
    }


=item use_pyzor ( 0 | 1 )		(default 1)

Whether to use Pyzor, if it is available.

=cut

    if (/^use_pyzor\s+(\d+)$/) {
      $self->{use_pyzor} = $1; next;
    }

=item pyzor_timeout n              (default: 10)

How many seconds you wait for Pyzor to complete before you go on without 
the results.

=cut

    if (/^pyzor_timeout\s+(\d+)$/) {
      $self->{pyzor_timeout} = $1+0; next;
    }

=item pyzor_max NUMBER

Pyzor is a system similar to Razor.  This option sets how often a message's
body checksum must have been reported to the Pyzor server before SpamAssassin
will consider the Pyzor check as matched.

The default is 5.

=cut

    if (/^pyzor_max\s+(\d+)/) {
      $self->{pyzor_max} = $1+0; next;
    }



=item pyzor_options options

Specify options to the pyzor command. Please note that only
[A-Za-z0-9 -/] is allowed (security).

=cut

    if (/^pyzor_options\s+([A-Za-z0-9 -\/]+)/) {
      $self->{pyzor_options} = $1; next;
    }

=item num_check_received { integer }   (default: 9)

How many received lines from and including the original mail relay
do we check in RBLs (at least 1 or 2 is recommended).

Note that for checking against dialup lists, you can call C<check_rbl()> with a
special set name of B<set-notfirsthop> and this rule will only be matched
against the relays except for the very first one; this allows SpamAssassin to
catch dialup-sent spam, without penalizing people who properly relay through
their ISP.

See also C<trusted_networks>, to specify which the relays you trust.  This
is a much better way to control DNSBL-checking behaviour.

=cut

    if (/^num_check_received\s+(\d+)$/) {
      $self->{num_check_received} = $1+0; next;
    }

=item trusted_networks ip.add.re.ss[/mask] ...   (default: none)

What networks or hosts are 'trusted' in your setup.   B<Trusted> in this case
means that relay hosts on these networks are considered to not be potentially
operated by spammers, open relays, or open proxies.  DNS blacklist checks
will never query for hosts on these networks.

If a C</mask> is specified, it's considered a CIDR-style 'netmask', specified
in bits.  If it is not specified, but less than 4 octets are specified with a
trailing dot, that's considered a mask to allow all addresses in the remaining
octets.  If a mask is not specified, and there is not trailing dot, then just
the single IP address specified is used, as if the mask was C</32>.

Examples:

    trusted_networks 192.168/16 127/8		# all in 192.168.*.* and 127.*.*.*
    trusted_networks 212.17.35.15		# just that host
    trusted_networks 127.			# all in 127.*.*.*

This operates additively, so a C<trusted_networks> line after another one
will result in all those networks becoming trusted.  To clear out the
existing entries, use C<clear_trusted_networks>.

SpamAssassin includes code to infer your trusted networks on the fly, so
this may not be necessary.  This inference works as follows:

=over 4

=item if the 'from' IP address is on the same /16 network as the top Received
line's, it's trusted

=item if the address of the 'from' host is in a reserved network range,
then it's trusted

=item if any addresses of the 'by' host is in a reserved network range,
then it's trusted

=back

(Thanks to Scott Banister and Andrew Flury for the inspiration for this
algorithm.)

=cut

    if (/^trusted_networks\s+(.+)$/) {
      foreach my $net (split (' ', $1)) {
	$self->{trusted_networks}->add_cidr ($net);
      }
      next;
    }

=item clear_trusted_networks

Empty the list of trusted networks.

=cut

    if (/^clear_trusted_networks$/) {
      $self->{trusted_networks} = Mail::SpamAssassin::NetSet->new(); next;
    }

=item use_razor2 ( 0 | 1 )		(default 1)

Whether to use Razor version 2, if it is available.

=cut

    if (/^use_razor2\s+(\d+)$/) {
      $self->{use_razor2} = $1; next;
    }

=item razor_timeout n		(default 10)

How many seconds you wait for razor to complete before you go on without 
the results

=cut

    if (/^razor_timeout\s+(\d+)$/) {
      $self->{razor_timeout} = $1; next;
    }

=item use_bayes ( 0 | 1 )		(default 1)

Whether to use the naive-Bayesian-style classifier built into SpamAssassin.

=cut

    if (/^use_bayes\s+(\d+)$/) {
      $self->{use_bayes} = $1; next;
    }

=item rbl_timeout n		(default 15)

All RBL queries are started at the beginning and we try to read the results at
the end.  This value specifies the maximum period of time to wait for an RBL
query.  If most of the RBL queries have succeeded for a particular message,
then SpamAssassin will not wait for the full period to avoid wasting time on
unresponsive server(s).  For the default 15 second timeout, here is a chart of
queries remaining versus the effective timeout in seconds:

  queries left    100%  90%  80%  70%  60%  50%  40%  30%  20%  10%  0%
  timeout          15   15   14   14   13   11   10    8    5    3   0

In addition, whenever the effective timeout is lowered due to additional query
results returning, the remaining queries are always given at least one more
second before timing out.

For example, if 20 queries are made at the beginning of a message check and 16
queries have returned (leaving 20%), the remaining 4 queries must finish
within 5 seconds of the beginning of the check or they will be timed out.

=cut

    if (/^rbl_timeout\s+(\d+)$/) {
      $self->{rbl_timeout} = $1+0; next;
    }

=item check_mx_attempts n	(default: 2)

By default, SpamAssassin checks the From: address for a valid MX this many
times, waiting 5 seconds each time.

=cut

    if (/^check_mx_attempts\s+(\S+)$/) {
      $self->{check_mx_attempts} = $1+0; next;
    }

=item check_mx_delay n		(default 5)

How many seconds to wait before retrying an MX check.

=cut

    if (/^check_mx_delay\s+(\S+)$/) {
      $self->{check_mx_delay} = $1+0; next;
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

Please note, the DNS test queries for MX records so if you specify your
own list of servers, please make sure to choose the one(s) which has an
associated MX record.

=cut

    if (/^dns_available\s+(yes|no|test|test:\s+.+)$/) {
      $self->{dns_available} = ($1 or "test"); next;
    }

=item auto_whitelist_factor n	(default: 0.5, range [0..1])

How much towards the long-term mean for the sender to regress a message.
Basically, the algorithm is to track the long-term mean score of messages for
the sender (C<mean>), and then once we have otherwise fully calculated the
score for this message (C<score>), we calculate the final score for the
message as:

C<finalscore> = C<score> +  (C<mean> - C<score>) * C<factor>

So if C<factor> = 0.5, then we'll move to half way between the calculated
score and the mean.  If C<factor> = 0.3, then we'll move about 1/3 of the way
from the score toward the mean.  C<factor> = 1 means just use the long-term
mean; C<factor> = 0 mean just use the calculated score.

=cut
    if (/^auto_whitelist_factor\s+(.*)$/) {
      $self->{auto_whitelist_factor} = $1; next;
    }

=item bayes_auto_learn ( 0 | 1 )      (default: 1)

Whether SpamAssassin should automatically feed high-scoring mails (or
low-scoring mails, for non-spam) into its learning systems.  The only
learning system supported currently is a naive-Bayesian-style classifier.

Note that certain tests are ignored when determining whether a message
should be trained upon:
 - auto-whitelist (AWL)
 - rules with tflags set to 'learn' (the Bayesian rules)
 - rules with tflags set to 'userconf' (user white/black-listing rules, etc)

Also note that auto-training occurs using scores from either scoreset
0 or 1, depending on what scoreset is used during message check.  It is
likely that the message check and auto-train scores will be different.

=cut

    if (/^(?:bayes_)?auto_learn\s+(.*)$/) {
      $self->{bayes_auto_learn} = $1+0; next;
    }

=item bayes_auto_learn_threshold_nonspam n.nn	(default -2.0)

The score threshold below which a mail has to score, to be fed into
SpamAssassin's learning systems automatically as a non-spam message.

=cut

    if (/^(?:bayes_)?auto_learn_threshold_nonspam\s+(.*)$/) {
      $self->{bayes_auto_learn_threshold_nonspam} = $1+0; next;
    }

=item bayes_auto_learn_threshold_spam n.nn	(default 15.0)

The score threshold above which a mail has to score, to be fed into
SpamAssassin's learning systems automatically as a spam message.

=cut

    if (/^(?:bayes_)?auto_learn_threshold_spam\s+(.*)$/) {
      $self->{bayes_auto_learn_threshold_spam} = $1+0; next;
    }

=item bayes_auto_learn_journal  	(default 0)

If this option is set, when SpamAssassin does Bayes autolearning, it
will put the information into the journal instead of directly into the
database.  This lowers contention for locking the database for a write,
but will also cause more access to the journal and will cause new tokens
to not be used until the journal is syncronized into the database.

=cut

    if (/^bayes_auto_learn_journal\s+(.*)$/) {
      $self->{bayes_auto_learn_journal} = $1+0; next;
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
    if (/^bayes_ignore_header\s+(.*)$/) {
      push (@{$self->{bayes_ignore_headers}}, $1); next;
    }

=item bayes_min_ham_num			(Default: 200)
=item bayes_min_spam_num		(Default: 200)

To be accurate, the Bayes system does not activate until a certain number of
ham (non-spam) and spam have been learned.  The default is 200 of each ham and
spam, but you can tune these up or down with these two settings.

=cut

    if (/^bayes_min_ham_num\s+(.*)$/) {
      $self->{bayes_min_ham_num} = $1+0; next;
    }

    if (/^bayes_min_spam_num\s+(.*)$/) {
      $self->{bayes_min_spam_num} = $1+0; next;
    }

=item bayes_learn_during_report         (Default: 1)

The Bayes system will, by default, learn any reported messages
(spamassassin -r) as spam.  If you do not want this to happen, set
this option to 0.

=cut

    if (/^bayes_learn_during_report\s+(.*)$/) {
      $self->{bayes_learn_during_report} = $1+0; next;
    }


=item always_add_headers { 0 | 1 }      (default: 1)

By default, B<X-Spam-Status>, B<X-Spam-Checker-Version>, (and optionally
B<X-Spam-Level>) will be added to all messages scanned by SpamAssassin.  If you
don't want to add the headers to non-spam, set this value to 0.  See also
B<always_add_report>.

As of version 2.60 this is deprecated. It will be removed in a future
version. (Use the add_header option to customize headers.)

=cut

   if (/^always_add_headers\s+(\d+)$/) {
     if ($1 == 0){
       delete $self->{headers_ham}->{"Status"};
       delete $self->{headers_ham}->{"Checker-Version"};
       delete $self->{headers_ham}->{"Level"};
     }
     next;
   }


=item always_add_report { 0 | 1 }	(default: 0)

By default, mail tagged as spam includes a report, either in the
headers or in an attachment (report_safe). If you set this to option
to C<1>, the report will be included in the B<X-Spam-Report> header,
even if the message is not tagged as spam.

This option is deprecated as of version 2.60. Please use the
add_header option instead:

add_header Report ham _REPORT_

=cut

  if (/^always_add_report\s+(\d+)$/) {
    if ($1 == 1) {
      $self->{headers_ham}->{"Report"} = "_REPORT_";
    }
    next;
  }

=item spam_level_stars { 0 | 1 }        (default: 1)

By default, a header field called "X-Spam-Level" will be added to the message,
with its value set to a number of asterisks equal to the score of the message.
In other words, for a message scoring 7.2 points:

X-Spam-Level: *******

This can be useful for MUA rule creation.

This is deprecated as of version 2.60. Please use the add_header
option instead:

add_header Level all _STARS(*)_

=cut

   if(/^spam_level_stars\s+(\d+)$/) {
     if ($1 == 0) {
       delete $self->{headers_ham}->{"Level"};
     }
     next;
   }

=item spam_level_char { x (some character, unquoted) }        (default: *)

By default, the "X-Spam-Level" header will use a '*' character with
its length equal to the score of the message. Some people don't like
escaping *s though, so you can set the character to anything with this
option.

In other words, for a message scoring 7.2 points with this option set to .

X-Spam-Level: .......

This is deprecated as of version 2.60. Please use the add_header
option instead:

add_header Level all _STARS(.)_

=cut

   if(/^spam_level_char\s+(.)$/) {
     $self->{headers_ham}->{"Level"} = "_STARS($1)_";
     next;
   }

=item dcc_add_header { 0 | 1 }   (default: 0)

DCC processing creates a message header containing the statistics for the
message.  This option sets whether SpamAssassin will add the heading to
messages it processes.

The default is to not add the header.

This is deprecated as of 2.60. Use the add_header option instead. For example:
add_header DCC all _DCCB_: _DCCR_

=cut

    if (/^dcc_add_header\s+(\d+)$/) {
      if ($1 == 1) {
	$self->{headers_spam}->{"DCC"} = "_DCCB_: _DCCR_";
	$self->{headers_ham}->{"DCC"} = $self->{headers_spam}->{"DCC"};
      }
      next;
    }

=item pyzor_add_header { 0 | 1 }   (default: 0)

Pyzor processing creates a message header containing the statistics for the
message.  This option sets whether SpamAssassin will add the heading to
messages it processes.

The default is to not add the header.

This option is deprecated. Please use the add_header option instead:

add_header Pyzor all _PYZOR_

=cut

    if (/^pyzor_add_header\s+(\d+)$/) {
      if ($1 == 1) {
	$self->{headers_spam}->{"Pyzor"} = "_PYZOR_";
	$self->{headers_ham}->{"Pyzor"} = "_PYZOR_";
      }
      next;
    }

=item use_terse_report { 0 | 1 }   (default: 0)

By default, SpamAssassin uses a long report format, explaining what
happened to the mail message, for newbie users.   If you would prefer
shorter reports, set this to C<1>.

This option is deprecated. Longer reports are used by default, with
the report_safe option. If you wish to use a shorter report in the
headers of spam messages, use the following option:

add_header Report spam _REPORT_

=cut

    if (/^use_terse_report\s+(\d+)$/) {
      if($1 == 1) {
	$self->{headers_spam}->{"Report"} = "_REPORT_";
      }
      next;
    }


=item terse_report ...some text for a report...

Set the report template which is attached to spam mail messages, for the
terse-report format.  See the C<10_misc.cf> configuration file in
C</usr/share/spamassassin> for an example.

This option is deprecated and does nothing.

=cut

    if (/^terse_report\b\s*(.*?)$/) {
      next;
    }

=item clear_terse_report_template

Clear the terse-report template. Deprecated.

=cut

    if (/^clear_terse_report_template$/) {
      next;
    }



###########################################################################
    # SECURITY: no eval'd code should be loaded before this line.
    #
    if ($scoresonly && !$self->{allow_user_rules}) { goto failed_line; }

    if ($scoresonly) { dbg("Checking privileged commands in user config"); }

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

    if (/^allow_user_rules\s+(\d+)$/) {
      $self->{allow_user_rules} = $1+0; 
      dbg( ($self->{allow_user_rules} ? "Allowing":"Not allowing") . " user rules!"); next;
    }

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

Test names should not start with a number, and must contain only alphanumerics
and underscores.  It is suggested that lower-case characters not be used, as an
informal convention.  Dashes are not allowed.

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

=item header SYMBOLIC_TEST_NAME rbleval:check_rbl('set', 'zone')

Check a DNSBL (DNS blacklist), also known as RBLs (realtime blacklists).  This
will retrieve Received headers from the mail, parse the IP addresses, select
which ones are 'untrusted' based on the C<trusted_networks> logic, and query
that blacklist.  There's a few things to note:

=over 4

=item Duplicated or reserved IPs

These are stripped, and the DNSBLs will not be queried for them.  Reserved IPs
are those listed in <http://www.iana.org/assignments/ipv4-address-space>,
<http://duxcw.com/faq/network/privip.htm>, or
<http://duxcw.com/faq/network/autoip.htm>.

=item The first argument, 'set'

This is used as a 'zone ID'.  If you want to look up a multi-meaning zone like
relays.osirusoft.com, you can then query the results from that zone using it;
but all check_rbl_sub() calls must use that zone ID.

Also, if an IP gets a hit in one lookup in a zone using that ID, any further
hits in other rules using that zone ID will *not* be added to the score.

=item Selecting all IPs except for the originating one

This is accomplished by naming the set 'foo-notfirsthop'.  Useful for querying
against DNS lists which list dialup IP addresses; the first hop may be a
dialup, but as long as there is at least one more hop, via their outgoing
SMTP server, that's legitimate, and so should not gain points.  If there
is only one hop, that will be queried anyway, as it should be relaying
via its outgoing SMTP server instead of sending directly to your MX.

=item Selecting just the most recent untrusted Received header

When checking a 'nice' DNSBL (a DNS whitelist?), you cannot trust
Received headers further back than the very first 'untrusted' one.
This is accomplished by naming the set 'foo-lastuntrusted'.

=back

=item header SYMBOLIC_TEST_NAME rbleval:check_rbl_txt('set', 'zone')

Same as check_rbl(), except querying using IN TXT instead of IN A records.
If the zone supports it, it will result in a line of text describing
why the IP is listed, typically a hyperlink to a database entry.

=cut
    if (/^header\s+(\S+)\s+rbleval:(.*)$/) {
      $self->add_test ($1, $2, TYPE_RBL_EVALS);
      $self->{user_rules_to_compile} = 1 if $scoresonly;
      next;
    }
    if (/^header\s+(\S+)\s+eval:(.*)$/) {
      $self->add_test ($1, $2, TYPE_HEAD_EVALS);
      $self->{user_rules_to_compile} = 1 if $scoresonly;
      next;
    }
    if (/^header\s+(\S+)\s+exists:(.*)$/) {
      $self->add_test ($1, "$2 =~ /./", TYPE_HEAD_TESTS);
      $self->{descriptions}->{$1} = "Found a $2 header";
      $self->{user_rules_to_compile} = 1 if $scoresonly;
      next;
    }
    if (/^header\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, TYPE_HEAD_TESTS);
      $self->{user_rules_to_compile} = 1 if $scoresonly;
      next;
    }

=item body SYMBOLIC_TEST_NAME /pattern/modifiers

Define a body pattern test.  C<pattern> is a Perl regular expression.

The 'body' in this case is the textual parts of the message body;
any non-text MIME parts are stripped, and the message decoded from
Quoted-Printable or Base-64-encoded format if necessary.  The message
Subject header is considered part of the body and becomes the first
paragraph when running the rules.  All HTML tags and line breaks will
be removed before matching.

=item body SYMBOLIC_TEST_NAME eval:name_of_eval_method([args])

Define a body eval test.  See above.

=cut
    if (/^body\s+(\S+)\s+eval:(.*)$/) {
      $self->add_test ($1, $2, TYPE_BODY_EVALS);
      $self->{user_rules_to_compile} = 1 if $scoresonly;
      next;
    }
    if (/^body\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, TYPE_BODY_TESTS);
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
#      $self->add_test ($1, $2, TYPE_URI_EVALS);
#      $self->{user_rules_to_compile} = 1 if $scoresonly;
#      next;
#    }
    if (/^uri\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, TYPE_URI_TESTS);
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
      $self->add_test ($1, $2, TYPE_RAWBODY_EVALS);
      $self->{user_rules_to_compile} = 1 if $scoresonly;
      next;
    }
    if (/^rawbody\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, TYPE_RAWBODY_TESTS);
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
      $self->add_test ($1, $2, TYPE_FULL_EVALS);
      $self->{user_rules_to_compile} = 1 if $scoresonly;
      next;
    }
    if (/^full\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, TYPE_FULL_TESTS);
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

If you want to define a meta-rule, but do not want its individual sub-rules to
count towards the final score unless the entire meta-rule matches, give the
sub-rules names that start with '__' (two underscores).  SpamAssassin will
ignore these for scoring.

=cut

    if (/^meta\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, TYPE_META_TESTS);
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

Define a regression testing string. You can have more than one regression test
string per symbolic test name. Simply specify a string that you wish the test
to match.

These tests are only run as part of the test suite - they should not affect the
general running of SpamAssassin.

=cut

    if (/^test\s+(\S+)\s+(ok|fail)\s+(.*)$/) {
      $self->add_regression_test($1, $2, $3); next;
    }

=item razor_config filename

Define the filename used to store Razor's configuration settings.
Currently this is left to Razor to decide.

=cut

    if (/^razor_config\s+(.*)$/) {
      $self->{razor_config} = $1; next;
    }

=item pyzor_path STRING

This option tells SpamAssassin specifically where to find the C<pyzor> client
instead of relying on SpamAssassin to find it in the current PATH.
Note that if I<taint mode> is enabled in the Perl interpreter, you should
use this, as the current PATH will have been cleared.

=cut

    if (/^pyzor_path\s+(.+)$/) {
      $self->{pyzor_path} = $1; next;
    }

=item dcc_home STRING

This option tells SpamAssassin specifically where to find the dcc homedir.
If C<dcc_path> is not specified, it will default to looking in C<dcc_home/bin>
for dcc client instead of relying on SpamAssassin to find it in the current PATH.
If it isn't found there, it will look in the current PATH. If a C<dccifd> socket
is found in C<dcc_home>, it will use that interface that instead of C<dccproc>.

=cut

    if (/^dcc[-_]home\s+(.+)$/) {
      $self->{dcc_home} = $1; next;
    }

=item dcc_dccifd_path STRING

This option tells SpamAssassin specifically where to find the dccifd socket.
If C<dcc_dccifd_path> is not specified, it will default to looking in C<dcc_home>
If a C<dccifd> socket is found, it will use it instead of C<dccproc>.

=cut

    if (/^dcc[-_]dccifd[-_]path\s+(.+)$/) {
      $self->{dcc_dccifd_path} = $1; next;
    }

=item dcc_path STRING

This option tells SpamAssassin specifically where to find the C<dccproc>
client instead of relying on SpamAssassin to find it in the current PATH.
Note that if I<taint mode> is enabled in the Perl interpreter, you should
use this, as the current PATH will have been cleared.

=cut

    if (/^dcc_path\s+(.+)$/) {
      $self->{dcc_path} = $1; next;
    }

=item dcc_options options

Specify additional options to the dccproc(8) command. Please note that only
[A-Z -] is allowed (security).

The default is C<-R>

=cut

    if (/^dcc_options\s+([A-Z -]+)/) {
      $self->{dcc_options} = $1; next;
    }

=item auto_whitelist_path /path/to/file	(default: ~/.spamassassin/auto-whitelist)

Automatic-whitelist directory or file.  By default, each user has their own, in
their C<~/.spamassassin> directory with mode 0700, but for system-wide
SpamAssassin use, you may want to share this across all users.

=cut

    if (/^auto_whitelist_path\s+(.*)$/) {
      $self->{auto_whitelist_path} = $1; next;
    }

=item bayes_path /path/to/file	(default: ~/.spamassassin/bayes)

Path for Bayesian probabilities databases.  Several databases will be created,
with this as the base, with C<_toks>, C<_seen> etc. appended to this filename;
so the default setting results in files called C<~/.spamassassin/bayes_seen>,
C<~/.spamassassin/bayes_toks> etc.

By default, each user has their own, in their C<~/.spamassassin> directory with
mode 0700/0600, but for system-wide SpamAssassin use, you may want to reduce
disk space usage by sharing this across all users.  (However it should be noted
that Bayesian filtering appears to be more effective with an individual
database per user.)

=cut

    if (/^bayes_path\s+(.*)$/) {
      $self->{bayes_path} = $1; next;
    }

=item timelog_path /path/to/dir		(default: NULL)

If you set this value, SpamAssassin will try to create logfiles for each
message it processes and dump information on how fast it ran, and in which
parts of the code the time was spent.  The files will be named:
C<unixdate_messageid> (i.e 1023257504_chuvn31gdu@4ax.com)

Make sure  SA can write the log file; if you're not sure what permissions are
needed, chmod the log directory to 1777, and adjust later.

=cut

    if (/^timelog_path\s+(.*)$/) {
      $Mail::SpamAssassin::TIMELOG->{logpath}=$1; next;
    }

=item auto_whitelist_file_mode		(default: 0700)

The file mode bits used for the automatic-whitelist directory or file.

Make sure you specify this using the 'x' mode bits set, as it may also be used
to create directories.  However, if a file is created, the resulting file will
not have any execute bits set (the umask is set to 111).

=cut
    if (/^auto_whitelist_file_mode\s+(.*)$/) {
      $self->{auto_whitelist_file_mode} = $1; next;
    }

=item bayes_file_mode		(default: 0700)

The file mode bits used for the Bayesian filtering database files.

Make sure you specify this using the 'x' mode bits set, as it may also be used
to create directories.  However, if a file is created, the resulting file will
not have any execute bits set (the umask is set to 111).

=cut
    if (/^bayes_file_mode\s+(.*)$/) {
      $self->{bayes_file_mode} = $1; next;
    }

=item bayes_use_hapaxes		(default: 1)

Should the Bayesian classifier use hapaxes (words/tokens that occur only
once) when classifying?  This produces significantly better hit-rates, but
increases database size by about a factor of 8 to 10.

=cut
    if (/^bayes_use_hapaxes\s+(.*)$/) {
      $self->{bayes_use_hapaxes} = $1; next;
    }

=item bayes_use_chi2_combining		(default: 1)

Should the Bayesian classifier use chi-squared combining, instead of
Robinson/Graham-style naive Bayesian combining?  Chi-squared produces
more 'extreme' output results, but may be more resistant to changes
in corpus size etc.

=cut
    if (/^bayes_use_chi2_combining\s+(.*)$/) {
      $self->{bayes_use_chi2_combining} = $1; next;
    }

=item bayes_expiry_max_db_size		(default: 150000)

What should be the maximum size of the Bayes tokens database?  When expiry
occurs, the Bayes system will keep either 75% of the maximum value, or
100,000 tokens, whichever has a larger value.  150,000 tokens is roughly
equivalent to a 8Mb database file.

=cut
    if (/^bayes_expiry_max_db_size\s+(\d+)$/) {
      $self->{bayes_expiry_max_db_size} = $1; next;
    }

=item bayes_auto_expire       		(default: 1)

If enabled, the Bayes system will try to automatically expire old tokens
from the database.  Auto-expiry occurs when the number of tokens in the
database surpasses the bayes_expiry_max_db_size value.

=cut
    if (/^bayes_auto_expire\s+(\d+)$/) {
      $self->{bayes_auto_expire} = $1; next;
    }

=item bayes_journal_max_size		(default: 102400)

SpamAssassin will opportunistically sync the journal and the database.
It will do so at least once a day, but can also sync if the file size
goes above this setting, in bytes.  If set to 0, the journal sync will
only occur once a day.

=cut
    if (/^bayes_journal_max_size\s+(\d+)$/) {
      $self->{bayes_journal_max_size} = $1; next;
    }

=item user_scores_dsn DBI:databasetype:databasename:hostname:port

If you load user scores from an SQL database, this will set the DSN
used to connect.  Example: C<DBI:mysql:spamassassin:localhost>

=cut

    if (/^user_scores_dsn\s+(\S+)$/) {
      $self->{user_scores_dsn} = $1; next;
    }

=item user_scores_sql_username username

The authorized username to connect to the above DSN.

=cut
    if(/^user_scores_sql_username\s+(\S+)$/) {
      $self->{user_scores_sql_username} = $1; next;
    }

=item user_scores_sql_password password

The password for the database username, for the above DSN.

=cut
    if(/^user_scores_sql_password\s+(\S+)$/) {
      $self->{user_scores_sql_password} = $1; next;
    }

=item user_scores_sql_table tablename

The table user preferences are stored in, for the above DSN.

=cut
    if(/^user_scores_sql_table\s+(\S+)$/) {
      $self->{user_scores_sql_table} = $1; next;
    }

# Michael 'Moose' Dinn <dinn@twistedpair.ca>
# For integration with horde preferences system
# 20020831

=item user_scores_sql_field_username field_username

The field that the username whose preferences you're looking up is stored in.
Default: C<username>.

=cut
    if(/^user_scores_sql_field_username\s+(\S+)$/) {
      $self->{user_scores_sql_field_username} = $1; next;
    }

=item user_scores_sql_field_preference field_preference

The name of the preference that you're looking for.  Default: C<preference>.

=cut
    if(/^user_scores_sql_field_preference\s+(\S+)$/) {
      $self->{user_scores_sql_field_preference} = $1; next;
    }

=item user_scores_sql_field_value field_value

The name of the value you're looking for.  Default: C<value>.

=cut
    if(/^user_scores_sql_field_value\s+(\S+)$/) {
      $self->{user_scores_sql_field_value} = $1; next;
    }

=item user_scores_sql_field_scope field_scope

The 'scope' field. In Horde this makes the preference a single-module
preference or a global preference. There's no real need to change it in other
systems.  Default: C<spamassassin>.

=cut
    if(/^user_scores_sql_field_scope\s+(\S+)$/) {
      $self->{user_scores_sql_field_scope} = $1; next;
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
  $self->{tests}->{$name} = $text;
  $self->{test_types}->{$name} = $type;
  $self->{tflags}->{$name} ||= '';
  $self->{source_file}->{$name} = $self->{currentfile};

  # All scoresets should have a score defined, so if the one we're in
  # doesn't, we need to set them all.
  # TODO? - nice tests should get negative scores
  if ( ! exists $self->{scores}->{$name} ) {
    # T_ rules (in a testing probationary period) get low, low scores
    my $set_score = ($name =~/^T_/) ? 0.01 : 1.0;
    for my $index (0..3) {
      $self->{scoreset}->[$index]->{$name} = $set_score;
    }
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

# note: error 70 == SA_SOFTWARE
sub finish_parsing {
  my ($self) = @_;

  while (my ($name, $text) = each %{$self->{tests}}) {
    my $type = $self->{test_types}->{$name};

    # eval type handling
    if (($type & 1) == 1) {
      my @args;
      if (my ($function, $args) = ($text =~ m/(.*?)\s*\((.*?)\)\s*$/)) {
	if ($args) {
	  @args = ($args =~ m/['"](.*?)['"]\s*(?:,\s*|$)/g);
        }
	unshift(@args, $function);
	if ($type == TYPE_BODY_EVALS) {
	  $self->{body_evals}->{$name} = \@args;
	}
	elsif ($type == TYPE_HEAD_EVALS) {
	  $self->{head_evals}->{$name} = \@args;
	}
	elsif ($type == TYPE_RBL_EVALS) {
	  $self->{rbl_evals}->{$name} = \@args;
	}
	elsif ($type == TYPE_RAWBODY_EVALS) {
	  $self->{rawbody_evals}->{$name} = \@args;
	}
	elsif ($type == TYPE_FULL_EVALS) {
	  $self->{full_evals}->{$name} = \@args;
	}
	#elsif ($type == TYPE_URI_EVALS) {
	#  $self->{uri_evals}->{$name} = \@args;
	#}
	else {
	  $self->{errors}++;
	  sa_die(70, "unknown type $type for $name: $text");
	}
      }
      else {
	$self->{errors}++;
	sa_die(70, "syntax error for $name: $text");
      }
    }
    # non-eval tests
    else {
      if ($type == TYPE_BODY_TESTS) {
	$self->{body_tests}->{$name} = $text;
      }
      elsif ($type == TYPE_HEAD_TESTS) {
	$self->{head_tests}->{$name} = $text;
      }
      elsif ($type == TYPE_META_TESTS) {
	$self->{meta_tests}->{$name} = $text;
      }
      elsif ($type == TYPE_URI_TESTS) {
	$self->{uri_tests}->{$name} = $text;
      }
      elsif ($type == TYPE_RAWBODY_TESTS) {
	$self->{rawbody_tests}->{$name} = $text;
      }
      elsif ($type == TYPE_FULL_TESTS) {
	$self->{full_tests}->{$name} = $text;
      }
      else {
	$self->{errors}++;
	sa_die(70, "unknown type $type for $name: $text");
      }
    }
  }

  delete $self->{tests};		# free it up
}

sub add_to_addrlist {
  my ($self, $singlelist, @addrs) = @_;

  foreach my $addr (@addrs) {
    $addr = lc $addr;
    my $re = $addr;
    $re =~ s/[\000\\\(]/_/gs;			# paranoia
    $re =~ s/([^\*\?_a-zA-Z0-9])/\\$1/g;	# escape any possible metachars
    $re =~ tr/?/./;				# "?" -> "."
    $re =~ s/\*/\.\*/g;				# "*" -> "any string"
    $self->{$singlelist}->{$addr} = qr/^${re}$/;
  }
}

sub add_to_addrlist_rcvd {
  my ($self, $listname, $addr, $domain) = @_;
  
  $addr = lc $addr;
  my $re = $addr;
  $re =~ s/[\000\\\(]/_/gs;			# paranoia
  $re =~ s/([^\*\?_a-zA-Z0-9])/\\$1/g;		# escape any possible metachars
  $re =~ tr/?/./;				# "?" -> "."
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

###########################################################################

sub maybe_header_only {
  my($self,$rulename) = @_;
  my $type = $self->{test_types}->{$rulename};
  return 0 if (!defined ($type));

  if (($type == TYPE_HEAD_TESTS) || ($type == TYPE_HEAD_EVALS)) {
    return 1;

  } elsif ($type == TYPE_META_TESTS) {
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

  if (($type == TYPE_BODY_TESTS) || ($type == TYPE_BODY_EVALS)
	|| ($type == TYPE_URI_TESTS) || ($type == TYPE_URI_EVALS))
  {
    # some rawbody go off of headers...
    return 1;

  } elsif ($type == TYPE_META_TESTS) {
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

=cut
