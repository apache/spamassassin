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

=head1 DESCRIPTION

SpamAssassin is configured using some traditional UNIX-style configuration
files, loaded from the /usr/share/spamassassin and /etc/mail/spamassassin
directories.

The C<#> character starts a comment, which continues until end of line.

Whitespace in the files is not significant, but please note that starting a
line with whitespace is deprecated, as we reserve its use for multi-line rule
definitions, at some point in the future.

Currently, each rule or configuration setting must fit on one-line; multi-line
settings are not supported yet.

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
 _SCORE_           message score
 _REQD_            message threshold
 _VERSION_         version (eg. 2.61 or 2.70-r6142-foo1)
 _SUBVERSION_      sub-version/code revision date (eg. 2004-01-10)
 _HOSTNAME_        hostname
 _BAYES_           bayes score
 _AWL_             AWL modifier
 _DATE_            rfc-2822 date of scan
 _STARS(*)_        one * (use any character) for each score point (note: this
                   is limited to 50 'stars' to stay on the right side of the RFCs)
 _RELAYSTRUSTED_   relays used and deemed to be trusted
 _RELAYSUNTRUSTED_ relays used that can not be trusted
 _AUTOLEARN_       autolearn status ("ham", "no", "spam", "disabled",
                   "failed", "unavailable")
 _TESTS(,)_        tests hit separated by , (or other separator)
 _TESTSSCORES(,)_  as above, except with scores appended (eg. AWL=-3.0,...)
 _DCCB_            DCC's "Brand"
 _DCCR_            DCC's results
 _PYZOR_           Pyzor results
 _RBL_             full results for positive RBL queries in DNS URI format
 _LANGUAGES_       possible languages of mail
 _PREVIEW_         content preview
 _REPORT_          terse report of tests hit (for header reports)
 _SUMMARY_         summary of tests hit for standard report (for body reports)
 _CONTACTADDRESS_  contents of the 'report_contact' setting

=head1 USER PREFERENCES

The following options can be used in both site-wide (C<local.cf>) and
user-specific (C<user_prefs>) configuration files to customize how
SpamAssassin handles incoming email messages.

=cut

package Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::Util;
use Mail::SpamAssassin::NetSet;
use File::Spec;

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
  my $self = {
    main => shift
  }; bless ($self, $class);

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

  $self->{eval_plugins} = { };

  # testing stuff
  $self->{regression_tests} = { };

  $self->{required_score} = 5.0;
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

  $self->{use_auto_whitelist} = 1;
  $self->{auto_whitelist_factory} = "Mail::SpamAssassin::DBBasedAddrList";
  $self->{auto_whitelist_path} = "__userstate__/auto-whitelist";
  $self->{auto_whitelist_file_mode} = '0700';
  $self->{auto_whitelist_factor} = 0.5;
  $self->{auto_whitelist_db_modules} = "DB_File GDBM_File NDBM_File SDBM_File";

  $self->{subject_tag} = '*****SPAM*****';
  $self->{rewrite_header} = { };
  $self->{to_tag} = 'SPAM';
  $self->{report_safe} = 1;
  $self->{report_contact} = 'the administrator of that system';
  $self->{report_hostname} = '';
  $self->{skip_rbl_checks} = 0;
  $self->{dns_available} = "test";
  $self->{check_mx_attempts} = 2;
  $self->{check_mx_delay} = 5;
  $self->{ok_locales} = 'all';
  $self->{ok_languages} = 'all';
  $self->{allow_user_rules} = 0;
  $self->{user_rules_to_compile} = { };
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
  $self->{bayes_auto_learn_threshold_nonspam} = 0.1;
  $self->{bayes_auto_learn_threshold_spam} = 12.0;
  $self->{bayes_learn_to_journal} = 0;
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
  $self->{bayes_ignore_from} = { };
  $self->{bayes_ignore_to} = { };

  # Allow alternate bayes storage implementation
  $self->{bayes_store_module} = '';

  # Used for SQL based Bayes implementation
  $self->{bayes_sql_dsn} = '';
  $self->{bayes_sql_username} = '';
  $self->{bayes_sql_password} = '';
  $self->{bayes_sql_override_username} = '';

  $self->{use_hashcash} = 1;
  $self->{hashcash_accept} = { };
  $self->{hashcash_doublespend_path} = '__userstate__/hashcash_seen';
  $self->{hashcash_doublespend_file_mode} = "0700";

  $self->{whitelist_from} = { };
  $self->{blacklist_from} = { };

  $self->{blacklist_to} = { };
  $self->{whitelist_to} = { };
  $self->{more_spam_to} = { };
  $self->{all_spam_to} = { };

  $self->{trusted_networks} = Mail::SpamAssassin::NetSet->new();
  $self->{internal_networks} = Mail::SpamAssassin::NetSet->new();

  # this will hold the database connection params
  $self->{user_scores_dsn} = '';
  $self->{user_scores_sql_username} = '';
  $self->{user_scores_sql_password} = '';

  # defaults for SQL based auto-whitelist
  $self->{user_awl_sql_table} = 'awl';

  $self->{user_scores_ldap_username} = 'username';
  $self->{user_scores_ldap_password} = '';

  # Make sure we add in X-Spam-Checker-Version
  $self->{headers_spam}->{"Checker-Version"} = "SpamAssassin _VERSION_ (_SUBVERSION_) on _HOSTNAME_";
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

  $self->{scoresonly} = $scoresonly;

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
  my @if_stack = ();
  my $skip_parsing = 0;

  foreach (split (/\n/, $_[1])) {
    s/(?<!\\)#.*$//; # remove comments
    s/^\s+|\s+$//g;  # remove leading and trailing spaces (including newlines)
    next unless($_); # skip empty lines

    # handle i18n
    if (s/^lang\s+(\S+)\s+//) { next if ($lang !~ /^$1/i); }

    # Versioning assertions
    if (/^file\s+start\s+(.+)$/) { $self->{currentfile} = $1; next; }
    if (/^file\s+end/) {
      if (scalar @if_stack > 0) {
	my $cond = pop @if_stack;

	if ($cond->{type} eq 'ifplugin') {
	  warn "unclosed 'if' in ".
		$self->{currentfile}.": ifplugin ".$cond->{plugin}."\n";
	} else {
	  die "unknown 'if' type: ".$cond->{type}."\n";
	}

	$self->{errors}++;
	@if_stack = ();
      }

      $self->{currentfile} = '(no file)';
      $skip_parsing = 0;
      next;
    }

    # convert all dashes in setting name to underscores.
    # Simplifies regexps below...
    1 while s/^(\S+)\-(\S+)/$1_$2/g;

    my($key, $value) = split(/\s+/, $_, 2);
    $key = lc $key;
    $value = '' unless ( defined $value );

    # Do a better job untainting this info ...
    $value =~ /^(.*)$/;
    $value = $1;

=head2 CONDITIONAL-PARSING OPTIONS

=item ifplugin PluginModuleName

Used to support conditional interpretation, based on whether a plugin module
has been loaded successfully or not.  Lines between this and a corresponding
C<endif> line, will be ignored unless the named plugin module has been loaded
using C<loadplugin>.

Note that if the end of a configuration file is reached while still inside a
C<ifplugin> scope, a warning will be issued, but parsing will restart on
the next file.

For example:

	loadplugin MyPlugin plugintest.pm

	ifplugin MyPlugin
	  header MY_PLUGIN_FOO	eval:check_for_foo()
	  score  MY_PLUGIN_FOO	0.1
	endif

=cut

    if ($key eq 'ifplugin') {
      push (@if_stack, {
	  type => 'ifplugin',
	  plugin => $value,
	  skip_parsing => $skip_parsing
	});

      if ($self->{plugins_loaded}->{$value}) {
	# leave $skip_parsing as-is; we may not be parsing anyway in this block.
	# in other words, support nested 'if's and 'require_version's
      } else {
	$skip_parsing = 1;
      }
      next;
    }

    # and the endif statement:
    if ($key eq 'endif') {
      my $cond = pop @if_stack;
      $skip_parsing = $cond->{skip_parsing};
      next;
    }

=head2 VERSION OPTIONS

=over 4

=item require_version n.nn

Indicates that the entire file, from this line on, requires a certain version
of SpamAssassin to run.  If an older or newer version of SpamAssassin tries to
read configuration from this file, it will output a warning instead, and
ignore it.

=cut

    if ( $key eq 'require_version' ) {
      my $req_version = $value;
      $req_version =~ s/^\@\@VERSION\@\@$/$Mail::SpamAssassin::VERSION/;

      # earlier versions used !=
      # starting with 3.0.0, perl doesn't like != so it was switched to ne
      # we should probably allow "require_version 3.0" be good for all
      # "3.0.x" versions - tvd
      #
      if ($Mail::SpamAssassin::VERSION ne $req_version) {
        warn "configuration file \"$self->{currentfile}\" requires version ".
                "$req_version of SpamAssassin, but this is code version ".
                "$Mail::SpamAssassin::VERSION. Maybe you need to use ".
                "the -C switch, or remove the old config files? ".
                "Skipping this file";
        $skip_parsing = 1;
        $self->{errors}++;
      }
      next;
    }

    if ($skip_parsing) { next; }

    # note: no eval'd code should be loaded before the SECURITY line below.
###########################################################################

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

    if( $key eq 'version_tag' ) {
      my $tag = lc($value);
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

=back

=head2 WHITELIST AND BLACKLIST OPTIONS

=over 4

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

    if ( $key eq 'whitelist_from' ) {
      $self->add_to_addrlist ('whitelist_from', split (/\s+/, $value)); next;
    }

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

    if ( $key eq 'unwhitelist_from' ) {
      $self->remove_from_addrlist ('whitelist_from', split (/\s+/, $value)); next;
    }

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
it will be, but for a complex network, or if you're running with DNS checks off
or with C<-L>, you may get better results by setting that parameter.

e.g.

  whitelist_from_rcvd joe@example.com  example.com
  whitelist_from_rcvd *@axkit.org      sergeant.org

=item def_whitelist_from_rcvd addr@lists.sourceforge.net sourceforge.net

Same as C<whitelist_from_rcvd>, but used for the default whitelist entries
in the SpamAssassin distribution.  The whitelist score is lower, because
these are often targets for spammer spoofing.

=cut

    if ( $key eq 'whitelist_from_rcvd' ) {
      $self->add_to_addrlist_rcvd ('whitelist_from_rcvd', split(/\s+/, $value));
      next;
    }
    if ( $key eq 'def_whitelist_from_rcvd' ) {
      $self->add_to_addrlist_rcvd ('def_whitelist_from_rcvd', split(/\s+/, $value));
      next;
    }

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

    if ( $key eq 'unwhitelist_from_rcvd' ) {
      $self->remove_from_addrlist_rcvd('whitelist_from_rcvd', split (/\s+/, $value));
      $self->remove_from_addrlist_rcvd('def_whitelist_from_rcvd', split (/\s+/, $value));
      next;
    }

=item blacklist_from add@ress.com

Used to specify addresses which send mail that is often tagged (incorrectly) as
non-spam, but which the user doesn't want.  Same format as C<whitelist_from>.

=cut

    if ( $key eq 'blacklist_from' ) {
      $self->add_to_addrlist ('blacklist_from', split (/\s+/, $value)); next;
    }

=item unblacklist_from add@ress.com

Used to override a default blacklist_from entry, so for example a distribution blacklist_from
can be overridden in a local.cf file, or an individual user can override a blacklist_from entry
in their own C<user_prefs> file.

e.g.

  unblacklist_from joe@example.com fred@example.com
  unblacklist_from *@spammer.com

=cut

    if ( $key eq 'unblacklist_from' ) {
      $self->remove_from_addrlist ('blacklist_from', split (/\s+/, $value)); next;
    }


=item whitelist_to add@ress.com

If the given address appears as a recipient in the message headers
(Resent-To, To, Cc, obvious envelope recipient, etc.) the mail will
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

    if ( $key eq 'whitelist_to' ) {
      $self->add_to_addrlist ('whitelist_to', split (/\s+/, $value)); next;
    }
    if ( $key eq 'more_spam_to' ) {
      $self->add_to_addrlist ('more_spam_to', split (/\s+/, $value)); next;
    }
    if ( $key eq 'all_spam_to' ) {
      $self->add_to_addrlist ('all_spam_to', split (/\s+/, $value)); next;
    }

=item blacklist_to add@ress.com

If the given address appears as a recipient in the message headers
(Resent-To, To, Cc, obvious envelope recipient, etc.) the mail will
be blacklisted.  Same format as C<blacklist_from>.

=cut

    if ( $key eq 'blacklist_to' ) {
      $self->add_to_addrlist ('blacklist_to', split (/\s+/, $value)); next;
    }

=back

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

    if ( ($key eq 'required_hits') || ($key eq 'required_score') ) {
      $self->{required_score} = $value+0.0; next;
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

If the first score value is surrounded by parenthesis '()', then that
value is considered to be relative to the already set score.  ie: '(3)'
means increase the score for this rule by 3 points in all score sets.
'(3) (0) (3) (0)' means increase the score for this rule by 3 in score
sets 0 and 2 only.

If no score is given for a test by the end of the configuration, the
default score is 1.0, or 0.01 for tests whose names begin with 'T_'
(this is used to indicate a rule in testing).

Note that test names which begin with '__' are reserved for meta-match
sub-rules, and are not scored or listed in the 'tests hit' reports.

=cut

  if ( $key eq 'score' ) {
    my($rule, @scores) = split(/\s+/, $value);

    my $relative = (@scores > 0 && $scores[0] =~ /^\(\d+(\.\d+)?\)$/) ? 1 : 0;
    if ($relative && !exists $self->{scoreset}->[0]->{$rule}) {
      my $msg = "Relative score without previous setting in SpamAssassin configuration, ".
                        "skipping: $_";

      if ($self->{lint_rules}) {
        warn $msg."\n";
      } else {
        dbg ($msg);
      }
      $self->{errors}++;
      next;
    }

    if (@scores == 4) {
      for my $index (0..3) {
	my $score = $relative ?
	  $self->{scoreset}->[$index]->{$rule} + $scores[$index] :
	  $scores[$index];

	$self->{scoreset}->[$index]->{$rule} = $score + 0.0;
      }
    }
    elsif (@scores > 0) {
      my $score = $relative ?
        $self->{scoreset}->[0]->{$rule} + $scores[0] : $scores[0];

      for my $index (0..3) {
	$self->{scoreset}->[$index]->{$rule} = $score + 0.0;
      }
    }
    next;
  }

=back

=head2 MESSAGE TAGGING OPTIONS

=over 4

=item rewrite_header { subject | from | to } STRING

By default, suspected tag will not have the C<Subject>, C<From> or
C<To> lines tagged to indicate spam. By setting this option, the
header will be tagged with C<STRING> to indicate that a message is
spam. For the From or To headers, this will take the form of an RFC
2822 comment following the address in parantheses. For the Subject
header, this will be prepended to the original subject. Note that you
should only use the _REQD_ and _SCORE_ tags when rewriting the Subject
header unless C<report_safe> is 0. Otherwise, you will not be able to
remove the SpamAssassin markup. Parentheses are not permitted in
STRING. (They will be converted to square brackets.)

=cut

    if ( $key eq 'rewrite_header' ) {
      my($hdr, $string) = split(/\s+/, $value, 2);
      $hdr = ucfirst(lc($hdr));

      # We only deal with From, Subject, and To ...
      if ($hdr =~ /^(?:From|Subject|To)$/) {
        $string =~ tr/()/[]/;
        $self->{rewrite_header}->{$hdr} = $string;
        next;
      }

      # if we get here, note the issue, then we'll fail through for an error.
      dbg("rewrite_header: ignoring $hdr, not From, Subject, or To");
    }

=item fold_headers { 0 | 1 }        (default: 1)

By default,  headers added by SpamAssassin will be whitespace folded.
In other words, they will be broken up into multiple lines instead of
one very long one and each other line will have a tabulator prepended
to mark it as a continuation of the preceding one.

The automatic wrapping can be disabled here  (which can generate very
long lines).

=cut

   if ( $key eq 'fold_headers' ) {
     $self->{fold_headers} = $value+0; next;
   }

=item add_header { spam | ham | all } header_name string

Customized headers can be added to the specified type of messages (spam,
ham, or "all" to add to either).  All headers begin with C<X-Spam->
(so a C<header_name> Foo will generate a header called X-Spam-Foo).
header_name is restricted to the character set [A-Za-z0-9_-].

C<string> can contain tags as explained above in the TAGS section.  You
can also use C<\n> and C<\t> in the header to add newlines and tabulators
as desired.  A backslash has to be written as \\, any other escaped chars
will be silently removed.

All headers will be folded if fold_headers is set to C<1>. Note: Manually
adding newlines via C<\n> disables any further automatic wrapping (ie:
long header lines are possible). The lines will still be properly folded
(marked as continuing) though.

You can customize existing headers with add_header (only the specified
subset of messages will be changed).

See also C<clear_headers> for removing headers.

Here are some examples (these are the defaults):

 add_header spam Flag _YESNOCAPS_
 add_header all Status _YESNO_, score=_SCORE__ required=_REQD_ tests=_TESTS_ autolearn=_AUTOLEARN_ version=_VERSION_
 add_header all Level _STARS(*)_
 add_header all Checker-Version SpamAssassin _VERSION_ (_SUBVERSION_) on _HOSTNAME_

=cut

    # easier to do RE here ...
    if (/^add_header\s+(ham|spam|all)\s+([A-Za-z0-9_-]+)\s+(.*?)\s*$/) {
      my ($type, $name, $line) = ($1, $2, $3);
      if ($line =~ /^"(.*)"$/) {
	$line = $1;
      }
      my @line = split(
                   /\\\\/,    # split at backslashes,
                   "$line\n"  # newline needed to make trailing backslashes work
                 );
      map {
        s/\\t/\t/g; # expand tabs
        s/\\n/\n/g; # expand newlines
        s/\\.//g;   # purge all other escapes
      } @line;
      $line = join("\\", @line);
      chop($line);  # remove dummy newline again
      if (($type eq "ham") || ($type eq "all")) {
	$self->{headers_ham}->{$name} = $line;
      }
      if (($type eq "spam") || ($type eq "all")) {
	$self->{headers_spam}->{$name} = $line;
      }
      next;
    }

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

    if (/^remove_header\s+(ham|spam|all)\s+([A-Za-z0-9_-]+)\s*$/) {
      my ($type, $name) = ($1, $2);

      next if ( $name eq "Checker-Version" );

      if (($type eq "ham") || ($type eq "all")) {
	delete $self->{headers_ham}->{$name};
      }
      if (($type eq "spam") || ($type eq "all")) {
	delete $self->{headers_spam}->{$name};
      }
      next;
    }

=item clear_headers

Clear the list of headers to be added to messages.  You may use this
before any add_header options to prevent the default headers from being
added to the message.

Note that B<X-Spam-Checker-Version> is not removable because the version
information is needed by mail administrators and developers to debug
problems.  Without at least one header, it might not even be possible to
determine that SpamAssassin is running.

=cut

    if ( $key eq 'clear_headers' ) {
      for my $name (keys %{ $self->{headers_ham} }) {
	delete $self->{headers_ham}->{$name} if $name ne "Checker-Version";
      }
      for my $name (keys %{ $self->{headers_spam} }) {
	delete $self->{headers_spam}->{$name} if $name ne "Checker-Version";
      }
      next;
    }

=item report_safe_copy_headers header_name ...

If using report_safe, a few of the headers from the original message
are copied into the wrapper header (From, To, Cc, Subject, Date, etc.)
If you want to have other headers copied as well, you can add them
using this option.  You can specify multiple headers on the same line,
separated by spaces, or you can just use multiple lines.

=cut

   if ( $key eq 'report_safe_copy_headers' ) {
     push(@{$self->{report_safe_copy_headers}}, split(/\s+/, $value));
     next;
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
some C<X-Spam-> headers and no changes will be made to the body.  In
addition, a header named B<X-Spam-Report> will be added to spam.  You
can use the B<remove_header> option to remove that header after setting
B<report_safe> to 0.

=cut

    if ( $key eq 'report_safe' ) {
      $self->{report_safe} = $value+0;
      if (! $self->{report_safe}) {
	$self->{headers_spam}->{"Report"} = "_REPORT_";
      }
      next;
    }

=item report_charset CHARSET		(default: unset)

Set the MIME Content-Type charset used for the text/plain report which
is attached to spam mail messages.

=cut

    if ( $key eq 'report_charset' ) {
      $self->{report_charset} = $value; next;
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

    if ( $key eq 'report' ) {
      my $report = $value;
      if ( $report =~ /^"(.*?)"$/ ) {
        $report = $1;
      }

      $self->{report_template} .= "$report\n"; next;
    }

=item clear_report_template

Clear the report template.

=cut

    if ( $key eq 'clear_report_template' ) {
      $self->{report_template} = ''; next;
    }

=item report_contact ...text of contact address...

Set what _CONTACTADDRESS_ is replaced with in the above report text.
By default, this is 'the administrator of that system', since the hostname
of the system the scanner is running on is also included.

=cut

    if ( $key eq 'report_contact' ) {
      $self->{report_contact} = $value; next;
    }

=item report_hostname ...hostname to use...

Set what _HOSTNAME_ is replaced with in the above report text.
By default, this is determined dynamically as whatever the host running
SpamAssassin calls itself.

=cut

    if ( $key eq 'report_hostname' ) {
      $self->{report_hostname} = $value; next;
    }

=item unsafe_report ...some text for a report...

Set the report template which is attached to spam mail messages which contain a
non-text/plain part.  See the C<10_misc.cf> configuration file in
C</usr/share/spamassassin> for an example.

Each C<unsafe-report> line appends to the existing template, so use
C<clear_unsafe_report_template> to restart.

Tags can be used in this template (see above for details).

=cut

    if ( $key eq 'unsafe_report' ) {
      my $report = $value;
      if ( $report =~ /^"(.*?)"$/ ) {
        $report = $1;
      }

      $self->{unsafe_report_template} .= "$report\n"; next;
    }

=item clear_unsafe_report_template

Clear the unsafe_report template.

=cut

    if ( $key eq 'clear_unsafe_report_template' ) {
      $self->{unsafe_report_template} = ''; next;
    }

=item spamtrap ...some text for spamtrap reply mail...

A template for spam-trap responses.  If the first few lines begin with
C<Xxxxxx: yyy> where Xxxxxx is a header and yyy is some text, they'll be used
as headers.  See the C<10_misc.cf> configuration file in
C</usr/share/spamassassin> for an example.

Unfortunately tags can not be used with this option.

=cut

    if ( $key eq 'spamtrap' ) {
      my $report = $value;
      if ( $report =~ /^"(.*?)"$/ ) {
        $report = $1;
      }
      $self->{spamtrap_template} .= "$report\n"; next;
    }

=item clear_spamtrap_template

Clear the spamtrap template.

=cut

    if ( $key eq 'clear_spamtrap_template' ) {
      $self->{spamtrap_template} = ''; next;
    }

=item describe SYMBOLIC_TEST_NAME description ...

Used to describe a test.  This text is shown to users in the detailed report.

Note that test names which begin with '__' are reserved for meta-match
sub-rules, and are not scored or listed in the 'tests hit' reports.

Also note that by convention, rule descriptions should be limited in
length to no more than 50 characters.

=cut

    if ( $key eq 'describe' ) {
      my($k,$v) = split(/\s+/, $value, 2);
      $self->{descriptions}->{$k} = $v; next;
    }

=back

=head2 LANGUAGE OPTIONS

=over 4

=item ok_languages xx [ yy zz ... ]		(default: all)

This option is used to specify which languages are considered OK for
incoming mail.  SpamAssassin will try to detect the language used in the
message text.

Note that the language cannot always be recognized with sufficient
confidence.  In that case, no points will be assigned.

The rule C<UNWANTED_LANGUAGE_BODY> is triggered based on how this is set.

In your configuration, you must use the two or three letter language
specifier in lowercase, not the English name for the language.  You may
also specify C<all> if a desired language is not listed, or if you want to
allow any language.  The default setting is C<all>.

Examples:

  ok_languages all         (allow all languages)
  ok_languages en          (only allow English)
  ok_languages en ja zh    (allow English, Japanese, and Chinese)

Note: if there are multiple ok_languages lines, only the last one is used.

Select the languages to allow from the list below:

=over 4

=item af	- Afrikaans

=item am	- Amharic

=item ar	- Arabic

=item be	- Byelorussian

=item bg	- Bulgarian

=item bs	- Bosnian

=item ca	- Catalan

=item cs	- Czech

=item cy	- Welsh

=item da	- Danish

=item de	- German

=item el	- Greek

=item en	- English

=item eo	- Esperanto

=item es	- Spanish

=item et	- Estonian

=item eu	- Basque

=item fa	- Persian

=item fi	- Finnish

=item fr	- French

=item fy	- Frisian

=item ga	- Irish Gaelic

=item gd	- Scottish Gaelic

=item he	- Hebrew

=item hi	- Hindi

=item hr	- Croatian

=item hu	- Hungarian

=item hy	- Armenian

=item id	- Indonesian

=item is	- Icelandic

=item it	- Italian

=item ja	- Japanese

=item ka	- Georgian

=item ko	- Korean

=item la	- Latin

=item lt	- Lithuanian

=item lv	- Latvian

=item mr	- Marathi

=item ms	- Malay

=item ne	- Nepali

=item nl	- Dutch

=item no	- Norwegian

=item pl	- Polish

=item pt	- Portuguese

=item qu	- Quechua

=item rm	- Rhaeto-Romance

=item ro	- Romanian

=item ru	- Russian

=item sa	- Sanskrit

=item sco	- Scots

=item sk	- Slovak

=item sl	- Slovenian

=item sq	- Albanian

=item sr	- Serbian

=item sv	- Swedish

=item sw	- Swahili

=item ta	- Tamil

=item th	- Thai

=item tl	- Tagalog

=item tr	- Turkish

=item uk	- Ukrainian

=item vi	- Vietnamese

=item yi	- Yiddish

=item zh	- Chinese (both Traditional and Simplified)

=item zh.big5	- Chinese (Traditional only)

=item zh.gb2312	- Chinese (Simplified only)

=back

=cut

    if ( $key eq 'ok_languages' ) {
      $self->{ok_languages} = $value; next;
    }

=back

Z<>

=over 4

=item ok_locales xx [ yy zz ... ]		(default: all)

This option is used to specify which locales (country codes) are
considered OK for incoming mail.  Mail using B<character sets> used by
languages in these countries will not be marked as possibly being spam in
a foreign language.

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

    if ( $key eq 'ok_locales' ) {
      $self->{ok_locales} = $value; next;
    }

=back

=head2 NETWORK TEST OPTIONS

=over 4

=item use_dcc ( 0 | 1 )		(default: 1)

Whether to use DCC, if it is available.

=cut

    if ( $key eq 'use_dcc' ) {
      $self->{use_dcc} = $value+0; next;
    }

=item dcc_timeout n              (default: 10)

How many seconds you wait for dcc to complete before you go on without
the results

=cut

    if ( $key eq 'dcc_timeout' ) {
      $self->{dcc_timeout} = $value+0; next;
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

    if ( $key eq 'dcc_body_max' ) {
      $self->{dcc_body_max} = $value+0; next;
    }

    if ( $key eq 'dcc_fuz1_max' ) {
      $self->{dcc_fuz1_max} = $value+0; next;
    }

    if ( $key eq 'dcc_fuz2_max' ) {
      $self->{dcc_fuz2_max} = $value+0; next;
    }


=item use_pyzor ( 0 | 1 )		(default: 1)

Whether to use Pyzor, if it is available.

=cut

    if ( $key eq 'use_pyzor' ) {
      $self->{use_pyzor} = $value+0; next;
    }

=item pyzor_timeout n              (default: 10)

How many seconds you wait for Pyzor to complete before you go on without
the results.

=cut

    if ( $key eq 'pyzor_timeout' ) {
      $self->{pyzor_timeout} = $value+0; next;
    }

=item pyzor_max NUMBER

Pyzor is a system similar to Razor.  This option sets how often a message's
body checksum must have been reported to the Pyzor server before SpamAssassin
will consider the Pyzor check as matched.

The default is 5.

=cut

    if ( $key eq 'pyzor_max' ) {
      $self->{pyzor_max} = $value+0; next;
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

If C<trusted_networks> is not set and C<internal_networks> is, the value
of C<internal_networks> will be used for this parameter.

If you're running with DNS checks enabled, SpamAssassin includes code to
infer your trusted networks on the fly, so this may not be necessary.
(Thanks to Scott Banister and Andrew Flury for the inspiration for this
algorithm.)  This inference works as follows:

=over 4

=item *

if the 'from' IP address is on the same /16 network as the top Received
line's 'by' host, it's trusted

=item *

if the address of the 'from' host is in a reserved network range,
then it's trusted

=item *

if any addresses of the 'by' host is in a reserved network range,
then it's trusted

=back

=cut

    if ( $key eq 'trusted_networks' ) {
      foreach my $net (split (/\s+/, $value)) {
	$self->{trusted_networks}->add_cidr ($net);
      }
      next;
    }

=item clear_trusted_networks

Empty the list of trusted networks.

=cut

    if ( $key eq 'clear_trusted_networks' ) {
      $self->{trusted_networks} = Mail::SpamAssassin::NetSet->new(); next;
    }

=item internal_networks ip.add.re.ss[/mask] ...   (default: none)

What networks or hosts are 'internal' in your setup.   B<Internal> means that
relay hosts on these networks are considered to be MXes for your domain(s), or
internal relays.  This uses the same format as C<trusted_networks>, above.

This value is used when checking 'dial-up' or dynamic IP address blocklists, in
order to detect direct-to-MX spamming.

If C<trusted_networks> is set and C<internal_networks> is not, the value
of C<trusted_networks> will be used for this parameter.

If neither C<trusted_networks> or C<internal_networks> is set, no addresses
will be considered local; in other words, any relays past the machine where
SpamAssassin is running will be considered external.

=cut

    if ( $key eq 'internal_networks' ) {
      foreach my $net (split (/\s+/, $value)) {
	$self->{internal_networks}->add_cidr ($net);
      }
      next;
    }

=item clear_internal_networks

Empty the list of internal networks.

=cut

    if ( $key eq 'clear_internal_networks' ) {
      $self->{internal_networks} = Mail::SpamAssassin::NetSet->new(); next;
    }

=item use_razor2 ( 0 | 1 )		(default: 1)

Whether to use Razor version 2, if it is available.

=cut

    if ( $key eq 'use_razor2' ) {
      $self->{use_razor2} = $value+0; next;
    }

=item razor_timeout n		(default: 10)

How many seconds you wait for razor to complete before you go on without
the results

=cut

    if ( $key eq 'razor_timeout' ) {
      $self->{razor_timeout} = $value+0; next;
    }

=item use_bayes ( 0 | 1 )		(default: 1)

Whether to use the naive-Bayesian-style classifier built into SpamAssassin.

=cut

    if ( $key eq 'use_bayes' ) {
      $self->{use_bayes} = $value+0; next;
    }

=item skip_rbl_checks { 0 | 1 }   (default: 0)

By default, SpamAssassin will run RBL checks.  If your ISP already does this
for you, set this to 1.

=cut

    if ( $key eq 'skip_rbl_checks' ) {
      $self->{skip_rbl_checks} = $value+0; next;
    }

=item rbl_timeout n		(default: 15)

All RBL queries are made at the beginning of a check and we try to read the
results at the end.  This value specifies the maximum period of time to wait
for an RBL query.  If most of the RBL queries have succeeded for a particular
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

    if ( $key eq 'rbl_timeout' ) {
      $self->{rbl_timeout} = $value+0; next;
    }

=item check_mx_attempts n	(default: 2)

By default, SpamAssassin checks the From: address for a valid MX this many
times, waiting 5 seconds each time.

=cut

    if ( $key eq 'check_mx_attempts' ) {
      $self->{check_mx_attempts} = $value+0; next;
    }

=item check_mx_delay n		(default: 5)

How many seconds to wait before retrying an MX check.

=cut

    if ( $key eq 'check_mx_delay' ) {
      $self->{check_mx_delay} = $value+0; next;
    }

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


    if (/^bayes_ignore_from\s+(.+)$/) {
      $self->add_to_addrlist ('bayes_ignore_from', split (' ', $1)); next;
    }

=item bayes_ignore_to add@ress.com

Bayesian classification and autolearning will not be performed on mail
to the listed addresses.  See C<bayes_ignore_from> for details.

=cut

    if (/^bayes_ignore_to\s+(.+)$/) {
      $self->add_to_addrlist ('bayes_ignore_to', split (' ', $1)); next;
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

SpamAssassin's network rules are run in parallel.  This can cause overhead
in terms of the number of file descriptors required; it is recommended
that the minimum limit on fds be raised to at least 256 for safety.

=cut

    # RE is easier for now ...
    if (/^dns_available\s+(yes|no|test|test:\s+.+)$/) {
      $self->{dns_available} = ($1 or "test"); next;
    }

=item use_hashcash { 1 | 0 }   (default: 1)

Whether to use hashcash, if it is available.

=cut

    if ( $key eq 'use_hashcash' ) {
      $self->{use_hashcash} = $value+0; next;
    }

=item hashcash_accept add@ress.com ...

Used to specify addresses that we accept HashCash tokens for.  You should set
it to match all the addresses that you may receive mail at.

Like whitelist and blacklist entries, the addresses are file-glob-style
patterns, so C<friend@somewhere.com>, C<*@isp.com>, or C<*.domain.net> will all
work.  Specifically, C<*> and C<?> are allowed, but all other metacharacters
are not.  Regular expressions are not used for security reasons.

The sequence C<%u> is replaced with the current user's username, which
is useful for ISPs or multi-user domains.

Multiple addresses per line, separated by spaces, is OK.  Multiple
C<hashcash_accept> lines is also OK.

=cut

    if ( $key eq 'hashcash_accept' ) {
      $self->add_to_addrlist ('hashcash_accept', split (/\s+/, $value)); next;
    }

=item hashcash_doublespend_path /path/to/file	(default: ~/.spamassassin/hashcash_seen)

Path for HashCash double-spend database.  HashCash tokens are only usable once,
so their use is tracked in this database to avoid providing a loophole.

By default, each user has their own, in their C<~/.spamassassin> directory with
mode 0700/0600.  Note that once a token is 'spent' it is written to this file,
and double-spending of a hashcash token makes it invalid, so this is not
suitable for sharing between multiple users.

=cut

    if ( $key eq 'hashcash_doublespend_path' ) {
      $self->{hashcash_doublespend_path} = $value; next;
    }

=item hashcash_doublespend_file_mode		(default: 0700)

The file mode bits used for the HashCash double-spend database file.

Make sure you specify this using the 'x' mode bits set, as it may also be used
to create directories.  However, if a file is created, the resulting file will
not have any execute bits set (the umask is set to 111).

=cut

    if ( $key eq 'hashcash_doublespend_file_mode' ) {
      $self->{hashcash_doublespend_file_mode} = $value+0; next;
    }

=back

=head2 LEARNING OPTIONS

=over 4

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

    if ( $key eq 'auto_whitelist_factor' ) {
      $self->{auto_whitelist_factor} = $value+0; next;
    }

=item auto_whitelist_db_modules Module ...	(default: see below)

What database modules should be used for the auto-whitelist storage database
file.   The first named module that can be loaded from the perl include path
will be used.  The format is:

  PreferredModuleName SecondBest ThirdBest ...

ie. a space-separated list of perl module names.  The default is:

  DB_File GDBM_File NDBM_File SDBM_File

=cut

    if ( $key eq 'auto_whitelist_db_modules' ) {
      $self->{auto_whitelist_db_modules} = $value; next;
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

    if ( $key eq 'bayes_auto_learn' ) {
      $self->{bayes_auto_learn} = $value+0; next;
    }

=item bayes_auto_learn_threshold_nonspam n.nn	(default: 0.1)

The score threshold below which a mail has to score, to be fed into
SpamAssassin's learning systems automatically as a non-spam message.

=cut

    if ( $key eq 'bayes_auto_learn_threshold_nonspam' ) {
      $self->{bayes_auto_learn_threshold_nonspam} = $value+0; next;
    }

=item bayes_auto_learn_threshold_spam n.nn	(default: 12.0)

The score threshold above which a mail has to score, to be fed into
SpamAssassin's learning systems automatically as a spam message.

Note: SpamAssassin requires at least 3 points from the header, and 3
points from the body to auto-learn as spam.  Therefore, the minimum
working value for this option is 6.

=cut

    if ( $key eq 'bayes_auto_learn_threshold_spam' ) {
      $self->{bayes_auto_learn_threshold_spam} = $value+0; next;
    }

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

    if ( $key eq 'bayes_ignore_header' ) {
      push (@{$self->{bayes_ignore_headers}}, $value); next;
    }

=item bayes_min_ham_num			(Default: 200)

=item bayes_min_spam_num		(Default: 200)

To be accurate, the Bayes system does not activate until a certain number of
ham (non-spam) and spam have been learned.  The default is 200 of each ham and
spam, but you can tune these up or down with these two settings.

=cut

    if ( $key eq 'bayes_min_ham_num' ) {
      $self->{bayes_min_ham_num} = $value+0; next;
    }

    if ( $key eq 'bayes_min_spam_num' ) {
      $self->{bayes_min_spam_num} = $value+0; next;
    }

=item bayes_learn_during_report         (Default: 1)

The Bayes system will, by default, learn any reported messages
(C<spamassassin -r>) as spam.  If you do not want this to happen, set
this option to 0.

=cut

    if ( $key eq 'bayes_learn_during_report' ) {
      $self->{bayes_learn_during_report} = $value+0; next;
    }

=item bayes_sql_override_username

Used by BayesStoreSQL storage implementation.

If this options is set the BayesStoreSQL module will override the set username with
the value given.  This could be useful for implementing global or group bayes databases.

=cut

    if ($key eq 'bayes_sql_override_username') {
      $self->{bayes_sql_override_username} = $value; next;
    }

##############

=item pyzor_options [option ...]

Additional options for the pyzor(1) command line.   Note that for security,
only characters in the ranges A-Z, a-z, 0-9, -, _ and / are permitted.

=cut

    # leave as RE for now?
    if (/^pyzor_options\s+([-A-Za-z0-9_\/ ]+)$/) {
      $self->{pyzor_options} = $1;
      next;
    }

###########################################################################
    # SECURITY: no eval'd code should be loaded before this line.
    #
    if ($scoresonly && !$self->{allow_user_rules}) { goto failed_line; }

    if ($scoresonly) { dbg("Checking privileged commands in user config"); }

=back

=head1 PRIVILEGED SETTINGS

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

Note that it is not currently possible to use C<allow_user_rules> to modify an
existing system rule from a C<user_prefs> file with C<spamd>.

=cut

    if ( $key eq 'allow_user_rules' ) {
      $self->{allow_user_rules} = $value+0;
      dbg( ($self->{allow_user_rules} ? "Allowing":"Not allowing") . " user rules!"); next;
    }

=item header SYMBOLIC_TEST_NAME header op /pattern/modifiers	[if-unset: STRING]

Define a test.  C<SYMBOLIC_TEST_NAME> is a symbolic test name, such as
'FROM_ENDS_IN_NUMS'.  C<header> is the name of a mail header, such as
'Subject', 'To', etc.

Appending C<:raw> to the header name will inhibit decoding of quoted-printable
or base-64 encoded strings.

There are several special pseudo-headers:

=over 4

=item C<ALL> can be used to mean the text of all the message's headers.

=item C<ToCc> can be used to mean the contents of both the 'To' and 'Cc'
headers.

=item C<EnvelopeFrom> is the address used in the 'MAIL FROM:' phase of the SMTP
transaction that delivered this message, if this data has been made available
by the SMTP server.

=item C<MESSAGEID> is a symbol meaning all Message-Id's found in the message;
some mailing list software moves the I<real> Message-Id to 'Resent-Message-Id'
or 'X-Message-Id', then uses its own one in the 'Message-Id' header.  The value
returned for this symbol is the text from all 3 headers, separated by newlines.

=back

C<op> is either C<=~> (contains regular expression) or C<!~> (does not contain
regular expression), and C<pattern> is a valid Perl regular expression, with
C<modifiers> as regexp modifiers in the usual style.   Note that multi-line
rules are not supported, even if you use C<x> as a modifier.

If the C<[if-unset: STRING]> tag is present, then C<STRING> will
be used if the header is not found in the mail message.

Test names should not start with a number, and must contain only
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

=item header SYMBOLIC_TEST_NAME eval:check_rbl('set', 'zone')

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

=item Selecting IPs by whether they are trusted

When checking a 'nice' DNSBL (a DNS whitelist), you cannot trust the IP
addresses in Received headers that were not added by trusted relays.  To test
the first IP address that can be trusted, name the set 'foo-firsttrusted'.
That should test the IP address of the relay that connected to the most remote
trusted relay.

In addition, you can test all untrusted IP addresses by naming the set
'foo-untrusted'.

Note that this requires that SpamAssassin know which relays are trusted.  For
simple cases, SpamAssassin can make a good estimate.  For complex cases, you
may get better results by setting C<trusted_networks> manually.

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
single A record containing a bitmask of results.

=cut

    # easier as RE now
    if (/^header\s+(\S+)\s+(?:rbl)?eval:(.*)$/) {
      my ($name, $fn) = ($1, $2);

      if ($fn =~ /^check_rbl/) {
	$self->add_test ($name, $fn, TYPE_RBL_EVALS);
      }
      else {
	$self->add_test ($name, $fn, TYPE_HEAD_EVALS);
      }
      next;
    }
    if (/^header\s+(\S+)\s+exists:(.*)$/) {
      $self->add_test ($1, "$2 =~ /./", TYPE_HEAD_TESTS);
      $self->{descriptions}->{$1} = "Found a $2 header";
      next;
    }
    if ( $key eq 'header' ) {
      $self->add_test (split(/\s+/,$value,2), TYPE_HEAD_TESTS);
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

    # easier as RE right now
    if (/^body\s+(\S+)\s+eval:(.*)$/) {
      $self->add_test ($1, $2, TYPE_BODY_EVALS);
      next;
    }
    if ( $key eq 'body' ) {
      $self->add_test (split(/\s+/,$value,2), TYPE_BODY_TESTS);
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
#      next;
#    }
    if ( $key eq 'uri' ) {
      $self->add_test (split(/\s+/,$value,2), TYPE_URI_TESTS);
      next;
    }

=item rawbody SYMBOLIC_TEST_NAME /pattern/modifiers

Define a raw-body pattern test.  C<pattern> is a Perl regular expression.

The 'raw body' of a message is the raw data inside all textual parts.
The text will be decoded from base64 or quoted-printable encoding,
but HTML tags and line breaks will still be present.   The pattern
will be applied line-by-line.

=item rawbody SYMBOLIC_TEST_NAME eval:name_of_eval_method([args])

Define a raw-body eval test.  See above.

=cut

    # easier as RE now
    if (/^rawbody\s+(\S+)\s+eval:(.*)$/) {
      $self->add_test ($1, $2, TYPE_RAWBODY_EVALS);
      next;
    }
    if ( $key eq 'rawbody' ) {
      $self->add_test (split(/\s+/,$value,2), TYPE_RAWBODY_TESTS);
      next;
    }

=item full SYMBOLIC_TEST_NAME /pattern/modifiers

Define a full-body pattern test.  C<pattern> is a Perl regular expression.

The 'full body' of a message is the fully pristine message body, including
all parts (including images or other attachments), MIME boundaries,
etc.

=item full SYMBOLIC_TEST_NAME eval:name_of_eval_method([args])

Define a full-body eval test.  See above.

=cut

    # easier as RE now
    if (/^full\s+(\S+)\s+eval:(.*)$/) {
      $self->add_test ($1, $2, TYPE_FULL_EVALS);
      next;
    }
    if ( $key eq 'full' ) {
      $self->add_test (split(/\s+/,$value,2), TYPE_FULL_TESTS);
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

    if ( $key eq 'meta' ) {
      $self->add_test (split(/\s+/,$value,2), TYPE_META_TESTS);
      next;
    }

=item tflags SYMBOLIC_TEST_NAME [ {net|nice|learn|userconf|noautolearn} ]

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

=item noautolearn

The test will be ignored when calculating the score for learning systems.

=back

=cut

    if ( $key eq 'tflags' ) {
      my($k,$v) = split(/\s+/, $value, 2);
      $self->{tflags}->{$k} = $v; next;
      next;     # ignored in SpamAssassin modules
    }

###########################################################################
    # SECURITY: allow_user_rules is only in affect until here.
    #
    if ($scoresonly) { goto failed_line; }

=back

=head1 ADMINISTRATOR SETTINGS

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

    # RE ...
    if (/^test\s+(\S+)\s+(ok|fail)\s+(.*)$/) {
      $self->add_regression_test($1, $2, $3); next;
    }

=item razor_config filename

Define the filename used to store Razor's configuration settings.
Currently this is left to Razor to decide.

=cut

    if ( $key eq 'razor_config' ) {
      $self->{razor_config} = $value; next;
    }

=item pyzor_path STRING

This option tells SpamAssassin specifically where to find the C<pyzor> client
instead of relying on SpamAssassin to find it in the current PATH.
Note that if I<taint mode> is enabled in the Perl interpreter, you should
use this, as the current PATH will have been cleared.

=cut

    if ( $key eq 'pyzor_path' ) {
      $self->{pyzor_path} = $value; next;
    }

=item dcc_home STRING

This option tells SpamAssassin specifically where to find the dcc homedir.
If C<dcc_path> is not specified, it will default to looking in C<dcc_home/bin>
for dcc client instead of relying on SpamAssassin to find it in the current PATH.
If it isn't found there, it will look in the current PATH. If a C<dccifd> socket
is found in C<dcc_home>, it will use that interface that instead of C<dccproc>.

=cut

    if ( $key eq 'dcc_home' ) {
      $self->{dcc_home} = $value; next;
    }

=item dcc_dccifd_path STRING

This option tells SpamAssassin specifically where to find the dccifd socket.
If C<dcc_dccifd_path> is not specified, it will default to looking in C<dcc_home>
If a C<dccifd> socket is found, it will use it instead of C<dccproc>.

=cut

    if ( $key eq 'dcc_dccifd_path' ) {
      $self->{dcc_dccifd_path} = $value; next;
    }

=item dcc_path STRING

This option tells SpamAssassin specifically where to find the C<dccproc>
client instead of relying on SpamAssassin to find it in the current PATH.
Note that if I<taint mode> is enabled in the Perl interpreter, you should
use this, as the current PATH will have been cleared.

=cut

    if ( $key eq 'dcc_path' ) {
      $self->{dcc_path} = $value; next;
    }

=item dcc_options options

Specify additional options to the dccproc(8) command. Please note that only
[A-Z -] is allowed (security).

The default is C<-R>

=cut

    # RE ...
    if (/^dcc_options\s+([A-Z -]+)/) {
      $self->{dcc_options} = $1; next;
    }

=item use_auto_whitelist ( 0 | 1 )		(default: 1)

Whether to use auto-whitelists.  Auto-whitelists track the long-term
average score for each sender and then shift the score of new messages
toward that long-term average.  This can increase or decrease the score
for messages, depending on the long-term behavior of the particular
correspondent.

For more information about the auto-whitelist system, please look at the
the C<Automatic Whitelist System> section of the README file.  The
auto-whitelist is not intended as a general-purpose replacement for static
whitelist entries added to your config files.

=cut

    if ( $key eq 'use_auto_whitelist' ) {
      $self->{use_auto_whitelist} = $value+0; next;
    }

=item auto_whitelist_factory module (default: Mail::SpamAssassin::DBBasedAddrList)

Select alternative whitelist factory module.

=cut

    if ( $key eq 'auto_whitelist_factory' ) {
      $self->{auto_whitelist_factory} = $value; next;
    }

=item auto_whitelist_path /path/to/file	(default: ~/.spamassassin/auto-whitelist)

Automatic-whitelist directory or file.  By default, each user has their own, in
their C<~/.spamassassin> directory with mode 0700, but for system-wide
SpamAssassin use, you may want to share this across all users.

=cut

    if ( $key eq 'auto_whitelist_path' ) {
      $self->{auto_whitelist_path} = $value; next;
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

    if ( $key eq 'bayes_path' ) {
      $self->{bayes_path} = $value; next;
    }

=item auto_whitelist_file_mode		(default: 0700)

The file mode bits used for the automatic-whitelist directory or file.

Make sure you specify this using the 'x' mode bits set, as it may also be used
to create directories.  However, if a file is created, the resulting file will
not have any execute bits set (the umask is set to 111).

=cut

    if ( $key eq 'auto_whitelist_file_mode' ) {
      $self->{auto_whitelist_file_mode} = $value+0; next;
    }

=item bayes_file_mode		(default: 0700)

The file mode bits used for the Bayesian filtering database files.

Make sure you specify this using the 'x' mode bits set, as it may also be used
to create directories.  However, if a file is created, the resulting file will
not have any execute bits set (the umask is set to 111).

=cut

    if ( $key eq 'bayes_file_mode' ) {
      $self->{bayes_file_mode} = $value+0; next;
    }

=item bayes_use_hapaxes		(default: 1)

Should the Bayesian classifier use hapaxes (words/tokens that occur only
once) when classifying?  This produces significantly better hit-rates, but
increases database size by about a factor of 8 to 10.

=cut

    if ( $key eq 'bayes_use_hapaxes' ) {
      $self->{bayes_use_hapaxes} = $value+0; next;
    }

=item bayes_use_chi2_combining		(default: 1)

Should the Bayesian classifier use chi-squared combining, instead of
Robinson/Graham-style naive Bayesian combining?  Chi-squared produces
more 'extreme' output results, but may be more resistant to changes
in corpus size etc.

=cut

    if ( $key eq 'bayes_use_chi2_combining' ) {
      $self->{bayes_use_chi2_combining} = $value+0; next;
    }

=item bayes_journal_max_size		(default: 102400)

SpamAssassin will opportunistically sync the journal and the database.
It will do so once a day, but will sync more often if the journal file
size goes above this setting, in bytes.  If set to 0, opportunistic
syncing will not occur.

=cut

    if ( $key eq 'bayes_journal_max_size' ) {
      $self->{bayes_journal_max_size} = $value+0; next;
    }

=item bayes_expiry_max_db_size		(default: 150000)

What should be the maximum size of the Bayes tokens database?  When expiry
occurs, the Bayes system will keep either 75% of the maximum value, or
100,000 tokens, whichever has a larger value.  150,000 tokens is roughly
equivalent to a 8Mb database file.

=cut

    if ( $key eq 'bayes_expiry_max_db_size' ) {
      $self->{bayes_expiry_max_db_size} = $value+0; next;
    }

=item bayes_auto_expire       		(default: 1)

If enabled, the Bayes system will try to automatically expire old tokens
from the database.  Auto-expiry occurs when the number of tokens in the
database surpasses the bayes_expiry_max_db_size value.

=cut

    if ( $key eq 'bayes_auto_expire' ) {
      $self->{bayes_auto_expire} = $value+0; next;
    }

=item bayes_learn_to_journal  	(default: 0)

If this option is set, whenever SpamAssassin does Bayes learning, it
will put the information into the journal instead of directly into the
database.  This lowers contention for locking the database to execute
an update, but will also cause more access to the journal and cause a
delay before the updates are actually committed to the Bayes database.

=cut

    if ( $key eq 'bayes_learn_to_journal' ) {
      $self->{bayes_learn_to_journal} = $value+0; next;
    }

=item bayes_store_module

If this option is set, the module given will be used as an alternate to the default
bayes storage mechanism.  It must conform to the published storage specification
(see Mail::SpamAssassin::BayesStore).

=cut

    if ( $key eq 'bayes_store_module' ) {
      my $module = $value;
      $module =~ /^([_A-Za-z0-9:]+)$/;
      $self->{bayes_store_module} = $1;
      next;
    }

=item bayes_sql_dsn DBI::databasetype:databasename:hostname:port

Used for BayesStoreSQL storage implementation.

This option give the connect string used to connect to the SQL based Bayes storage.

=cut

    if ( $key eq 'bayes_sql_dsn' ) {
      $self->{bayes_sql_dsn} = $value; next;
    }

=item bayes_sql_username

Used by BayesStoreSQL storage implementation.

This option gives the username used by the above DSN.

=cut

    if ( $key eq 'bayes_sql_username' ) {
      $self->{bayes_sql_username} = $value; next;
    }

=item bayes_sql_password

Used by BayesStoreSQL storage implementation.

This option gives the password used by the above DSN.

=cut

    if ( $key eq 'bayes_sql_password' ) {
      $self->{bayes_sql_password} = $value; next;
    }

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

    if ( $key eq 'user_scores_dsn' ) {
      $self->{user_scores_dsn} = $value; next;
    }

=item user_scores_sql_username username

The authorized username to connect to the above DSN.

=cut

    if( $key eq 'user_scores_sql_username' ) {
      $self->{user_scores_sql_username} = $value; next;
    }

=item user_scores_sql_password password

The password for the database username, for the above DSN.

=cut

    if( $key eq 'user_scores_sql_password' ) {
      $self->{user_scores_sql_password} = $value; next;
    }

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

The name of the table where user scores and preferences are stored, default
is userpref.

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

=item Current default query:

SELECT preference, value FROM _TABLE_ WHERE username = _USERNAME_ OR username = '@GLOBAL' ORDER BY username ASC

=item Use global and then domain level defaults:

SELECT preference, value FROM _TABLE_ WHERE username = _USERNAME_ OR username = '@GLOBAL' OR username = '@~'||_DOMAIN_ ORDER BY username ASC

=item Maybe global prefs should override user prefs:

SELECT preference, value FROM _TABLE_ WHERE username = _USERNAME_ OR username = '@GLOBAL' ORDER BY username DESC

=cut

    if ($key eq 'user_scores_sql_custom_query') {
      $self->{user_scores_sql_custom_query} = $value; next;
    }

=item user_awl_dsn DBI:databasetype:databasename:hostname:port

If you load user auto-whitelists from an SQL database, this will set the DSN
used to connect.  Example: C<DBI:mysql:spamassassin:localhost>

=cut
    if ( $key eq 'user_awl_dsn' ) {
      $self->{user_awl_dsn} = $value; next;
    }

=item user_awl_sql_username username

The authorized username to connect to the above DSN.

=cut
    if ( $key eq 'user_awl_sql_username' ) {
      $self->{user_awl_sql_username} = $value; next;
    }

=item user_awl_sql_password password

The password for the database username, for the above DSN.

=cut
    if ( $key eq 'user_awl_sql_password' ) {
      $self->{user_awl_sql_password} = $value; next;
    }

=item user_awl_sql_table tablename

The table user auto-whitelists are stored in, for the above DSN.

=cut
    if ( $key eq 'user_awl_sql_table' ) {
      $self->{user_awl_sql_table} = $value; next;
    }

=item user_scores_ldap_username

This is the Bind DN used to connect to the LDAP server.

Example: C<cn=master,dc=koehntopp,dc=de>

=cut

    if ($key eq 'user_scores_ldap_username') {
      $self->{user_scores_ldap_username} = $value; next;
    }

=item user_scores_ldap_password

This is the password used to connect to the LDAP server.

=cut
 
    if ($key eq 'user_scores_ldap_password') {
      $self->{user_scores_ldap_password} = $value; next;
    }

=item loadplugin PluginModuleName [/path/to/module.pm]

Load a SpamAssassin plugin module.  The C<PluginModuleName> is the perl module
name, used to create the plugin object itself.

C</path/to/module.pm> is the file to load, containing the module's perl code;
if it's specified as a relative path, it's considered to be relative to the
current configuration file.  If it is omitted, the module will be loaded
using perl's search path (the C<@INC> array).

See C<Mail::SpamAssassin::Plugin> for more details on writing plugins.

=cut

    if (/^loadplugin\s+(\S+)\s+(\S+)$/) {	# two-arg variant
      $self->load_plugin ($1, $2); next;
    }
    elsif ($key eq 'loadplugin') {		# single-arg variant
      $self->load_plugin ($value); next;
    }


###########################################################################

failed_line:

    # last ditch: try to see if the plugins know what to do with it
    if ($self->{main}->call_plugins ("parse_config", {
		key => $key,
		value => $value,
		line => $_,
		conf => $self,
		user_config => $scoresonly
	    }))
    {
      # a plugin dealt with it successfully.
      next;
    }

###########################################################################

    my $msg = "Failed to parse line in SpamAssassin configuration, ".
                        "skipping: $_";

    if ($self->{lint_rules}) {
      warn $msg."\n";
    } else {
      dbg ($msg);
    }
    $self->{errors}++;
  }

  # Let's do some linting here ...
  # This is here, BTW, so we can check for $self->{tests} easily before
  # finish_parsing() is called and deletes it.
  if ($self->{lint_rules}) {
    # Check for description and score issues in lint fashion
    while ( my($k,$v) = each %{$self->{descriptions}} ) {
      if (length($v) > 50) {
        warn "warning: description for $k is over 50 chars\n";
        $self->{errors}++;
      }
      if (!exists $self->{tests}->{$k}) {
        warn "warning: description exists for non-existent rule $k\n";
        $self->{errors}++;
      }
    }

    while ( my($k) = each %{$self->{scores}} ) {
      if (!exists $self->{tests}->{$k}) {
        warn "warning: score set for non-existent rule $k\n";
        $self->{errors}++;
      }
    }
  }

  # we should set a default score for all valid rules...  Do this here
  # instead of add_test because mostly 'score' occurs after the rule is
  # specified, so why set the scores to default, then set them again at
  # 'score'?
  # 
  while ( my($k,$v) = each %{$self->{tests}} ) {
    if ($self->{lint_rules}) {
      if (length($k) > 22 && $k !~ /^__/ && $k !~ /^T_/) {
        warn "warning: rule '$k' is over 22 chars\n";
        $self->{errors}++;
      }
    }

    if ( ! exists $self->{scores}->{$k} ) {
      # T_ rules (in a testing probationary period) get low, low scores
      my $set_score = ($k =~/^T_/) ? 0.01 : 1.0;

      $set_score = -$set_score if ( $self->{tflags}->{$k} =~ /\bnice\b/ );
      for my $index (0..3) {
        $self->{scoreset}->[$index]->{$k} = $set_score;
      }
    }
  }

  delete $self->{scoresonly};
}

sub add_test {
  my ($self, $name, $text, $type) = @_;

  # Don't allow invalid names ...
  if ($name !~ /^\w+$/) {
    warn "error: rule '$name' has invalid characters (not Alphanumeric + Underscore)\n";
    $self->{errors}++;
    return;
  }

  $self->{tests}->{$name} = $text;
  $self->{test_types}->{$name} = $type;
  $self->{tflags}->{$name} ||= '';
  $self->{source_file}->{$name} = $self->{currentfile};

  if ($self->{scoresonly}) {
    $self->{user_rules_to_compile}->{$type} = 1;
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
	sa_die(70, "syntax error for eval function $name: $text");
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

sub load_plugin {
  my ($self, $package, $path) = @_;
  $self->{main}->{plugins}->load_plugin ($package, $path);
}

sub load_plugin_succeeded {
  my ($self, $plugin, $package, $path) = @_;
  $self->{plugins_loaded}->{$package} = 1;
}

sub register_eval_rule {
  my ($self, $pluginobj, $nameofsub) = @_;
  $self->{eval_plugins}->{$nameofsub} = $pluginobj;
}

sub finish {
  my ($self) = @_;
  delete $self->{main};
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
