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

Mail::SpamAssassin - Spam detector and markup engine

=head1 SYNOPSIS

  my $spamtest = Mail::SpamAssassin->new();
  my $mail = $spamtest->parse($message);
  my $status = $spamtest->check($mail);

  if ($status->is_spam()) {
    $message = $status->rewrite_mail();
  }
  else {
    ...
  }
  ...

  $status->finish();
  $mail->finish();

=head1 DESCRIPTION

Mail::SpamAssassin is a module to identify spam using several methods
including text analysis, internet-based realtime blacklists, statistical
analysis, and internet-based hashing algorithms.

Using its rule base, it uses a wide range of heuristic tests on mail
headers and body text to identify "spam", also known as unsolicited bulk
email.  Once identified as spam, the mail can then be tagged as spam for
later filtering using the user's own mail user agent application or at
the mail transfer agent.

If you wish to use a command-line filter tool, try the C<spamassassin>
or the C<spamd>/C<spamc> tools provided.

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin;
use strict;
use warnings;
use bytes;

require 5.006_001;

use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Constants;
use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::Conf::SQL;
use Mail::SpamAssassin::Conf::LDAP;
use Mail::SpamAssassin::PerMsgStatus;
use Mail::SpamAssassin::Message;
use Mail::SpamAssassin::PluginHandler;
use Mail::SpamAssassin::DnsResolver;

use Errno qw(ENOENT EACCES);
use File::Basename;
use File::Path;
use File::Spec 0.8;
use File::Copy;
use Cwd;
use Config;

# Load Time::HiRes if it's available
BEGIN {
  eval { require Time::HiRes };
  Time::HiRes->import( qw(time) ) unless $@;
}

use vars qw{
  @ISA $VERSION $SUB_VERSION @EXTRA_VERSION $IS_DEVEL_BUILD $HOME_URL
  @default_rules_path @default_prefs_path
  @default_userprefs_path @default_userstate_dir
  @site_rules_path
};

$VERSION = "3.002005";      # update after release (same format as perl $])
$IS_DEVEL_BUILD = 1;        # change for release versions

# Used during the prerelease/release-candidate part of the official release
# process. If you hacked up your SA, you should add a version_tag to your .cf
# files; this variable should not be modified.
@EXTRA_VERSION = qw();

@ISA = qw();

# SUB_VERSION is now just <yyyy>-<mm>-<dd>
$SUB_VERSION = (split(/\s+/,'$LastChangedDate$ updated by SVN'))[1];

if (defined $IS_DEVEL_BUILD && $IS_DEVEL_BUILD) {
  push(@EXTRA_VERSION,
       ('r' . qw{$LastChangedRevision$ updated by SVN}[1]));
}

sub Version {
  $VERSION =~ /^(\d+)\.(\d\d\d)(\d\d\d)$/;
  return join('-', sprintf("%d.%d.%d", $1, $2, $3), @EXTRA_VERSION);
}

$HOME_URL = "http://spamassassin.apache.org/";

# note that the CWD takes priority.  This is required in case a user
# is testing a new version of SpamAssassin on a machine with an older
# version installed.  Unless you can come up with a fix for this that
# allows "make test" to work, don't change this.
@default_rules_path = (
  './rules',              # REMOVEFORINST
  '../rules',             # REMOVEFORINST
  '__local_state_dir__/__version__',
  '__def_rules_dir__',
  '__prefix__/share/spamassassin',
  '/usr/local/share/spamassassin',
  '/usr/share/spamassassin',
);

# first 3 are BSDish, latter 2 Linuxish
@site_rules_path = (
  '__local_rules_dir__',
  '__prefix__/etc/mail/spamassassin',
  '__prefix__/etc/spamassassin',
  '/usr/local/etc/spamassassin',
  '/usr/pkg/etc/spamassassin',
  '/usr/etc/spamassassin',
  '/etc/mail/spamassassin',
  '/etc/spamassassin',
);

@default_prefs_path = (
  '__local_rules_dir__/user_prefs.template',
  '__prefix__/etc/mail/spamassassin/user_prefs.template',
  '__prefix__/share/spamassassin/user_prefs.template',
  '/etc/spamassassin/user_prefs.template',
  '/etc/mail/spamassassin/user_prefs.template',
  '/usr/local/share/spamassassin/user_prefs.template',
  '/usr/share/spamassassin/user_prefs.template',
);

@default_userprefs_path = (
  '~/.spamassassin/user_prefs',
);

@default_userstate_dir = (
  '~/.spamassassin',
);

###########################################################################

=item $t = Mail::SpamAssassin->new( { opt => val, ... } )

Constructs a new C<Mail::SpamAssassin> object.  You may pass a hash
reference to the constructor which may contain the following attribute-
value pairs.

=over 4

=item debug

This is the debug options used to determine logging level.  It exists to
allow sections of debug messages (called "facilities") to be enabled or
disabled.  If this is a string, it is treated as a comma-delimited list
of the debug facilities.  If it's a hash reference, then the keys are
treated as the list of debug facilities and if it's a array reference,
then the elements are treated as the list of debug facilities.

There are also two special cases: (1) if the special case of "info" is
passed as a debug facility, then all informational messages are enabled;
(2) if the special case of "all" is passed as a debug facility, then all
debugging facilities are enabled.

=item rules_filename

The filename/directory to load spam-identifying rules from. (optional)

=item site_rules_filename

The directory to load site-specific spam-identifying rules from. (optional)

=item userprefs_filename

The filename to load preferences from. (optional)

=item userstate_dir

The directory user state is stored in. (optional)

=item config_tree_recurse

Set to C<1> to recurse through directories when reading configuration
files, instead of just reading a single level.  (optional, default 0)

=item config_text

The text of all rules and preferences.  If you prefer not to load the rules
from files, read them in yourself and set this instead.  As a result, this will
override the settings for C<rules_filename>, C<site_rules_filename>,
and C<userprefs_filename>.

=item post_config_text

Similar to C<config_text>, this text is placed after config_text to allow an
override of config files.

=item force_ipv4

If set to 1, DNS tests will not attempt to use IPv6. Use if the existing tests
for IPv6 availablity produce incorrect results or crashes.

=item languages_filename

If you want to be able to use the language-guessing rule
C<UNWANTED_LANGUAGE_BODY>, and are using C<config_text> instead of
C<rules_filename>, C<site_rules_filename>, and C<userprefs_filename>, you will
need to set this.  It should be the path to the B<languages> file normally
found in the SpamAssassin B<rules> directory.

=item local_tests_only

If set to 1, no tests that require internet access will be performed. (default:
0)

=item ignore_site_cf_files

If set to 1, any rule files found in the C<site_rules_filename> directory will
be ignored.  *.pre files (used for loading plugins) found in the
C<site_rules_filename> directory will still be used. (default: 0)

=item dont_copy_prefs

If set to 1, the user preferences file will not be created if it doesn't
already exist. (default: 0)

=item save_pattern_hits

If set to 1, the patterns hit can be retrieved from the
C<Mail::SpamAssassin::PerMsgStatus> object.  Used for debugging.

=item home_dir_for_helpers

If set, the B<HOME> environment variable will be set to this value
when using test applications that require their configuration data,
such as Razor, Pyzor and DCC.

=item username

If set, the C<username> attribute will use this as the current user's name.
Otherwise, the default is taken from the runtime environment (ie. this process'
effective UID under UNIX).

=back

If none of C<rules_filename>, C<site_rules_filename>, C<userprefs_filename>, or
C<config_text> is set, the C<Mail::SpamAssassin> module will search for the
configuration files in the usual installed locations using the below variable
definitions which can be passed in.

=over 4

=item PREFIX

Used as the root for certain directory paths such as:

  '__prefix__/etc/mail/spamassassin'
  '__prefix__/etc/spamassassin'

Defaults to "@@PREFIX@@".

=item DEF_RULES_DIR

Location where the default rules are installed.  Defaults to
"@@DEF_RULES_DIR@@".

=item LOCAL_RULES_DIR

Location where the local site rules are installed.  Defaults to
"@@LOCAL_RULES_DIR@@".

=item LOCAL_STATE_DIR

Location of the local state directory, mainly used for installing updates via
C<sa-update> and compiling rulesets to native code.  Defaults to
"@@LOCAL_STATE_DIR@@".

=back


=cut

# undocumented ctor settings: 
#
# - keep_config_parsing_metadata: used by build/listpromotable, default 0

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = shift;
  if (!defined $self) { $self = { }; }
  bless ($self, $class);

  # basic backwards compatibility; debug used to be a boolean.
  # translate that into 'all', which is what it meant before 3.1.0.
  if ($self->{debug} && $self->{debug} eq '1') {
    $self->{debug} = 'all';
  }

  # enable or disable debugging
  Mail::SpamAssassin::Logger::add_facilities($self->{debug});

  # first debugging information possibly printed should be the version
  dbg("generic: SpamAssassin version " . Version());

  # if the libs are installed in an alternate location, and the caller
  # didn't set PREFIX, we should have an estimated guess ready, values
  # substituted at 'make' time
  $self->{PREFIX}		||= '@@PREFIX@@';
  $self->{DEF_RULES_DIR}	||= '@@DEF_RULES_DIR@@';
  $self->{LOCAL_RULES_DIR}	||= '@@LOCAL_RULES_DIR@@';
  $self->{LOCAL_STATE_DIR}	||= '@@LOCAL_STATE_DIR@@';

  $self->{conf} ||= new Mail::SpamAssassin::Conf ($self);
  $self->{plugins} = Mail::SpamAssassin::PluginHandler->new ($self);

  $self->{save_pattern_hits} ||= 0;

  # Make sure that we clean $PATH if we're tainted
  Mail::SpamAssassin::Util::clean_path_in_taint_mode();

  if (!defined $self->{username}) {
    $self->{username} = (Mail::SpamAssassin::Util::portable_getpwuid ($>))[0];
  }

  $self->create_locker();

  $self->{resolver} = Mail::SpamAssassin::DnsResolver->new($self);

  $self;
}

sub create_locker {
  my ($self) = @_;

  my $class;
  my $m = $self->{conf}->{lock_method};

  # let people choose what they want -- even if they may not work on their
  # OS.  (they could be using cygwin!)
  if ($m eq 'win32') { $class = 'Win32'; }
  elsif ($m eq 'flock') { $class = 'Flock'; }
  elsif ($m eq 'nfssafe') { $class = 'UnixNFSSafe'; }
  else {
    # OS-specific defaults
    if (Mail::SpamAssassin::Util::am_running_on_windows()) {
      $class = 'Win32';
    } else {
      $class = 'UnixNFSSafe';
    }
  }

  # this could probably be made a little faster; for now I'm going
  # for slow but safe, by keeping in quotes
  eval '
    use Mail::SpamAssassin::Locker::'.$class.';
    $self->{locker} = new Mail::SpamAssassin::Locker::'.$class.' ($self);
  '; ($@) and die $@;

  if (!defined $self->{locker}) { die "locker: oops! no locker"; }
}

###########################################################################

=item parse($message, $parse_now)

Parse will return a Mail::SpamAssassin::Message object with just the
headers parsed.  When calling this function, there are two optional
parameters that can be passed in: $message is either undef (which will
use STDIN), a scalar of the entire message, an array reference of the
message with 1 line per array element, or a file glob which holds the
entire contents of the message; and $parse_now, which specifies whether
or not to create the MIME tree at parse time or later as necessary.

The I<$parse_now> option, by default, is set to false (0).  This
allows SpamAssassin to not have to generate the tree of internal
data nodes if the information is not going to be used.  This is
handy, for instance, when running C<spamassassin -d>, which only
needs the pristine header and body which is always parsed and stored
by this function.

For more information, please see the C<Mail::SpamAssassin::Message>
and C<Mail::SpamAssassin::Message::Node> POD.

=cut

sub parse {
  my($self, $message, $parsenow) = @_;
  $self->init(1);
  my $msg = Mail::SpamAssassin::Message->new({message=>$message, parsenow=>$parsenow, normalize=>$self->{conf}->{normalize_charset}});

  # bug 5069: The goal here is to get rendering plugins to do things
  # like OCR, convert doc and pdf to text, etc, though it could be anything
  # that wants to process the message after it's been parsed.
  $self->call_plugins("post_message_parse", { message => $msg });

  return $msg;
}


###########################################################################

=item $status = $f->check ($mail)

Check a mail, encapsulated in a C<Mail::SpamAssassin::Message> object,
to determine if it is spam or not.

Returns a C<Mail::SpamAssassin::PerMsgStatus> object which can be
used to test or manipulate the mail message.

Note that the C<Mail::SpamAssassin> object can be re-used for further messages
without affecting this check; in OO terminology, the C<Mail::SpamAssassin>
object is a "factory".   However, if you do this, be sure to call the
C<finish()> method on the status objects when you're done with them.

=cut

sub check {
  my ($self, $mail_obj) = @_;

  $self->init(1);
  my $msg = Mail::SpamAssassin::PerMsgStatus->new($self, $mail_obj);
  $msg->check();
  $msg;
}

=item $status = $f->check_message_text ($mailtext)

Check a mail, encapsulated in a plain string C<$mailtext>, to determine if it
is spam or not.

Otherwise identical to C<check()> above.

=cut

sub check_message_text {
  my ($self, $mailtext) = @_;
  my $msg = $self->parse($mailtext, 1);
  my $result = $self->check($msg);

  # Kill off the metadata ...
  # Do _NOT_ call normal finish() here.  PerMsgStatus has a copy of
  # the message.  So killing it here will cause things like
  # rewrite_message() to fail. <grrr>
  #
  $msg->finish_metadata();

  return $result;
}

###########################################################################

=item $status = $f->learn ($mail, $id, $isspam, $forget)

Learn from a mail, encapsulated in a C<Mail::SpamAssassin::Message> object.

If C<$isspam> is set, the mail is assumed to be spam, otherwise it will
be learnt as non-spam.

If C<$forget> is set, the attributes of the mail will be removed from
both the non-spam and spam learning databases.

C<$id> is an optional message-identification string, used internally
to tag the message.  If it is C<undef>, the Message-Id of the message
will be used.  It should be unique to that message.

Returns a C<Mail::SpamAssassin::PerMsgLearner> object which can be used to
manipulate the learning process for each mail.

Note that the C<Mail::SpamAssassin> object can be re-used for further messages
without affecting this check; in OO terminology, the C<Mail::SpamAssassin>
object is a "factory".   However, if you do this, be sure to call the
C<finish()> method on the learner objects when you're done with them.

C<learn()> and C<check()> can be run using the same factory.  C<init_learner()>
must be called before using this method.

=cut

sub learn {
  my ($self, $mail_obj, $id, $isspam, $forget) = @_;
  local ($_);

  require Mail::SpamAssassin::PerMsgLearner;
  $self->init(1);
  my $msg = Mail::SpamAssassin::PerMsgLearner->new($self, $mail_obj);

  if ($forget) {
    dbg("learn: forgetting message");
    $msg->forget($id);
  } elsif ($isspam) {
    dbg("learn: learning spam");
    $msg->learn_spam($id);
  } else {
    dbg("learn: learning ham");
    $msg->learn_ham($id);
  }

  $msg;
}

###########################################################################

=item $f->init_learner ( [ { opt => val, ... } ] )

Initialise learning.  You may pass the following attribute-value pairs to this
method.

=over 4

=item caller_will_untie

Whether or not the code calling this method will take care of untie'ing
from the Bayes databases (by calling C<finish_learner()>) (optional, default 0).

=item force_expire

Should an expiration run be forced to occur immediately? (optional, default 0).

=item learn_to_journal

Should learning data be written to the journal, instead of directly to the
databases? (optional, default 0).

=item wait_for_lock

Whether or not to wait a long time for locks to complete (optional, default 0).

=item opportunistic_expire_check_only

During the opportunistic journal sync and expire check, don't actually do the
expire but report back whether or not it should occur (optional, default 0).

=item no_relearn

If doing a learn operation, and the message has already been learned as
the opposite type, don't re-learn the message.

=back

=cut

sub init_learner {
  my $self = shift;
  my $opts = shift;
  dbg("learn: initializing learner");

  # Make sure we're already initialized ...
  $self->init(1);

  my %kv = (
    'force_expire'			=> 'learn_force_expire',
    'learn_to_journal'			=> 'learn_to_journal',
    'caller_will_untie'			=> 'learn_caller_will_untie',
    'wait_for_lock'			=> 'learn_wait_for_lock',
    'opportunistic_expire_check_only'	=> 'opportunistic_expire_check_only',
    'no_relearn'			=> 'learn_no_relearn',
  );

  my %ret;

  # Set any other options that need setting ...
  while( my($k,$v) = each %kv ) {
    $ret{$k} = $self->{$v};
    if (exists $opts->{$k}) { $self->{$v} = $opts->{$k}; }
  }

  return \%ret;
}

###########################################################################

=item $f->rebuild_learner_caches ({ opt => val })

Rebuild any cache databases; should be called after the learning process.
Options include: C<verbose>, which will output diagnostics to C<stdout>
if set to 1.

=cut

sub rebuild_learner_caches {
  my $self = shift;
  my $opts = shift;
  $self->{bayes_scanner}->sync(1,1,$opts) if $self->{bayes_scanner};
  1;
}

=item $f->finish_learner ()

Finish learning.

=cut

sub finish_learner {
  my $self = shift;
  $self->{bayes_scanner}->sanity_check_is_untied(1) if $self->{bayes_scanner};
  1;
}

=item $f->dump_bayes_db()

Dump the contents of the Bayes DB

=cut

sub dump_bayes_db {
  my($self,@opts) = @_;
  $self->{bayes_scanner}->dump_bayes_db(@opts) if $self->{bayes_scanner};
}

=item $f->signal_user_changed ( [ { opt => val, ... } ] )

Signals that the current user has changed (possibly using C<setuid>), meaning
that SpamAssassin should close any per-user databases it has open, and re-open
using ones appropriate for the new user.

Note that this should be called I<after> reading any per-user configuration, as
that data may override some paths opened in this method.  You may pass the
following attribute-value pairs:

=over 4

=item username

The username of the user.  This will be used for the C<username> attribute.

=item user_dir

A directory to use as a 'home directory' for the current user's data,
overriding the system default.  This directory must be readable and writable by
the process.  Note that the resulting C<userstate_dir> will be the
C<.spamassassin> subdirectory of this dir.

=item userstate_dir

A directory to use as a directory for the current user's data, overriding the
system default.  This directory must be readable and writable by the process.
The default is C<user_dir/.spamassassin>.

=back

=cut

sub signal_user_changed {
  my $self = shift;
  my $opts = shift;
  my $set = 0;

  dbg("info: user has changed");

  if (defined $opts && $opts->{username}) {
    $self->{username} = $opts->{username};
  } else {
    undef $self->{username};
  }
  if (defined $opts && $opts->{user_dir}) {
    $self->{user_dir} = $opts->{user_dir};
  } else {
    undef $self->{user_dir};
  }
  if (defined $opts && $opts->{userstate_dir}) {
    $self->{userstate_dir} = $opts->{userstate_dir};
  } else {
    undef $self->{userstate_dir};
  }

  # reopen bayes dbs for this user
  $self->{bayes_scanner}->finish() if $self->{bayes_scanner};
  if ($self->{conf}->{use_bayes}) {
      require Mail::SpamAssassin::Bayes;
      $self->{bayes_scanner} = new Mail::SpamAssassin::Bayes ($self);
  } else {
      delete $self->{bayes_scanner} if $self->{bayes_scanner};
  }

  # this user may have a different learn_to_journal setting, so reset appropriately
  $self->{'learn_to_journal'} = $self->{conf}->{bayes_learn_to_journal};

  $set |= 1 unless $self->{local_tests_only};
  $set |= 2 if $self->{bayes_scanner} && $self->{bayes_scanner}->is_scan_available();

  $self->{conf}->set_score_set ($set);

  $self->call_plugins ("signal_user_changed", {
		username => $self->{username},
		userstate_dir => $self->{userstate_dir},
		user_dir => $self->{user_dir},
	      });

  1;
}

###########################################################################

=item $f->report_as_spam ($mail, $options)

Report a mail, encapsulated in a C<Mail::SpamAssassin::Message> object, as
human-verified spam.  This will submit the mail message to live,
collaborative, spam-blocker databases, allowing other users to block this
message.

It will also submit the mail to SpamAssassin's Bayesian learner.

Options is an optional reference to a hash of options.  Currently these
can be:

=over 4

=item dont_report_to_dcc

Inhibits reporting of the spam to DCC.

=item dont_report_to_pyzor

Inhibits reporting of the spam to Pyzor.

=item dont_report_to_razor

Inhibits reporting of the spam to Razor.

=item dont_report_to_spamcop

Inhibits reporting of the spam to SpamCop.

=back

=cut

sub report_as_spam {
  my ($self, $mail, $options) = @_;
  local ($_);

  $self->init(1);

  # learn as spam if enabled
  if ( $self->{conf}->{bayes_learn_during_report} ) {
    $self->learn ($mail, undef, 1, 0);
  }

  require Mail::SpamAssassin::Reporter;
  $mail = Mail::SpamAssassin::Reporter->new($self, $mail, $options);
  $mail->report();
}

###########################################################################

=item $f->revoke_as_spam ($mail, $options)

Revoke a mail, encapsulated in a C<Mail::SpamAssassin::Message> object, as
human-verified ham (non-spam).  This will revoke the mail message from live,
collaborative, spam-blocker databases, allowing other users to block this
message.

It will also submit the mail to SpamAssassin's Bayesian learner as nonspam.

Options is an optional reference to a hash of options.  Currently these
can be:

=over 4

=item dont_report_to_razor

Inhibits revoking of the spam to Razor.


=back

=cut

sub revoke_as_spam {
  my ($self, $mail, $options) = @_;
  local ($_);

  $self->init(1);

  # learn as nonspam
  $self->learn ($mail, undef, 0, 0);

  require Mail::SpamAssassin::Reporter;
  $mail = Mail::SpamAssassin::Reporter->new($self, $mail, $options);
  $mail->revoke ();
}

###########################################################################

=item $f->add_address_to_whitelist ($addr)

Given a string containing an email address, add it to the automatic
whitelist database.

=cut

sub add_address_to_whitelist {
  my ($self, $addr) = @_;

  $self->call_plugins("whitelist_address", { address => $addr });
}

###########################################################################

=item $f->add_all_addresses_to_whitelist ($mail)

Given a mail message, find as many addresses in the usual headers (To, Cc, From
etc.), and the message body, and add them to the automatic whitelist database.

=cut

sub add_all_addresses_to_whitelist {
  my ($self, $mail_obj) = @_;

  foreach my $addr ($self->find_all_addrs_in_mail ($mail_obj)) {
    $self->call_plugins("whitelist_address", { address => $addr });
  }
}

###########################################################################

=item $f->remove_address_from_whitelist ($addr)

Given a string containing an email address, remove it from the automatic
whitelist database.

=cut

sub remove_address_from_whitelist {
  my ($self, $addr) = @_;

  $self->call_plugins("remove_address", { address => $addr });
}

###########################################################################

=item $f->remove_all_addresses_from_whitelist ($mail)

Given a mail message, find as many addresses in the usual headers (To, Cc, From
etc.), and the message body, and remove them from the automatic whitelist
database.

=cut

sub remove_all_addresses_from_whitelist {
  my ($self, $mail_obj) = @_;

  foreach my $addr ($self->find_all_addrs_in_mail ($mail_obj)) {
    $self->call_plugins("remove_address", { address => $addr });
  }
}

###########################################################################

=item $f->add_address_to_blacklist ($addr)

Given a string containing an email address, add it to the automatic
whitelist database with a high score, effectively blacklisting them.

=cut

sub add_address_to_blacklist {
  my ($self, $addr) = @_;
  $self->call_plugins("blacklist_address", { address => $addr });
}

###########################################################################

=item $f->add_all_addresses_to_blacklist ($mail)

Given a mail message, find addresses in the From headers and add them to the
automatic whitelist database with a high score, effectively blacklisting them.

Note that To and Cc addresses are not used.

=cut

sub add_all_addresses_to_blacklist {
  my ($self, $mail_obj) = @_;

  $self->init(1);

  my @addrlist = ();
  my @hdrs = $mail_obj->get_header ('From');
  if ($#hdrs >= 0) {
    push (@addrlist, $self->find_all_addrs_in_line (join (" ", @hdrs)));
  }

  foreach my $addr (@addrlist) {
    $self->call_plugins("blacklist_address", { address => $addr });
  }

}

###########################################################################

=item $text = $f->remove_spamassassin_markup ($mail)

Returns the text of the message, with any SpamAssassin-added text (such
as the report, or X-Spam-Status headers) stripped.

Note that the B<$mail> object is not modified.

Warning: if the input message in B<$mail> contains a mixture of CR-LF
(Windows-style) and LF (UNIX-style) line endings, it will be "canonicalized"
to use one or the other consistently throughout.

=cut

sub remove_spamassassin_markup {
  my ($self, $mail_obj) = @_;
  local ($_);

  my $mbox = $mail_obj->get_mbox_separator() || '';

  dbg("markup: removing markup");

  # Go looking for a "report_safe" encapsulated message.  Abort out ASAP
  # if we have definitive proof it's not an encapsulated message.
  my $ct = $mail_obj->get_header("Content-Type") || '';
  if ( $ct =~ m!^\s*multipart/mixed;\s+boundary\s*=\s*["']?(.+?)["']?(?:;|$)!i ) {

    # Ok, this is a possible encapsulated message, search for the
    # appropriate mime part and deal with it if necessary.
    my $boundary = "\Q$1\E";
    my @msg = split(/^/,$mail_obj->get_pristine_body());

    my $flag = 0;
    $ct   = '';
    my $cd = '';
    for ( my $i = 0 ; $i <= $#msg ; $i++ ) {
      # only look at mime part headers
      next unless ( $msg[$i] =~ /^--$boundary\r?$/ || $flag );

      if ( $msg[$i] =~ /^\s*$/ ) {    # end of mime header

        # Ok, we found the encapsulated piece ...
	if ($ct =~ m@^(?:message/rfc822|text/plain);\s+x-spam-type=original@ ||
	    ($ct eq "message/rfc822" &&
	     $cd eq $self->{conf}->{'encapsulated_content_description'}))
        {
          splice @msg, 0, $i+1;  # remove the front part, including the blank line

          # find the end and chop it off
          for ( $i = 0 ; $i <= $#msg ; $i++ ) {
            if ( $msg[$i] =~ /^--$boundary/ ) {
              splice @msg, ($msg[$i-1] =~ /\S/ ? $i : $i-1);
	      # will remove the blank line (not sure it'll always be
	      # there) and everything below.  don't worry, the splice
	      # guarantees the for will stop ...
            }
          }

	  # Ok, we're done.  Return the rewritten message.
	  return join('', $mbox, @msg);
        }

        $flag = 0;
        $ct   = '';
        $cd   = '';
        next;
      }

      # Ok, we're in the mime header ...  Capture the appropriate headers...
      $flag = 1;
      if ( $msg[$i] =~ /^Content-Type:\s+(.+?)\s*$/i ) {
        $ct = $1;
      }
      elsif ( $msg[$i] =~ /^Content-Description:\s+(.+?)\s*$/i ) {
        $cd = $1;
      }
    }
  }

  # Ok, if we got here, the message wasn't a report_safe encapsulated message.
  # So treat it like a "report_safe 0" message.
  my $hdrs = $mail_obj->get_pristine_header();
  my $body = $mail_obj->get_pristine_body();

  # remove DOS line endings
  $hdrs =~ s/\r//gs;

  # unfold SA added headers, but not X-Spam-Prev headers ...
  $hdrs = "\n".$hdrs;   # simplifies regexp below
  1 while $hdrs =~ s/(\nX-Spam-(?!Prev).+?)\n[ \t]+(\S.*\n)/$1 $2/g;
  $hdrs =~ s/^\n//;

###########################################################################
  # Backward Compatibilty, pre 3.0.x.

  # deal with rewritten headers w/out X-Spam-Prev- versions ...
  $self->init(1);
  foreach my $header ( keys %{$self->{conf}->{rewrite_header}} ) {
    # let the 3.0 decoding do it...
    next if ($hdrs =~ /^X-Spam-Prev-$header:/im);

    dbg("markup: removing markup in $header");
    if ($header eq 'Subject') {
      my $tag = $self->{conf}->{rewrite_header}->{'Subject'};
      $tag = quotemeta($tag);
      $tag =~ s/_HITS_/\\d{2}\\.\\d{2}/g;
      $tag =~ s/_SCORE_/\\d{2}\\.\\d{2}/g;
      $tag =~ s/_REQD_/\\d{2}\\.\\d{2}/g;
      1 while $hdrs =~ s/^Subject: ${tag} /Subject: /gm;
    } else {
      $hdrs =~ s/^(${header}:[ \t].*?)\t\([^)]*\)$/$1/gm;
    }
  }

  # Now deal with report cleansing from 2.4x and previous.
  # possibly a blank line, "SPAM: ----.+", followed by "SPAM: stuff" lines,
  # followed by another "SPAM: ----.+" line, followed by a blank line.
  1 while ($body =~ s/^\n?SPAM: ----.+\n(?:SPAM:.*\n)*SPAM: ----.+\n\n//);
###########################################################################

  # 3.0 version -- support for previously-nonexistent Subject hdr.
  # ensure the Subject line didn't *really* contain "(nonexistent)" in
  # the original message!
  if ($hdrs =~ /^X-Spam-Prev-Subject:\s*\(nonexistent\)$/m
        && $hdrs !~ /^Subject:.*\(nonexistent\).*$/m)
  {
    $hdrs =~ s/(^|\n)X-Spam-Prev-Subject:\s*\(nonexistent\)\n/$1\n/s;
    $hdrs =~ s/(^|\n)Subject:\s*[ \t]*.*\n(?:\s+\S.*\n)*/$1\n/s;
  }

  # 3.0 version -- revert from X-Spam-Prev to original ...
  while ($hdrs =~ s/^X-Spam-Prev-(([^:]+:)[ \t]*.*\n(?:\s+\S.*\n)*)//m) {
    my($hdr, $name) = ($1,$2);

    # If the rewritten version doesn't exist, we should deal with it anyway...
    unless ($hdrs =~ s/^$name[ \t]*.*\n(?:\s+\S.*\n)*/$hdr/m) {
      $hdrs =~ s/\n\n/\n$hdr\n/;
    }
  }

  # remove any other X-Spam headers we added, will be unfolded
  $hdrs = "\n".$hdrs;   # simplifies regexp below
  1 while $hdrs =~ s/\nX-Spam-.*\n/\n/g;
  $hdrs =~ s/^\n//;

  # re-add DOS line endings
  if ($mail_obj->{line_ending} ne "\n") {
    $hdrs =~ s/\r?\n/$mail_obj->{line_ending}/gs;
  }

  # Put the whole thing back together ...
  return join ('', $mbox, $hdrs, $body);
}

###########################################################################

=item $f->read_scoreonly_config ($filename)

Read a configuration file and parse user preferences from it.

User preferences are as defined in the C<Mail::SpamAssassin::Conf> manual page.
In other words, they include scoring options, scores, whitelists and
blacklists, and so on, but do not include rule definitions, privileged
settings, etc. unless C<allow_user_rules> is enabled; and they never include
the administrator settings.

=cut

sub read_scoreonly_config {
  my ($self, $filename) = @_;

  if (!open(IN,"<$filename")) {
    # the file may not exist; this should not be verbose
    dbg("config: read_scoreonly_config: cannot open \"$filename\": $!");
    return;
  }

  my $text = "file start $filename\n"
        . join ('', <IN>)
        # add an extra \n in case file did not end in one.
        . "\nfile end $filename\n";

  close IN;

  $self->{conf}->{main} = $self;
  $self->{conf}->parse_scores_only ($text);
  $self->{conf}->finish_parsing(1);

  delete $self->{conf}->{main};	# to allow future GC'ing
}

###########################################################################

=item $f->load_scoreonly_sql ($username)

Read configuration paramaters from SQL database and parse scores from it.  This
will only take effect if the perl C<DBI> module is installed, and the
configuration parameters C<user_scores_dsn>, C<user_scores_sql_username>, and
C<user_scores_sql_password> are set correctly.

The username in C<$username> will also be used for the C<username> attribute of
the Mail::SpamAssassin object.

=cut

sub load_scoreonly_sql {
  my ($self, $username) = @_;

  my $src = Mail::SpamAssassin::Conf::SQL->new ($self);
  $self->{username} = $username;
  unless ($src->load($username)) {
    return 0;
  }
  return 1;
}

###########################################################################

=item $f->load_scoreonly_ldap ($username)

Read configuration paramaters from an LDAP server and parse scores from it.
This will only take effect if the perl C<Net::LDAP> and C<URI> modules are
installed, and the configuration parameters C<user_scores_dsn>,
C<user_scores_ldap_username>, and C<user_scores_ldap_password> are set
correctly.

The username in C<$username> will also be used for the C<username> attribute of
the Mail::SpamAssassin object.

=cut

sub load_scoreonly_ldap {
  my ($self, $username) = @_;

  dbg("config: load_scoreonly_ldap($username)");
  my $src = Mail::SpamAssassin::Conf::LDAP->new ($self);
  $self->{username} = $username;
  $src->load($username);
}

###########################################################################

=item $f->set_persistent_address_list_factory ($factoryobj)

Set the persistent address list factory, used to create objects for the
automatic whitelist algorithm's persistent-storage back-end.  See
C<Mail::SpamAssassin::PersistentAddrList> for the API these factory objects
must implement, and the API the objects they produce must implement.

=cut

sub set_persistent_address_list_factory {
  my ($self, $fac) = @_;
  $self->{pers_addr_list_factory} = $fac;
}

###########################################################################

=item $f->compile_now ($use_user_prefs, $keep_userstate)

Compile all patterns, load all configuration files, and load all
possibly-required Perl modules.

Normally, Mail::SpamAssassin uses lazy evaluation where possible, but if you
plan to fork() or start a new perl interpreter thread to process a message,
this is suboptimal, as each process/thread will have to perform these actions.

Call this function in the master thread or process to perform the actions
straightaway, so that the sub-processes will not have to.

If C<$use_user_prefs> is 0, this will initialise the SpamAssassin
configuration without reading the per-user configuration file and it will
assume that you will call C<read_scoreonly_config> at a later point.

If C<$keep_userstate> is true, compile_now() will revert any configuration
options which have a default with I<__userstate__> in it post-init(),
and then re-change the option before returning.  This lets you change
I<$ENV{'HOME'}> to a temp directory, have compile_now() and create any
files there as necessary without disturbing the actual files as changed
by a configuration option.  By default, this is disabled.

=cut

sub compile_now {
  my ($self, $use_user_prefs, $deal_with_userstate) = @_;

  # tell plugins we are here
  $self->call_plugins("compile_now_start",
		      { use_user_prefs => $use_user_prefs,
			keep_userstate => $deal_with_userstate});

  # note: this may incur network access. Good.  We want to make sure
  # as much as possible is preloaded!
  my @testmsg = ("From: ignore\@compiling.spamassassin.taint.org\n", 
    "Message-Id:  <".time."\@spamassassin_spamd_init>\n", "\n",
    "I need to make this message body somewhat long so TextCat preloads\n"x20);

  dbg("ignore: test message to precompile patterns and load modules");

  # Backup default values which deal with userstate.
  # This is done so we can create any new files in, presumably, a temp dir.
  # see bug 2762 for more details.
  my %backup = ();
  if (defined $deal_with_userstate && $deal_with_userstate) {
    while(my($k,$v) = each %{$self->{conf}}) {
      $backup{$k} = $v if (defined $v && !ref($v) && $v =~/__userstate__/);
    }
  }

  $self->init($use_user_prefs);

  # if init() didn't change the value from default, forget about it.
  # if the value is different, remember the new version, and reset the default.
  while(my($k,$v) = each %backup) {
    if ($self->{conf}->{$k} eq $v) {
      delete $backup{$k};
    }
    else {
      my $backup = $backup{$k};
      $backup{$k} = $self->{conf}->{$k};
      $self->{conf}->{$k} = $backup;
    }
  }

  my $mail = $self->parse(\@testmsg, 1);
  my $status = Mail::SpamAssassin::PerMsgStatus->new($self, $mail,
                        { disable_auto_learning => 1 } );

  # We want to turn off the bayes rules for this test msg
  my $use_bayes_rules_value = $self->{conf}->{use_bayes_rules};
  $self->{conf}->{use_bayes_rules} = 0;
  $status->check();
  $self->{conf}->{use_bayes_rules} = $use_bayes_rules_value;
  $status->finish();
  $mail->finish();
  $self->finish_learner();

  $self->{conf}->free_uncompiled_rule_source();

  # load SQL modules now as well
  my $dsn = $self->{conf}->{user_scores_dsn};
  if ($dsn ne '') {
    if ($dsn =~ /^ldap:/i) {
      Mail::SpamAssassin::Conf::LDAP::load_modules();
    } else {
      Mail::SpamAssassin::Conf::SQL::load_modules();
    }
  }

  # make sure things are ready for scanning
  $self->{bayes_scanner}->sanity_check_is_untied() if $self->{bayes_scanner};
  $self->call_plugins("compile_now_finish",
		      { use_user_prefs => $use_user_prefs,
			keep_userstate => $deal_with_userstate});

  # Reset any non-default values to the post-init() version.
  while(my($k,$v) = each %backup) {
    $self->{conf}->{$k} = $v;
  }

  # clear sed_path_cache
  delete $self->{conf}->{sed_path_cache};

  1;
}

###########################################################################

=item $f->debug_diagnostics ()

Output some diagnostic information, useful for debugging SpamAssassin
problems.

=cut

sub debug_diagnostics {
  my ($self) = @_;

  # load this class lazily, to avoid overhead when this method isn't
  # called.
  eval {
    require Mail::SpamAssassin::Util::DependencyInfo;
    dbg(Mail::SpamAssassin::Util::DependencyInfo::debug_diagnostics($self));
  };
}

###########################################################################

=item $failed = $f->lint_rules ()

Syntax-check the current set of rules.  Returns the number of 
syntax errors discovered, or 0 if the configuration is valid.

=cut

sub lint_rules {
  my ($self) = @_;

  dbg("ignore: using a test message to lint rules");
  my @testmsg = ("From: ignore\@compiling.spamassassin.taint.org\n", 
    "Subject: \n",
    "Message-Id:  <".CORE::time()."\@lint_rules>\n", "\n",
    "I need to make this message body somewhat long so TextCat preloads\n"x20);

  $self->{lint_rules} = $self->{conf}->{lint_rules} = 1;
  $self->{syntax_errors} = 0;

  my $olddcp = $self->{dont_copy_prefs};
  $self->{dont_copy_prefs} = 1;

  $self->init(1);
  $self->{syntax_errors} += $self->{conf}->{errors};

  $self->{dont_copy_prefs} = $olddcp;       # revert back to previous

  # bug 5048: override settings to ensure a faster lint
  $self->{'conf'}->{'use_auto_whitelist'} = 0;
  $self->{'conf'}->{'bayes_auto_learn'} = 0;

  my $mail = $self->parse(\@testmsg, 1);
  my $status = Mail::SpamAssassin::PerMsgStatus->new($self, $mail,
                        { disable_auto_learning => 1 } );
  $status->check();

  $self->{syntax_errors} += $status->{rule_errors};
  $status->finish();
  $mail->finish();

  return ($self->{syntax_errors});
}

###########################################################################

=item $f->finish()

Destroy this object, so that it will be garbage-collected once it
goes out of scope.  The object will no longer be usable after this
method is called.

=cut

sub finish {
  my ($self) = @_;

  $self->call_plugins("finish_tests", { conf => $self->{conf},
                                        main => $self });

  $self->{conf}->finish(); delete $self->{conf};
  $self->{plugins}->finish(); delete $self->{plugins};

  if ($self->{bayes_scanner}) {
    $self->{bayes_scanner}->finish();
    delete $self->{bayes_scanner};
  }

  $self->{resolver}->finish();

  %{$self} = ();
}

###########################################################################
# non-public methods.

sub init {
  my ($self, $use_user_pref) = @_;

  # Allow init() to be called multiple times, but only run once.
  if (defined $self->{_initted}) {
    # If the PID changes, reseed the PRNG and the DNS ID counter
    if ($self->{_initted} != $$) {
      $self->{_initted} = $$;
      srand;
      $self->{resolver}->reinit_post_fork();
    }
    return;
  }

  # Note that this PID has run init()
  $self->{_initted} = $$;

  #fix spamd reading root prefs file
  if (!defined $use_user_pref) {
    $use_user_pref = 1;
  }

  if (!defined $self->{config_text}) {
    $self->{config_text} = '';

    # read a file called "init.pre" in site rules dir *before* all others;
    # even the system config.
    my $siterules = $self->{site_rules_filename};
    $siterules ||= $self->first_existing_path (@site_rules_path);

    my $sysrules = $self->{rules_filename};
    $sysrules ||= $self->first_existing_path (@default_rules_path);

    if ($siterules) {
      $self->{config_text} .= $self->read_pre($siterules, 'site rules pre files');
    }
    else {
      warn "config: could not find site rules directory\n";
    }

    if ($sysrules) {
      $self->{config_text} .= $self->read_pre($sysrules, 'sys rules pre files');
    }
    else {
      warn "config: could not find sys rules directory\n";
    }

    if ($sysrules) {
      $self->{config_text} .= $self->read_cf($sysrules, 'default rules dir');
    }

    if (!$self->{languages_filename}) {
      $self->{languages_filename} = $self->find_rule_support_file("languages");
    }

    if ($siterules && !$self->{ignore_site_cf_files}) {
      $self->{config_text} .= $self->read_cf($siterules, 'site rules dir');
    }

    if ( $use_user_pref != 0 ) {
      $self->get_and_create_userstate_dir();

      # user prefs file
      my $fname = $self->{userprefs_filename};
      $fname ||= $self->first_existing_path (@default_userprefs_path);

      if (!$self->{dont_copy_prefs}) {
        # bug 4932: if the userprefs path doesn't exist, we need to make it, so
        # just use the last entry in the array as the default path.
        $fname ||= $self->sed_path($default_userprefs_path[-1]);

	if (!-f $fname && !$self->create_default_prefs($fname)) {
          warn "config: failed to create default user preference file $fname\n";
        }
      }

      $self->{config_text} .= $self->read_cf($fname, 'user prefs file');
    }
  }

  $self->{config_text} .= $self->{post_config_text} if ($self->{post_config_text});

  if ($self->{config_text} !~ /\S/) {
    warn "config: no configuration text or files found! please check your setup\n";
  }

  # Go and parse the config!
  $self->{conf}->{main} = $self;
  $self->{conf}->parse_rules ($self->{config_text});
  $self->{conf}->finish_parsing(0);
  delete $self->{conf}->{main};	# to allow future GC'ing

  undef $self->{config_text};   # ensure it's actually freed
  delete $self->{config_text};

  # Initialize the Bayes subsystem
  if ($self->{conf}->{use_bayes}) {
      require Mail::SpamAssassin::Bayes;
      $self->{bayes_scanner} = new Mail::SpamAssassin::Bayes ($self);
  }
  $self->{'learn_to_journal'} = $self->{conf}->{bayes_learn_to_journal};

  # Figure out/set our initial scoreset
  my $set = 0;
  $set |= 1 unless $self->{local_tests_only};
  $set |= 2 if $self->{bayes_scanner} && $self->{bayes_scanner}->is_scan_available();
  $self->{conf}->set_score_set ($set);

  if ($self->{only_these_rules}) {
    $self->{conf}->trim_rules($self->{only_these_rules});
  }

  # TODO -- open DNS cache etc. if necessary
}

sub read_cf {
  my ($self, $allpaths, $desc) = @_;
  return $self->_read_cf_pre($allpaths,$desc,\&get_cf_files_in_dir);
}

sub read_pre {
  my ($self, $allpaths, $desc) = @_;
  return $self->_read_cf_pre($allpaths,$desc,\&get_pre_files_in_dir);
}

sub _read_cf_pre {
  my ($self, $allpaths, $desc, $filelistmethod) = @_;

  return '' unless defined ($allpaths);

  my $txt = '';
  foreach my $path (split("\000", $allpaths)) 
  {
    dbg("config: using \"$path\" for $desc");

    if (-d $path) {
      foreach my $file ($self->$filelistmethod($path)) {
        $txt .= read_cf_file($file);
      }

    } elsif (-f $path && -s _ && -r _) {
      $txt .= read_cf_file($path);
    }
  }

  return $txt;
}


sub read_cf_file {
  my($path) = @_;
  my $txt = '';

  if (open (IN, "<".$path)) {
    $txt = "file start $path\n";
    $txt .= join ('', <IN>);
    # add an extra \n in case file did not end in one.
    $txt .= "\nfile end $path\n";
    close IN;
    dbg("config: read file $path");
  }
  else {
    warn "config: cannot open \"$path\": $!\n";
  }

  return $txt;
}

sub get_and_create_userstate_dir {
  my ($self, $dir) = @_;

  my $fname;

  # If vpopmail is enabled then set fname to virtual homedir
  # precedence: dir, userstate_dir, derive from user_dir, system default
  if (defined $dir) {
    $fname = File::Spec->catdir ($dir, ".spamassassin");
  }
  elsif (defined $self->{userstate_dir}) {
    $fname = $self->{userstate_dir};
  }
  elsif (defined $self->{user_dir}) {
    $fname = File::Spec->catdir ($self->{user_dir}, ".spamassassin");
  }

  $fname ||= $self->first_existing_path (@default_userstate_dir);

  # bug 4932: use the last default_userstate_dir entry if none of the others
  # already exist
  $fname ||= $self->sed_path($default_userstate_dir[-1]);

  if (!$self->{dont_copy_prefs}) {
    dbg("config: using \"$fname\" for user state dir");
  }

  if (!-d $fname) {
    # not being able to create the *dir* is not worth a warning at all times
    eval { mkpath($fname, 0, 0700) } or dbg("config: mkdir $fname failed: $@ $!\n");
  }

  $fname;
}

=item $fullpath = $f->find_rule_support_file ($filename)

Find a rule-support file, such as C<languages> or C<triplets.txt>,
in the system-wide rules directory, and return its full path if
it exists, or undef if it doesn't exist.

(This API was added in SpamAssassin 3.1.1.)

=cut

sub find_rule_support_file {
  my ($self, $filename) = @_;

  # take a copy to avoid modifying the real one (stupid map { } side-effect)
  my @paths = @default_rules_path;
  return $self->first_existing_path (map {
      s/$/\/${filename}/;
      $_;
    } @paths);
}

=item $f->create_default_prefs ($filename, $username [ , $userdir ] )

Copy default preferences file into home directory for later use and
modification, if it does not already exist and C<dont_copy_prefs> is
not set.

=cut

sub create_default_prefs {
  # $userdir will only exist if vpopmail config is enabled thru spamd
  # Its value will be the virtual user's maildir
  #
  my ($self, $fname, $user, $userdir) = @_;

  if ($self->{dont_copy_prefs}) {
    return(0);
  }

#  if ($userdir && $userdir ne $self->{user_dir}) {
#    warn "config: hooray! user_dirs don't match! '$userdir' vs '$self->{user_dir}'\n";
#  }

  if (!-f $fname)
  {
    # Pass on the value of $userdir for virtual users in vpopmail
    # otherwise it is empty and the user's normal homedir is used
    $self->get_and_create_userstate_dir($userdir);

    # copy in the default one for later editing
    my $defprefs = $self->first_existing_path (@Mail::SpamAssassin::default_prefs_path);

    if (defined $defprefs && open (IN, "<$defprefs")) {
      $fname = Mail::SpamAssassin::Util::untaint_file_path($fname);
      if (open (OUT, ">$fname")) {
        while (<IN>) {
          /^\#\* / and next;
          print OUT;
        }
        close OUT;
        close IN;

        if (($< == 0) && ($> == 0) && defined($user)) { # chown it
          my ($uid,$gid) = (getpwnam($user))[2,3];
          unless (chown($uid, $gid, $fname)) {
            warn "config: couldn't chown $fname to $uid:$gid for $user: $!\n";
          }
        }
        warn "config: created user preferences file: $fname\n";
        return(1);
      }
      else {
        warn "config: cannot write to $fname: $!\n";
      }
    }
    elsif (defined $defprefs) {
      warn "config: cannot open $defprefs: $!\n";
    }
    else {
      warn "config: can not determine default prefs path\n";
    }
  }

  return(0);
}

###########################################################################

sub expand_name ($) {
  my ($self, $name) = @_;
  my $home = $self->{user_dir} || $ENV{HOME} || '';

  if (Mail::SpamAssassin::Util::am_running_on_windows()) {
    my $userprofile = $ENV{USERPROFILE} || '';

    return $userprofile if ($userprofile && $userprofile =~ m/^[a-z]\:[\/\\]/oi);
    return $userprofile if ($userprofile =~ m/^\\\\/o);

    return $home if ($home && $home =~ m/^[a-z]\:[\/\\]/oi);
    return $home if ($home =~ m/^\\\\/o);

    return '';
  } else {
    return $home if ($home && $home =~ /\//o);
    return (getpwnam($name))[7] if ($name ne '');
    return (getpwuid($>))[7];
  }
}

sub sed_path {
  my ($self, $path) = @_;
  return undef if (!defined $path);

  if (exists($self->{conf}->{sed_path_cache}->{$path})) {
    return $self->{conf}->{sed_path_cache}->{$path};
  }

  my $orig_path = $path;

  $path =~ s/__local_rules_dir__/$self->{LOCAL_RULES_DIR} || ''/ges;
  $path =~ s/__local_state_dir__/$self->{LOCAL_STATE_DIR} || ''/ges;
  $path =~ s/__def_rules_dir__/$self->{DEF_RULES_DIR} || ''/ges;
  $path =~ s{__prefix__}{$self->{PREFIX} || $Config{prefix} || '/usr'}ges;
  $path =~ s{__userstate__}{$self->get_and_create_userstate_dir() || ''}ges;
  $path =~ s{__perl_major_ver__}{$self->get_perl_major_version()}ges;
  $path =~ s/__version__/${VERSION}/gs;
  $path =~ s/^\~([^\/]*)/$self->expand_name($1)/es;

  $path = Mail::SpamAssassin::Util::untaint_file_path ($path);
  $self->{conf}->{sed_path_cache}->{$orig_path} = $path;
  return $path;
}

sub get_perl_major_version {
  my $self = shift;
  $] =~ /^(\d\.\d\d\d)/ or die "bad perl ver $]";
  return $1;
}

sub first_existing_path {
  my $self = shift;
  my $path;
  foreach my $p (@_) {
    $path = $self->sed_path ($p);
    if (defined $path) {
      my($errn) = stat($path) ? 0 : 0+$!;
      if    ($errn == ENOENT) { }  # does not exist
      elsif ($errn) { warn "config: path \"$path\" is inaccessible: $!\n" }
      else { return $path }
    }
  }
  return;
}

###########################################################################

sub get_cf_files_in_dir {
  my ($self, $dir) = @_;
  return $self->_get_cf_pre_files_in_dir($dir, 'cf');
}

sub get_pre_files_in_dir {
  my ($self, $dir) = @_;
  return $self->_get_cf_pre_files_in_dir($dir, 'pre');
}

sub _get_cf_pre_files_in_dir {
  my ($self, $dir, $type) = @_;

  if ($self->{config_tree_recurse}) {
    my @cfs = ();

    # use "eval" to avoid loading File::Find unless this is specified
    eval {
      use File::Find qw();
      File::Find::find(
        sub {
          return unless (/\.${type}$/i && -f $_);
          push @cfs, $File::Find::name;
        }, $dir);
    };
    return sort { $a cmp $b } @cfs;

    die "oops! $@";     # should never get here
  }
  else {
    opendir(SA_CF_DIR, $dir) or warn "config: cannot opendir $dir: $!\n";
    my @cfs = grep { /\.${type}$/i && -f "$dir/$_" } readdir(SA_CF_DIR);
    closedir SA_CF_DIR;

    return map { "$dir/$_" } sort { $a cmp $b } @cfs;
  }
}

###########################################################################

sub have_plugin {
  my ($self, $subname) = @_;

  # We could potentially get called after a finish(), so just return.
  return unless $self->{plugins};

  return $self->{plugins}->have_callback ($subname);
}

sub call_plugins {
  my $self = shift;

  # We could potentially get called after a finish(), so just return.
  return unless $self->{plugins};

  my $subname = shift;
  return $self->{plugins}->callback ($subname, @_);
}

###########################################################################

sub find_all_addrs_in_mail {
  my ($self, $mail_obj) = @_;

  $self->init(1);

  my @addrlist = ();
  foreach my $header (qw(To From Cc Reply-To Sender
  				Errors-To Mail-Followup-To))
  {
    my @hdrs = $mail_obj->get_header ($header);
    if ($#hdrs < 0) { next; }
    push (@addrlist, $self->find_all_addrs_in_line (join (" ", @hdrs)));
  }

  # find addrs in body, too
  foreach my $line (@{$mail_obj->get_body()}) {
    push (@addrlist, $self->find_all_addrs_in_line ($line));
  }

  my @ret = ();
  my %done = ();

  foreach $_ (@addrlist) {
    s/^mailto://;       # from Outlook "forwarded" message
    next if defined ($done{$_}); $done{$_} = 1;
    push (@ret, $_);
  }

  @ret;
}

sub find_all_addrs_in_line {
  my ($self, $line) = @_;

  # a more permissive pattern based on "dot-atom" as per RFC2822
  my $ID_PATTERN   = '[-a-z0-9_\+\:\=\!\#\$\%\&\*\^\?\{\}\|\~\/\.]+';
  my $HOST_PATTERN = '[-a-z0-9_\+\:\/]+';

  my @addrs = ();
  my %seen = ();
  while ($line =~ s/(?:mailto:)?\s*
	      ($ID_PATTERN \@
	      $HOST_PATTERN(?:\.$HOST_PATTERN)+)//oix) 
  {
    my $addr = $1;
    $addr =~ s/^mailto://;
    next if (defined ($seen{$addr})); $seen{$addr} = 1;
    push (@addrs, $addr);
  }

  return @addrs;
}

###########################################################################

# sa_die -- used to die with a useful exit code.

sub sa_die {
  my $exitcode = shift;
  warn @_;
  exit $exitcode;
}

###########################################################################

=item $f->copy_config ( [ $source ], [ $dest ] )

Used for daemons to keep a persistent Mail::SpamAssassin object's
configuration correct if switching between users.  Pass an associative
array reference as either $source or $dest, and set the other to 'undef'
so that the object will use its current configuration.  i.e.:

  # create object w/ configuration
  my $spamtest = Mail::SpamAssassin->new( ... );

  # backup configuration to %conf_backup
  my %conf_backup = ();
  $spamtest->copy_config(undef, \%conf_backup) ||
    die "config: error returned from copy_config!\n";

  ... do stuff, perhaps modify the config, etc ...

  # reset the configuration back to the original
  $spamtest->copy_config(\%conf_backup, undef) ||
    die "config: error returned from copy_config!\n";

Note that the contents of the associative arrays should be considered
opaque by calling code.

=cut

sub copy_config {
  my ($self, $source, $dest) = @_;

  # At least one of either source or dest needs to be a hash reference ...
  unless ((defined $source && ref($source) eq 'HASH') ||
          (defined $dest && ref($dest) eq 'HASH'))
  {
    return 0;
  }

  # let the Conf object itself do all the heavy lifting.  It's better
  # than having this class know all about that class' internals...
  if (defined $source) {
    dbg ("config: copying current conf from backup");
  }
  else {
    dbg ("config: copying current conf to backup");
  }
  return $self->{conf}->clone($source, $dest);
}

###########################################################################

=item @plugins = $f->get_loaded_plugins_list ( )

Return the list of plugins currently loaded by this SpamAssassin object's
configuration; each entry in the list is an object of type
C<Mail::SpamAssassin::Plugin>.

(This API was added in SpamAssassin 3.2.0.)

=cut

sub get_loaded_plugins_list {
  my ($self) = @_;
  return $self->{plugins}->get_loaded_plugins_list();
}


1;
__END__

###########################################################################

=back

=head1 PREREQUISITES

C<HTML::Parser>
C<Sys::Syslog>

=head1 MORE DOCUMENTATION

See also E<lt>http://spamassassin.apache.org/E<gt> and
E<lt>http://wiki.apache.org/spamassassin/E<gt> for more information.

=head1 SEE ALSO

Mail::SpamAssassin::Conf(3)
Mail::SpamAssassin::PerMsgStatus(3)
spamassassin(1)
sa-update(1)

=head1 BUGS

See E<lt>http://issues.apache.org/SpamAssassin/E<gt>

=head1 AUTHORS

The SpamAssassin(tm) Project E<lt>http://spamassassin.apache.org/E<gt>

=head1 COPYRIGHT

SpamAssassin is distributed under the Apache License, Version 2.0, as
described in the file C<LICENSE> included with the distribution.

=head1 AVAILABILITY

The latest version of this library is likely to be available from CPAN
as well as:

  E<lt>http://spamassassin.apache.org/E<gt>

=cut
