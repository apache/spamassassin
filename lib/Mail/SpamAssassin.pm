=head1 NAME

Mail::SpamAssassin - Mail::Audit spam detector plugin

=head1 SYNOPSIS

  my $mail = Mail::SpamAssassin::MyMailAudit->new();

  my $spamtest = Mail::SpamAssassin->new();
  my $status = $spamtest->check ($mail);

  if ($status->is_spam ()) {
    $status->rewrite_mail ();
    $mail->accept("spamfolder");

  } else {
    $mail->accept();		# to default incoming mailbox
  }
  ...


=head1 DESCRIPTION

Mail::SpamAssassin is a Mail::Audit plugin to identify spam using text
analysis and several internet-based realtime blacklists.

Using its rule base, it uses a wide range of heuristic tests on mail headers
and body text to identify "spam", also known as unsolicited commercial email.

Once identified, the mail can then be optionally tagged as spam for later
filtering using the user's own mail user-agent application.

This module implements a Mail::Audit plugin, allowing SpamAssassin to be used
in a Mail::Audit filter.  If you wish to use a command-line filter tool,
try the C<spamassassin> or C<spamd> tools provided.

SpamAssassin also includes support for reporting spam messages to collaborative
filtering databases, such as Vipul's Razor ( http://razor.sourceforge.net/ ).

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin;

use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::ConfSourceSQL;
use Mail::SpamAssassin::PerMsgStatus;
use Mail::SpamAssassin::Reporter;
use Mail::SpamAssassin::Replier;
use Mail::SpamAssassin::MyMailAudit;

use File::Basename;
use File::Path;
use File::Spec;
use File::Copy;
use Cwd;
use Config;

use vars	qw{
  	@ISA $VERSION $HOME_URL $DEBUG
	@default_rules_path @default_prefs_path
	@default_userprefs_path @default_userstate_dir
	@site_rules_path
};

@ISA = qw();

$VERSION = "1.6";
sub Version { $VERSION; }

$HOME_URL = "http://spamassassin.taint.org/";

$DEBUG = 0;

@default_rules_path = qw(
        __installsitelib__/spamassassin.cf
	__installvendorlib__/spamassassin.cf
);

@site_rules_path = qw(
        /etc/spamassassin.cf
        /etc/mail/spamassassin.cf
        /usr/local/etc/spamassassin.cf
  	./spamassassin.cf
  	../spamassassin.cf
);
    
@default_prefs_path = qw(
        /etc/spamassassin.prefs
        __installsitelib__/spamassassin.prefs
	__installvendorlib__/spamassassin.prefs
);

@default_userprefs_path = qw(
        ~/.spamassassin.cf
);

@default_userstate_dir = qw(
        ~/.spamassassin
);

###########################################################################

=item $f = new Mail::SpamAssassin( [ { opt => val, ... } ] )

Constructs a new C<Mail::SpamAssassin> object.  You may pass the
following attribute-value pairs to the constructor.

=over 4

=item rules_filename

The filename to load spam-identifying rules from. (optional)

=item userprefs_filename

The filename to load preferences from. (optional)

=item userstate_dir

The directory user state is stored in. (optional)

=item config_text

The text of all rules and preferences.  If you prefer not to load the rules
from files, read them in yourself and set this instead.  As a result, this will
override the settings for C<rules_filename> and C<userprefs_filename>.

=item local_tests_only

If set to 1, no tests that require internet access will be performed. (default:
0)

=item dont_copy_prefs

If set to 1, the user preferences file will not be created if it doesn't
already exist. (default: 0)

=back

If none of C<rules_filename>, C<userprefs_filename>, or C<config_text> is set,
the C<Mail::SpamAssassin> module will search for the configuration files in the
usual installed locations.

=cut

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = shift;
  if (!defined $self) { $self = { }; }
  bless ($self, $class);

  if (defined $self->{debug}) { $DEBUG = $self->{debug}+0; }

  $self->{conf} = new Mail::SpamAssassin::Conf ($self);
  $self;
}

###########################################################################

=item $status = $f->check ($mail)

Check a mail, encapsulated in a C<Mail::Audit> object, to determine if
it is spam or not.

Returns a C<Mail::SpamAssassin::PerMsgStatus> object which can be
used to test or manipulate the mail message.

Note that the C<Mail::SpamAssassin> object can be re-used for further messages
without affecting this check; in OO terminology, the C<Mail::SpamAssassin>
object is a "factory".   However, if you do this, be sure to call the
C<finish()> method on the status objects when you're done with them.

=cut

sub check {
  my ($self, $mail_obj) = @_;
  local ($_);

  $self->init(1);
  my $mail = $self->encapsulate_mail_object ($mail_obj);
  my $msg = Mail::SpamAssassin::PerMsgStatus->new($self, $mail);
  $msg->check();
  $msg;
}

###########################################################################

=item $status = $f->check_message_text ($mailtext)

Check a mail, encapsulated in a plain string, to determine if it is spam or
not.

Otherwise identical to C<$f->check()> above.

=cut

sub check_message_text {
  my ($self, $mailtext) = @_;
  my @lines = split (/\n/s, $mailtext);
  my $mail_obj = Mail::SpamAssassin::MyMailAudit->new ('data' => \@lines);
  return $self->check ($mail_obj);
}

###########################################################################

=item $f->report_as_spam ($mail, $options)

Report a mail, encapsulated in a C<Mail::Audit> object, as human-verified spam.
This will submit the mail message to live, collaborative, spam-blocker
databases, allowing other users to block this message.

Options is an optional reference to a hash of options.  Currently these
can be:

=over 4

=item dont_report_to_razor

Inhibits reporting of the spam to Razor; useful if you know it's already
been listed there.

=back

=cut

sub report_as_spam {
  my ($self, $mail_obj, $options) = @_;
  local ($_);

  $self->init(1);
  my $mail = $self->encapsulate_mail_object ($mail_obj);
  my $msg = Mail::SpamAssassin::Reporter->new($self, $mail, $options);
  $msg->report ();
}

###########################################################################

=item $f->add_all_header_address_to_whitelist ($mail)

Given a mail message, find as many addresses in the usual headers (To,
Cc, From etc.) and add them to the automatic whitelist database.

=cut

sub add_all_header_address_to_whitelist {
  my ($self, $mail_obj) = @_;

  $self->init(1);
  my $mail = $self->encapsulate_mail_object ($mail_obj);
  my $list = Mail::SpamAssassin::AutoWhitelist->new($self);

  my $addrlist = ' ';
  foreach my $header (qw(To From Cc Reply-To Sender
  				Errors-To Mail-Followup-To))
  {
    my @hdrs = $mail->get_header ($header);
    if ($#hdrs < 0) { next; }
    $addrlist .= join (" ", @hdrs);
  }

  $addrlist =~ s/[\r\n]+/ , /gs;
  $addrlist =~ s/\s\"[^\"]+\"\s/ , /gs;	# remove names
  $addrlist =~ s/\([^\)]+\)/ , /gs;	# same

  %done = ();
  foreach $_ (split (/\s*,\s*/, $addrlist)) {
    next if ($_ !~ /\S/);

    s/^.*?<(.+)>\s*$/$1/g               # Foo Blah <jm@foo>
        or s/^(.+)\s\(.*?\)\s*$/$1/g;   # jm@foo (Foo Blah)

    if (!/^\S+\@\S+$/) { dbg ("wierd address, ignored: $_"); next; }

    next if defined ($done{$_});
    $done{$_} = 1;

    if ($list->add_known_good_address ($_)) {
      print "SpamAssassin auto-whitelist: adding address: $_\n";
    }
  }

  $list->finish();
}

###########################################################################

=item $f->reply_with_warning ($mail, $replysender)

Reply to the sender of a mail, encapsulated in a C<Mail::Audit> object,
explaining that their message has been added to spam-tracking databases
and deleted.  To be used in conjunction with C<report_as_spam>.  The
C<$replysender> argument should contain an email address to use as the
sender of the reply message.

=cut

sub reply_with_warning {
  my ($self, $mail_obj, $replysender) = @_;
  local ($_);

  $self->init(1);
  my $mail = $self->encapsulate_mail_object ($mail_obj);
  my $msg = new Mail::SpamAssassin::Replier ($self, $mail);
  $msg->reply ($replysender);
}

###########################################################################

=item $text = $f->remove_spamassassin_markup ($mail)

Returns the text of the message, with any SpamAssassin-added text (such
as the report, or X-Spam-Status headers) stripped.

=cut

sub remove_spamassassin_markup {
  my ($self, $mail_obj) = @_;
  local ($_);

  $self->init(1);
  my $mail = $self->encapsulate_mail_object ($mail_obj);
  my $hdrs = $mail->get_all_headers();

  # remove DOS line endings
  $hdrs =~ s/\r//gs;

  # de-break lines on SpamAssassin-modified headers.
  1 while $hdrs =~ s/(\n(?:X-Spam|Subject)[^\n]+?)\n[ \t]+/$1 /gs;

  # reinstate the old content type
  if ($hdrs =~ /^X-Spam-Prev-Content-Type: /m) {
    $hdrs =~ s/\nContent-Type: [^\n]*?\n/\n/gs;
    $hdrs =~ s/\nX-Spam-Prev-(Content-Type: [^\n]*\n)/\n$1/gs;

    # remove embedded spaces where they shouldn't be; a common problem
    $hdrs =~ s/(Content-Type: .*?boundary=\".*?) (.*?\".*?\n)/$1$2/gs;
  }

  # remove the headers we added
  1 while $hdrs =~ s/\nX-Spam-[^\n]*?\n/\n/gs;
  1 while $hdrs =~ s/^Subject: \*+SPAM\*+ /Subject: /gm;

  # ok, next, the report.
  # This is a little tricky since we can have either 0, 1 or 2 reports;
  # 0 for the non-spam case, 1 for normal filtering, and 2 for -t (where
  # an extra report is appended at the end of the mail).

  my @newbody = ();
  my $inreport = 0;
  foreach $_ (@{$mail->get_body()})
  {
    s/\r?$//;	# DOS line endings

    if (/^SPAM: ----/ && $inreport == 0) {
      # we've just entered a report.  If there's a blank line before the
      # report, get rid of it...
      if ($#newbody > 0 && $newbody[$#newbody-1] =~ /^$/) {
	pop (@newbody);
      }
      # and skip on to the next line...
      $inreport = 1; next;
    }

    if ($inreport && /^$/) {
      # blank line at end of report; skip it.  Also note that we're
      # now out of the report.
      $inreport = 0; next;
    }

    # finally, if we're not in the report, add it to the body array
    if (!$inreport) {
      push (@newbody, $_);
    }
  }

  return $hdrs."\n".join ('', @newbody);
}

###########################################################################

=item $f->read_scoreonly_config ($filename)

Read a configuration file and parse only scores from it.  This is used
to safely allow multi-user daemons to read per-user config files
without having to use C<setuid()>.

=cut

sub read_scoreonly_config {
  my ($self, $filename) = @_;

  if (!open(IN,"<$filename")) {
    warn "read_scoreonly_config: cannot open \"$filename\"\n";
    return;
  }
  my $text = join ('',<IN>);
  close IN;

  $self->{conf}->parse_scores_only ($text);
}

###########################################################################

=item $f->load_scoreonly_sql ($username)

Read configuration paramaters from SQL database and parse scores from it.  This
will only take effect if the perl C<DBI> module is installed, and the
configuration parameters C<user_scores_dsn>, C<user_scores_sql_username>, and
C<user_scores_sql_password> are set correctly.

=cut

sub load_scoreonly_sql {
  my ($self, $username) = @_;

  my $src = Mail::SpamAssassin::ConfSourceSQL->new ($self);
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

=item $f->compile_now ()

Compile all patterns, load all configuration files, and load all
possibly-required Perl modules.

Normally, Mail::SpamAssassin uses lazy evaluation where possible, but if you
plan to fork() or start a new perl interpreter thread to process a message,
this is suboptimal, as each process/thread will have to perform these actions.

Call this function in the master thread or process to perform the actions
straightaway, so that the sub-processes will not have to.

Note that this will initialise the SpamAssassin configuration without reading
the per-user configuration file; it assumes that you will call
C<read_scoreonly_config> at a later point.

=cut

sub compile_now {
  my ($self) = @_;

  # note: this may incur network access. Good.  We want to make sure
  # as much as possible is preloaded!
  my @testmsg = ("From: ignore\@compiling.spamassassin.taint.org\n",
  			"\n", "x\n");

  dbg ("ignore: test message to precompile patterns and load modules");
  $self->init(0);
  my $mail = Mail::SpamAssassin::MyMailAudit->new(data => \@testmsg);
  $self->check($mail)->finish();

  # load SQL modules now as well
  my $dsn = $self->{conf}->{user_scores_dsn};
  if ($dsn ne '') {
    Mail::SpamAssassin::ConfSourceSQL::load_modules();
  }

  1;
}

###########################################################################
# non-public methods.

sub init {
  my ($self, $use_user_pref) = @_;

  if ($self->{_initted}) { return; }
  $self->{_initted} = 1;

  #fix spamd reading root prefs file
  unless (defined $use_user_pref) {
    $use_user_pref = 1;
  }

  if (!defined $self->{config_text}) {
    $self->{config_text} = '';

    my $fname = $self->first_existing_path (@default_rules_path);
    $self->{config_text} .= $self->read_cf ($fname, 'default rules file');

    $fname = $self->{rules_filename};
    $fname ||= $self->first_existing_path (@site_rules_path);
    $self->{config_text} .= $self->read_cf ($fname, 'site rules file');

    if ( $use_user_pref != 0 ) {

      # user state directory
      $fname = $self->{userstate_dir};
      $fname ||= $self->first_existing_path (@default_userstate_dir);

      if (defined $fname && !$self->{dont_copy_prefs}) {
	dbg ("using \"$fname\" for user state dir");

	if (!-d $fname) {
	  mkpath ($fname, 0, 0700) or warn "mkdir $fname failed\n";
	}
      }

      # user prefs file
      $fname = $self->{userprefs_filename};
      $fname ||= $self->first_existing_path (@default_userprefs_path);

      if (defined $fname) {
        if (!-f $fname && !$self->create_default_prefs($fname)) {
          warn "Failed to create default prefs file $fname\n";
        }
      }

      $self->{config_text} .= $self->read_cf ($fname, 'user prefs file');
    }
  }

  if ($self->{config_text} !~ /\S/) {
    warn "No configuration text or files found! Please check your setup.\n";
  }

  $self->{conf}->parse_rules ($self->{config_text});
  $self->{conf}->finish_parsing ();

  delete $self->{config_text};

  # TODO -- open DNS cache etc. if necessary
}

sub read_cf {
  my ($self, $fname, $desc) = @_;

  return '' unless defined ($fname);

  dbg ("using \"$fname\" for $desc");
  my $txt = '';
  if (-f $fname && -s _) {
    open (IN, "<".$fname) or warn "cannot open \"$fname\"\n";
    $txt = join ('', <IN>);
    close IN;
  }
  return $txt;
}

=item $f->create_default_prefs ()

Copy default prefs file into home directory for later use and modification.

=cut

sub create_default_prefs {
  my ($self,$fname,$user) = @_;

  if (!$self->{dont_copy_prefs} && !-f $fname)
  {
    # copy in the default one for later editing
    my $defprefs = $self->first_existing_path
			(@Mail::SpamAssassin::default_prefs_path);
    
    open (IN, "<$defprefs") or warn "cannot open $defprefs";
    open (OUT, ">$fname") or warn "cannot write to $fname";
    while (<IN>) {
      /^\#\* / and next;
      print OUT;
    }
    close OUT;
    close IN;

    if (copy ($defprefs, $fname)) {
      if ( $< == 0 && $> == 0 && defined $user) {
	# chown it
	my ($uid,$gid) = (getpwnam($user))[2,3];
	unless (chown $uid, $gid, $fname) {
	   warn "Couldn't chown $fname to $uid:$gid for $user\n";
	}
      }
     warn "Created user preferences file: $fname\n";
     return(1);

   } else {
     warn "Failed to create user preferences file\n".
			 "\"$fname\" from default \"$defprefs\".\n";
   }
 }

 return(0);
}

###########################################################################

sub expand_name ($) {
  my $self = shift;
  my $name = shift;
  return (getpwnam($name))[7] if ($name ne '');
  return (getpwuid($>))[7];
}

sub sed_path {
  my $self = shift;
  my $path = shift;
  return undef if (!defined $path);
  $path =~ s/__installsitelib__/$Config{installsitelib}/gs;
  $path =~ s/__installvendorlib__/$Config{installvendorlib}/gs;
  $path =~ s/^\~([^\/]*)/$self->expand_name($1)/es;
  $path;
}

sub first_existing_path {
  my $self = shift;
  my $path;
  foreach my $p (@_) {
    $path = $self->sed_path ($p);
    if (-e $path) { return $path; }
  }
  $path;
}

###########################################################################

sub encapsulate_mail_object {
  my ($self, $mail_obj) = @_;

  # first, check to see if this is not actually a Mail::Audit object;
  # it could also be an already-encapsulated Mail::Audit wrapped inside
  # a Mail::SpamAssassin::Message.
  if ($mail_obj->{is_spamassassin_wrapper_object}) {
    return $mail_obj;
  }
  
  if ($self->{use_my_mail_class}) {
    my $class = $self->{use_my_mail_class};
    (my $file = $class) =~ s/::/\//g;
    require "$file.pm";
    return $class->new($mail_obj);
  }

  if (!defined $self->{mail_audit_supports_encapsulation}) {
    # test Mail::Audit for new-style encapsulation of the Mail::Internet
    # message object.
    my ($hdr, $val);
    foreach my $hdrtest (qw(From To Subject Message-Id Date Sender)) {
      $val = $mail_obj->get ($hdrtest);
      if (defined $val) { $hdr = $hdrtest; last; }
    }

    if (!defined $val) {                  # ah, just make one up
      $hdr = 'X-SpamAssassin-Test-Header'; $val = 'x';
    }

    # now try using one of the new methods...
    eval { $mail_obj->replace_header ($hdr, $val); };

    if ($@)
    {
      dbg ("using Mail::Audit exposed-message-object code");
      $self->{mail_audit_supports_encapsulation} = 0;
    } else {
      dbg ("using Mail::Audit message-encapsulation code");
      $self->{mail_audit_supports_encapsulation} = 1;
    }
  }

  if ($self->{mail_audit_supports_encapsulation}) {
    require Mail::SpamAssassin::EncappedMessage;
    # warning: Changed indirect object syntax here because of new() function 
    # above which may bite us in the foot some time. See Damian Conway's book for details
    return Mail::SpamAssassin::EncappedMessage->new($mail_obj);

  } else {
    require Mail::SpamAssassin::ExposedMessage;
    return Mail::SpamAssassin::ExposedMessage->new($mail_obj);
  }
}

sub dbg {
  if ($Mail::SpamAssassin::DEBUG > 0) { warn "debug: ".join('',@_)."\n"; }
}

# sa_die -- used to die with a useful exit code.

sub sa_die {
  my $exitcode = shift;
  warn @_;
  exit $exitcode;
}

1;
__END__

###########################################################################

=back

=head1 PREREQUISITES

C<Mail::Audit>
C<Mail::Internet>

=head1 COREQUISITES

C<Net::DNS>

=head1 MORE DOCUMENTATION

See also http://spamassassin.taint.org/ for more information.

=head1 SEE ALSO

C<Mail::SpamAssassin::PerMsgStatus>
C<spamassassin>

=head1 AUTHOR

Justin Mason E<lt>jm /at/ jmason.orgE<gt>

=head1 COPYRIGHT

SpamAssassin is distributed under Perl's Artistic license.

=head1 AVAILABILITY

The latest version of this library is likely to be available from CPAN
as well as:

  http://spamassassin.taint.org/

=cut


