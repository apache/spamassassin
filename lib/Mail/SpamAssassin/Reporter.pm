# Mail::SpamAssassin::Reporter - report a message as spam

package Mail::SpamAssassin::Reporter;

use strict;
use bytes;
use Carp;

use vars qw{
  @ISA $VERSION
};

@ISA = qw();
$VERSION = 'bogus';	# avoid CPAN.pm picking up razor ver

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my ($main, $msg, $options) = @_;

  my $self = {
    'main'		=> $main,
    'msg'		=> $msg,
    'options'		=> $options,
  };

  $self->{conf} = $self->{main}->{conf};

  bless ($self, $class);
  $self;
}

###########################################################################

sub report {
  my ($self) = @_;
  my $return = 1;

  my $text = $self->{main}->remove_spamassassin_markup ($self->{msg});

  if (!$self->{options}->{dont_report_to_razor} && $self->is_razor_available()) {
    if ($self->razor_report($text)) {
      dbg ("SpamAssassin: spam reported to Razor.");
      $return = 0;
    }
  }
  if (!$self->{options}->{dont_report_to_dcc} && $self->is_dcc_available()) {
    if ($self->dcc_report($text)) {
      dbg ("SpamAssassin: spam reported to DCC.");
      $return = 0;
    }
  }
  if (!$self->{options}->{dont_report_to_pyzor} && $self->is_pyzor_available()) {
    if ($self->pyzor_report($text)) {
      dbg ("SpamAssassin: spam reported to Pyzor.");
      $return = 0;
    }
  }

  $self->delete_fulltext_tmpfile();

  return $return;
}

###########################################################################
# non-public methods.

# This is to reset the alarm before dieing - spamd can die of a stray alarm!

sub adie {
  my $msg = shift;
  alarm 0;
  die $msg;
}

sub razor_report {
  my ($self, $fulltext) = @_;
  my $timeout=$self->{conf}->{razor_timeout};
  my $response;

  # razor also debugs to stdout. argh. fix it to stderr...
  if ($Mail::SpamAssassin::DEBUG->{enabled}) {
    open (OLDOUT, ">&STDOUT");
    open (STDOUT, ">&STDERR");
  }

  Mail::SpamAssassin::PerMsgStatus::enter_helper_run_mode();

  # Use Razor2 if it's available
  eval { require Razor2::Client::Agent; };
  if ( !$@ ) {
    eval {
      local ($^W) = 0;    # argh, warnings in Razor
      local %ENV;

      local $SIG{ALRM} = sub { die "alarm\n" };
      alarm $timeout;

      my $rc =
        Razor2::Client::Agent->new('razor-report')
        ;                 # everything's in the module!

      if ($rc) {
        my %opt = (
          debug      => $Mail::SpamAssassin::DEBUG->{enabled},
          foreground => 1,
          config     => $self->{conf}->{razor_config}
        );
        $rc->{opt} = \%opt;
        $rc->do_conf() or adie($rc->errstr);

        # Razor2 requires authentication for reporting
        my $ident = $rc->get_ident
          or adie ("Razor2 reporting requires authentication");

	my @msg = (\$fulltext);
        my $objects = $rc->prepare_objects( \@msg )
          or adie ("error in prepare_objects");
        $rc->get_server_info() or adie $rc->errprefix("reportit");

	# let's reset the alarm since get_server_info() calls
	# nextserver() which calls discover() which very likely will
	# reset the alarm for us ... how polite.  :(  
	alarm $timeout;

        my $sigs = $rc->compute_sigs($objects)
          or adie ("error in compute_sigs");

        $rc->connect() or adie ($rc->errprefix("reportit"));
        $rc->authenticate($ident) or adie ($rc->errprefix("reportit"));
        $rc->report($objects)     or adie ($rc->errprefix("reportit"));
        $rc->disconnect() or adie ($rc->errprefix("reportit"));
        $response = 1; # Razor 2.14 says that if we get here, we did ok.
      }
      else {
        warn "undefined Razor2::Client::Agent\n";
      }

      alarm 0;
      dbg("Razor2: spam reported, response is \"$response\".");
    };

    alarm 0;

    if ($@) {
      if ( $@ =~ /alarm/ ) {
        dbg("razor2 report timed out after $timeout secs.");
      } elsif ($@ =~ /could not connect/) {
        dbg("razor2 report could not connect to any servers");
      } elsif ($@ =~ /timeout/i) {
        dbg("razor2 report timed out connecting to razor servers");
      } else {
        warn "razor2 report failed: $! $@";
      }
      undef $response;
    }
  }
  else {
    my @msg = split (/^/m, $fulltext);
    my $config = $self->{conf}->{razor_config};
    $config ||= $self->{main}->sed_path ("~/razor.conf");
    my %options = (
      'debug'     => $Mail::SpamAssassin::DEBUG->{enabled}
    );

    eval {
      require Razor::Client;
      require Razor::Agent;
      local ($^W) = 0;            # argh, warnings in Razor
  
      local $SIG{ALRM} = sub { die "alarm\n" };
      alarm $timeout;
  
      my $rc = Razor::Client->new ($config, %options);
      adie ("Problem while loading Razor: $!") if (!$rc);
  
      my $ver = $Razor::Client::VERSION;
      if ($ver >= 1.12) {
        my $respary = $rc->report ('spam' => \@msg);
        for my $resp (@$respary) { $response .= $resp; }
      } else {
        $response = $rc->report (\@msg);
      }
  
      alarm 0;
      dbg ("Razor: spam reported, response is \"$response\".");
    };
    
    if ($@) {
      if ($@ =~ /alarm/) {
        dbg ("razor report timed out after $timeout secs.");
      } else {
        warn "razor-report failed: $! $@";
      }
      undef $response;
    }
  }

  Mail::SpamAssassin::PerMsgStatus::leave_helper_run_mode();

  if ($Mail::SpamAssassin::DEBUG->{enabled}) {
    open (STDOUT, ">&OLDOUT");
    close OLDOUT;
  }

  if (defined($response) && $response+0) {
    return 1;
  } else {
    return 0;
  }
}

sub dcc_report {
  my ($self, $fulltext) = @_;
  my $timeout=$self->{conf}->{dcc_timeout};

  timelog("DCC -> Starting report ($timeout secs max)", "dcc", 1);
  Mail::SpamAssassin::PerMsgStatus::enter_helper_run_mode();

  # use a temp file here -- open2() is unreliable, buffering-wise,
  # under spamd. :(
  my $tmpf = $self->create_fulltext_tmpfile(\$fulltext);

  eval {
    local $SIG{ALRM} = sub { die "__alarm__\n" };
    local $SIG{PIPE} = sub { die "__brokenpipe__\n" };

    alarm $timeout;

    # Note: not really tainted, these both come from system conf file.
    my $path = Mail::SpamAssassin::Util::untaint_file_path ($self->{conf}->{dcc_path});
    $self->{conf}->{dcc_options} =~ /^([^\;\'\"\0]+)$/;
    my $opts = $1; $opts ||= '';

    my $pid = open(DCC, join(' ', $path, "-t many", $opts, "< '$tmpf'", ">/dev/null 2>&1", '|')) || die "$!\n";
    close(DCC) || die "Received error code $?";

    alarm(0);
    waitpid ($pid, 0);
  };

  alarm 0;
  Mail::SpamAssassin::PerMsgStatus::leave_helper_run_mode();
 
  if ($@) {
    if ($@ =~ /^__alarm__$/) {
      dbg ("DCC -> report timed out after $timeout secs.");
      timelog("DCC interrupted after $timeout secs", "dcc", 2);
   } elsif ($@ =~ /^__brokenpipe__$/) {
      dbg ("DCC -> report failed: Broken pipe.");
      timelog("DCC report failed, broken pipe", "dcc", 2);
    } else {
      warn ("DCC -> report failed: $@\n");
      timelog("DCC report failed", "dcc", 2);
    }
    return 0;
  }

  timelog("DCC -> report finished", "dcc", 2);
  return 1;
}

sub pyzor_report {
  my ($self, $fulltext) = @_;
  my $timeout=$self->{conf}->{pyzor_timeout};

  timelog("Pyzor -> Starting report ($timeout secs max)", "pyzor", 1);
  Mail::SpamAssassin::PerMsgStatus::enter_helper_run_mode();

  # use a temp file here -- open2() is unreliable, buffering-wise,
  # under spamd. :(
  my $tmpf = $self->create_fulltext_tmpfile(\$fulltext);

  eval {
    local $SIG{ALRM} = sub { die "__alarm__\n" };
    local $SIG{PIPE} = sub { die "__brokenpipe__\n" };

    alarm $timeout;

    # Note: not really tainted, this comes from system conf file.
    my $path = Mail::SpamAssassin::Util::untaint_file_path ($self->{conf}->{pyzor_path});
    $self->{conf}->{pyzor_options} =~ /^([^\;\'\"\0]+)$/;
    my $opts = $1; $opts ||= '';

    my $pid = open(PYZ, join(' ', $path, $opts, "report", "< '$tmpf'", ">/dev/null 2>&1", '|')) || die "$!\n";
    close(PYZ) || die "Received error code $?";

    alarm(0);
    waitpid ($pid, 0);
  };

  alarm 0;
  Mail::SpamAssassin::PerMsgStatus::leave_helper_run_mode();

  if ($@) {
    if ($@ =~ /^__alarm__$/) {
      dbg ("Pyzor -> report timed out after $timeout secs.");
      timelog("Pyzor interrupted after $timeout secs", "pyzor", 2);
    } elsif ($@ =~ /^__brokenpipe__$/) {
      dbg ("Pyzor -> report failed: Broken pipe.");
      timelog("Pyzor report failed, broken pipe", "pyzor", 2);
    } else {
      warn ("Pyzor -> report failed: $@\n");
      timelog("Pyzor report failed", "pyzor", 2);
    }
    return 0;
  }

  timelog("Pyzor -> report finished", "pyzor", 2);
  return 1;
}
###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }
sub timelog { Mail::SpamAssassin::timelog (@_); }
sub create_fulltext_tmpfile { Mail::SpamAssassin::PerMsgStatus::create_fulltext_tmpfile(@_) }
sub delete_fulltext_tmpfile { Mail::SpamAssassin::PerMsgStatus::delete_fulltext_tmpfile(@_) }

# Use the Dns versions ...  At least something only needs 1 copy of code ...
sub is_pyzor_available { Mail::SpamAssassin::PerMsgStatus::is_pyzor_available(@_); }
sub is_dcc_available { Mail::SpamAssassin::PerMsgStatus::is_dcc_available(@_); }
sub is_razor_available {
  Mail::SpamAssassin::PerMsgStatus::is_razor2_available(@_) ||
  Mail::SpamAssassin::PerMsgStatus::is_razor1_available(@_);
}


1;
