# Mail::SpamAssassin::Reporter - report a message as spam

package Mail::SpamAssassin::Reporter;

use Carp;
use strict;

use vars	qw{
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

  bless ($self, $class);
  $self;
}

###########################################################################

sub report {
  my ($self) = @_;

  my $text = $self->{main}->remove_spamassassin_markup ($self->{msg});

  if (!$self->{main}->{local_tests_only}
  	&& !$self->{options}->{dont_report_to_razor}
    && !$self->{main}->{stop_at_threshold}
	&& $self->is_razor_available())
  {
    if ($self->razor_report($text)) {
      dbg ("SpamAssassin: spam reported to Razor.");
    }
  }
  if (!$self->{main}->{local_tests_only}
  	&& !$self->{options}->{dont_report_to_dcc}
    && !$self->{main}->{stop_at_threshold}
	&& $self->is_dcc_available())
  {
    if ($self->dcc_report($text)) {
      dbg ("SpamAssassin: spam reported to DCC.");
    }
  }
  if (!$self->{main}->{local_tests_only}
  	&& !$self->{options}->{dont_report_to_pyzor}
    && !$self->{main}->{stop_at_threshold}
	&& $self->is_pyzor_available())
  {
    if ($self->pyzor_report($text)) {
      dbg ("SpamAssassin: spam reported to Pyzor.");
    }
  }

}

###########################################################################
# non-public methods.

# This is to reset the alarm before dieing - spamd can die of a stray alarm!

sub adie {
  my $msg = shift;
  alarm 0;
  die $msg;
}

sub is_razor_available {
  my ($self) = @_;

  if ($self->{main}->{local_tests_only}) {
    dbg ("local tests only, ignoring Razor");
    return 0;
  }
  
  # Use Razor2 if it's available, Razor1 otherwise
  eval { require Razor2::Client::Agent; };
  if ($@) {
    dbg("Razor2 is not available");
  }
  else {
    dbg("Razor2 is available");
    return 1;
  }

  eval {
    require Razor::Client;
  };

  if ($@) {
    dbg ( "Razor is not available" );
    return 0;
  } else {
    dbg ("Razor is available");
    return 1;
  }
}

sub razor_report {
  my ($self, $fulltext) = @_;

  my $timeout = 10;             # seconds
  my $response;

  # razor also debugs to stdout. argh. fix it to stderr...
  if ($Mail::SpamAssassin::DEBUG->{enabled}) {
    open (OLDOUT, ">&STDOUT");
    open (STDOUT, ">&STDERR");
  }

  my $oldslash = $/;

  # Use Razor2 if it's available
  eval { require Razor2::Client::Agent; };
  if ( !$@ ) {
    eval {
      local ($^W) = 0;    # argh, warnings in Razor

      local $SIG{ALRM} = sub { die "alarm\n" };
      alarm $timeout;

      my $rc =
        Razor2::Client::Agent->new('razor-report')
        ;                 # everything's in the module!

      if ($rc) {
        my %opt = (
          debug      => $Mail::SpamAssassin::DEBUG->{enabled},
          foreground => 1,
          config     => $self->{main}->{conf}->{razor_config}
        );
        $rc->{opt} = \%opt;
        $rc->do_conf() or adie($rc->errstr);

        # Razor2 requires authentication for reporting
        my $ident = $rc->get_ident
          or adie ("Razor2 reporting requires authentication");

        my @msg     = ( \$fulltext );
        my $objects = $rc->prepare_objects( \@msg )
          or adie ("error in prepare_objects");
        $rc->get_server_info() or adie $rc->errprefix("reportit");
        my $sigs = $rc->compute_sigs($objects)
          or adie ("error in compute_sigs");

        $rc->connect() or adie ($rc->errprefix("reportit"));
        $rc->authenticate($ident) or adie ($rc->errprefix("reportit"));
        $rc->report($objects)     or adie ($rc->errprefix("reportit"));
        $rc->disconnect() or adie ($rc->errprefix("reportit"));
        $response = $objects->[0]->{resp}->[0]->{res};
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
      }
      else {
        warn "razor2 report failed: $! $@";
      }
      undef $response;
      }
  }
  else {
    my @msg = split (/^/m, $fulltext);
    my $config = $self->{main}->{conf}->{razor_config};
    $config ||= $self->{main}->sed_path ("~/razor.conf");
    my %options = (
      'debug'     => $Mail::SpamAssassin::DEBUG->{enabled}
    );

    eval {
      require Razor::Client;
      require Razor::Agent;
      local ($^W) = 0;            # argh, warnings in Razor
  
      local $SIG{ALRM} = sub { die "alarm\n" };
      alarm 10;
  
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

  $/ = $oldslash;

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

sub is_dcc_available {
  my ($self) = @_;
  my (@resp);

  if ($self->{main}->{local_tests_only}) {
    dbg ("local tests only, ignoring DCC");
    return 0;
  }

  if (!open(DCCHDL, "dccproc -V 2>&1 |")) {
    dbg ("DCC is not available");
    return 0;
  } 
  else {
    @resp = <DCCHDL>;
    close DCCHDL;
    dbg ("DCC is available: ".join(" ", @resp));
    return 1;
  }
}

use Symbol qw(gensym);

sub dcc_report {
  my ($self, $fulltext) = @_;

  eval {
    use IPC::Open2;
    my ($dccin, $dccout, $pid);

    local $SIG{ALRM} = sub { die "alarm\n" };
    local $SIG{PIPE} = sub { die "brokenpipe\n" };

    alarm 10;

    $dccin  = gensym();
    $dccout = gensym();

    $pid = open2($dccout, $dccin, 'dccproc -t many '.$self->{main}->{conf}->{dcc_options}.' >/dev/null 2>&1');

    print $dccin $fulltext;

    close ($dccin);

    waitpid ($pid, 0);

    alarm(0);
  };

  if ($@) {
    if ($@ =~ /alarm/) {
      dbg ("DCC report timed out after 10 secs.");
      return 0;
    } elsif ($@ =~ /brokenpipe/) {
      dbg ("DCC report failed - Broken pipe.");
      return 0;
    } else {
      warn ("DCC report skipped: $! $@");
      return 0;
    }
  }
  return 1;
}

sub is_pyzor_available {
  my ($self) = @_;
  my (@resp);

  if ($self->{main}->{local_tests_only}) {
    dbg ("local tests only, ignoring Pyzor");
    return 0;
  }

  if (!open(PyzorHDL, "pyzor ping 2>&1 |")) {
    dbg ("Pyzor is not available");
    return 0;
  } 
  else {
    @resp = <PyzorHDL>;
    close PyzorHDL;
    dbg ("Pyzor is available: ".join(" ", @resp));
    return 1;
  }
}

use Symbol qw(gensym);

sub pyzor_report {
  my ($self, $fulltext) = @_;

  eval {
    use IPC::Open2;
    my ($pyzorin, $pyzorout, $pid);

    local $SIG{ALRM} = sub { die "alarm\n" };
    local $SIG{PIPE} = sub { die "brokenpipe\n" };

    alarm 10;

    $pyzorin  = gensym();
    $pyzorout = gensym();

    $pid = open2($pyzorout, $pyzorin, 'pyzor report >/dev/null 2>&1');

    print $pyzorin $fulltext;

    close ($pyzorin);

    waitpid ($pid, 0);

    alarm(0);
  };

  if ($@) {
    if ($@ =~ /alarm/) {
      dbg ("Pyzor report timed out after 10 secs.");
      return 0;
    } elsif ($@ =~ /brokenpipe/) {
      dbg ("Pyzor report failed - Broken pipe.");
      return 0;
    } else {
      warn ("Pyzor report skipped: $! $@");
      return 0;
    }
  }
  return 1;
}
###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
