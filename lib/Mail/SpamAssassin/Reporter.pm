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
  my $timeout=$self->{main}->{conf}->{razor_timeout};
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
        $response = 1; # razor 2.14 says that if we get here, we did ok.
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

  if ($self->{main}->{local_tests_only}) {
    dbg ("local tests only, ignoring DCC");
    return 0;
  }

  my $dccproc = $self->{main}->{conf}->{dcc_path} || '';
  unless ($dccproc) {
    foreach my $path (File::Spec->path()) {
      $dccproc = File::Spec->catfile ($path, 'dccproc');
      if (-x $dccproc) {
        dbg ("DCC was found at $dccproc");
        $self->{main}->{conf}->{dcc_path} = $dccproc;
        last;
      }
    }
  }
  unless (-x $dccproc) {
    dbg ("DCC is not available: dccproc not found");
    return 0;
  }

  dbg ("DCC is available: ".$self->{main}->{conf}->{dcc_path});
  return 1;
}

sub dcc_report {
  my ($self, $fulltext) = @_;
  my $timeout=$self->{main}->{conf}->{dcc_timeout};

  eval {
    local $SIG{ALRM} = sub { die "alarm\n" };
    local $SIG{PIPE} = sub { die "brokenpipe\n" };

    alarm $timeout;

    my $cmd = join(" ", $self->{main}->{conf}->{dcc_path},'-t many',$self->{main}->{conf}->{dcc_options});
    open(DCC, "| $cmd > /dev/null 2>&1") || die "Couldn't fork \"$cmd\"";
    print DCC $fulltext;
    close(DCC) || die "Received error code $? from \"$cmd\"";

    alarm(0);
  };

  alarm 0;

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

  if ($self->{main}->{local_tests_only}) {
    dbg ("local tests only, ignoring Pyzor");
    return 0;
  }

  my $pyzor = $self->{main}->{conf}->{pyzor_path} || '';
  unless ($pyzor) {
    foreach my $path (File::Spec->path()) {
      $pyzor = File::Spec->catfile ($path, 'pyzor');
      if (-x $pyzor) {
        dbg ("Pyzor was found at $pyzor");
        $self->{main}->{conf}->{pyzor_path} = $pyzor;
        last;
      }
    }
  }
  unless (-x $pyzor) {
    dbg ("Pyzor is not available: pyzor not found");
    return 0;
  }
  
  dbg ("Pyzor is available: ".$self->{main}->{conf}->{pyzor_path});
  return 1;
}

sub pyzor_report {
  my ($self, $fulltext) = @_;
  my $timeout=$self->{main}->{conf}->{pyzor_timeout};

  eval {
    local $SIG{ALRM} = sub { die "alarm\n" };
    local $SIG{PIPE} = sub { die "brokenpipe\n" };

    alarm $timeout;

    my $cmd = join(" ", $self->{main}->{conf}->{pyzor_path},'report');
    open(PYZ, "| $cmd > /dev/null 2>&1") || die "Couldn't fork \"$cmd\"";
    print PYZ $fulltext;
    close(PYZ) || die "Received error code $? from \"$cmd\"";

    alarm(0);
  };

  alarm 0;

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
