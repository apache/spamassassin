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
}

###########################################################################
# non-public methods.

sub is_razor_available {
  my ($self) = @_;

  if ($self->{main}->{local_tests_only}) {
    dbg ("local tests only, ignoring Razor");
    return 0;
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

  my @msg = split (/^/m, $fulltext);
  my $timeout = 10;             # seconds
  my $response;
  my $config = $self->{main}->{conf}->{razor_config};
  my %options = (
    'debug'     => $Mail::SpamAssassin::DEBUG
  );

  # razor also debugs to stdout. argh. fix it to stderr...
  if ($Mail::SpamAssassin::DEBUG) {
    open (OLDOUT, ">&STDOUT");
    open (STDOUT, ">&STDERR");
  }

  my $oldslash = $/;

  eval {
    require Razor::Client;
    require Razor::Agent;
    local ($^W) = 0;            # argh, warnings in Razor

    local $SIG{ALRM} = sub { die "alarm\n" };
    alarm 10;

    my $rc = Razor::Client->new ($config, %options);
    die "Problem while loading Razor: $!" if (!$rc);

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

  $/ = $oldslash;

  if ($Mail::SpamAssassin::DEBUG) {
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

  if (!open(DCCHDL, "dccproc -V 2>&1 |")) {
    close DCCHDL;
    dbg ("DCC is not available");
    return 0;
  } 
  else {
    close DCCHDL;
    dbg ("DCC is available");
    return 1;
  }
}

sub dcc_report {
  my ($self, $fulltext) = @_;
  my $timeout = 10;

  eval {
    use IPC::Open2;
    my ($dccin, $dccout, $pid);

    local $SIG{ALRM} = sub { die "alarm\n" };
    local $SIG{PIPE} = sub { die "brokenpipe\n" };

    alarm 10;

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
###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
