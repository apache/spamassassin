# Mail::SpamAssassin::Reporter - report a message as spam

package Mail::SpamAssassin::Reporter;

use Carp;
use strict;

use vars	qw{
  	@ISA
};

@ISA = qw();

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
	&& $self->is_razor_available())
  {
    if ($self->razor_report($text)) {
      dbg ("SpamAssassin: spam reported to Razor.");
    }
  }
}

###########################################################################
# non-public methods.

sub is_razor_available {
  my ($self) = @_;
  
  eval {
    require Razor::Signature; 
    require Razor::Client;
  };
  if ($@) {
    dbg ( "Razor is not available" );
    return;
  }

  dbg ("Razor is available");
  return 1;
}

sub razor_report {
  my ($self, $fulltext) = @_;

  my @msg = split (/^/m, $fulltext);
  my $config = $self->{main}->{conf}->{razor_config};
  my %options = (
    # 'debug'	=> 1
  );
  my $response;

  eval q{
    use Razor::Client;
    use Razor::Signature; 
    my $client = new Razor::Client ($config, %options);
    $response = $client->report ([@msg]);
    dbg ("Razor: spam reported, response is \"$response\".");
  1;} or warn "razor-report failed: $! $@";

  if ($response) { return 1; }
  return 0;
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
