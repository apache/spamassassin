=head1 NAME

Mail::SpamAssassin::Reporter - report a message as spam

=cut

package Mail::SpamAssassin::Reporter;

use Carp;
use strict;

use Mail::SpamAssassin::ExposedMessage;
use Mail::SpamAssassin::EncappedMessage;
use Mail::Audit;

use vars	qw{
  	@ISA
};

@ISA = qw();

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my ($main, $msg) = @_;

  my $self = {
    'main'		=> $main,
    'msg'		=> $msg,
  };

  $self->{conf} = $self->{main}->{conf};

  bless ($self, $class);
  $self;
}

###########################################################################

sub report {
  my ($self) = @_;

  my $hdrs = $self->{msg}->get_all_headers();
  $hdrs =~ s/^X-Spam-.*?$//gm;
  $hdrs =~ s/^Subject: \*+SPAM\*+/Subject: /gm;

  my $body = join ('', @{$self->{msg}->get_body()});
  $body =~ s/^SPAM: .*?$//gm;

  $self->{msgtext} = $hdrs."\n".$body;

  if ($self->is_razor_available()) {
    $self->razor_report($self->{msgtext});
  }
}

###########################################################################
# non-public methods.

sub is_razor_available {
  my ($self) = @_;
  my $razor_avail = 0;

  eval '
    use Razor::Signature; 
    use Razor::String;
    $razor_avail = 1;
    1;
  ';

  dbg ("is Razor available? $razor_avail");

  return $razor_avail;
}

sub razor_report {
  my ($self, $fulltext) = @_;

  my @msg = split (/\n/, $fulltext);

  my $Rserver = $self->{main}->{conf}->{razor_host};
  my $Rport   = $self->{main}->{conf}->{razor_port};

  my $sock = new IO::Socket::INET PeerAddr => $Rserver,
                                  PeerPort => $Rport,
                                  Proto    => 'tcp';
  if (!$sock) {
    dbg ("failed to connect to Razor server $Rserver:$Rport, ignoring Razor");
    return 0;
  }

  my $sig = 'x';
  my $response = '';

  eval q{
    use Razor::String;
    use Razor::Signature; 

    $sig = Razor::Signature->hash (\@msg);
    undef @msg;         # no longer needed

    my %message;
    $message{'key'} = $sig;
    $message{'action'} = "report";
    my $str = Razor::String::hash2str ( {%message} );

    $sock->autoflush;
    print $sock "$str\n.\n";
    $response = join ('', <$sock>);
    dbg ("Razor: spam reported, response is \"$response\".");
    undef $sock;

  1;} or warn "razor check failed: $! $@";

  if ($response =~ /Positive $sig/) { return 1; }
  return 0;
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
