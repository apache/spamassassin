=head1 NAME

Mail::SpamAssassin::PerMsgLearner - per-message status (spam or not-spam)

=head1 SYNOPSIS

  my $spamtest = new Mail::SpamAssassin ({
    'rules_filename'      => '/etc/spamassassin.rules',
    'userprefs_filename'  => $ENV{HOME}.'/.spamassassin.cf'
  });
  my $mail = Mail::SpamAssassin::NoMailAudit->new();

  my $status = $spamtest->learn ($mail);
  ...


=head1 DESCRIPTION

The Mail::SpamAssassin C<learn()> method returns an object of this
class.  This object encapsulates all the per-message state for
the learning process.

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin::PerMsgLearner;

use strict;
eval "use bytes";

use Mail::SpamAssassin;
use Mail::SpamAssassin::AutoWhitelist;
use Mail::SpamAssassin::PerMsgStatus;
use Mail::SpamAssassin::Bayes;

use vars qw{
  @ISA
};

@ISA = qw();

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my ($main, $msg, $id) = @_;

  my $self = {
    'main'              => $main,
    'msg'               => $msg,
  };

  $self->{conf} = $self->{main}->{conf};

  $self->{bayes_scanner} = $self->{main}->{bayes_scanner};

  $id ||= $self->{msg}->get_header ("Message-Id");
  $id ||= $self->{msg}->get_header ("Message-ID");
  $id ||= 'no_id.$$.'.rand();
  $id =~ s/[-\0\s\;\:]/_/gs;

  $self->{id} = $id;

  bless ($self, $class);
  $self;
}

###########################################################################

sub learn_spam {
  my ($self) = @_;

  if ($self->{main}->{learn_with_whitelist}) {
    $self->{main}->add_all_addresses_to_blacklist ($self->{msg});
  }

  # use the real message-id here instead of mass-check's idea of an "id",
  # as we may deliver the msg into another mbox format but later need
  # to forget it's training.
  $self->{bayes_scanner}->learn (1, $self->{msg});
}

###########################################################################

sub learn_ham {
  my ($self) = @_;

  if ($self->{main}->{learn_with_whitelist}) {
    $self->{main}->add_all_addresses_to_whitelist ($self->{msg});
  }

  $self->{bayes_scanner}->learn (0, $self->{msg});
}

###########################################################################

sub forget {
  my ($self) = @_;

  if ($self->{main}->{learn_with_whitelist}) {
    $self->{main}->remove_all_addresses_from_whitelist ($self->{msg});
  }

  $self->{bayes_scanner}->forget ($self->{msg});
}

###########################################################################

sub finish {
  my $self = shift;
  delete $self->{main};
  delete $self->{msg};
  delete $self->{conf};
}

sub dbg { Mail::SpamAssassin::dbg (@_); }
sub timelog { Mail::SpamAssassin::timelog (@_); }

###########################################################################

1;
__END__

=back

=head1 SEE ALSO

C<Mail::SpamAssassin>
C<spamassassin>

