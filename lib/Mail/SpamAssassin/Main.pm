#

=head1 NAME

Mail::SpamAssassin - identify spam using text analysis

=head1 DESCRIPTION

TODO

=cut

package Mail::SpamAssassin::Main;

use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::Msg;
use Carp;
use File::Basename;
use File::Path;
use File::Spec;
use Cwd;
use strict;

use vars	qw{
  	@ISA $VERSION $HOME_URL
};

@ISA = qw();

$VERSION = "0.1";
sub Version { $VERSION; }

$HOME_URL = "http://spamassassin.taint.org/";

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = shift;
  bless ($self, $class);

  $self->{conf} = new Mail::SpamAssassin::Conf ($self);
  $self;
}

###########################################################################

sub init {
  my ($self) = @_;

  if ($self->{_initted}) { return; }
  $self->{_initted} = 1;

  $self->{config_text} ||= '';

  if (defined $self->{rules_filename}) {
    open (IN, "<".$self->{rules_filename}) or
		warn "cannot open \"$self->{rules_filename}\"\n";
    $self->{config_text} .= join ('', <IN>);
    close IN;
  }

  if (defined $self->{userprefs_filename}) {
    open (IN, "<".$self->{userprefs_filename}) or
		warn "cannot open \"$self->{userprefs_filename}\"\n";
    $self->{config_text} .= join ('', <IN>);
    close IN;
  }

  $self->{conf}->parse_rules ($self->{config_text});

  # TODO -- open DNS cache etc.
}

###########################################################################

sub check {
  my ($self, $audit) = @_;
  local ($_);

  $self->init();
  my $msg = new Mail::SpamAssassin::Msg ($self, $audit);

  $msg->do_head_tests();	  # pretty quick, these ones
  $msg->do_body_tests();	  # a bit more expensive than the heads
  $msg->do_head_eval_tests();	  # most expensive of all; DNS lookups etc

  # always set these -- we might be just testing, or used in a
  # mode where every mail is tagged.
  $self->{hits} = $msg->{hits};
  $self->{required_hits} = $self->{conf}->{required_hits};
  $_ =
'------------------- Start SpamAssassin results -----------------------
Content analysis:   (_HITS_ hits, _REQD_ required)
_SUMMARY_
------------------- End of SpamAssassin results ----------------------
';

  s/_HITS_/$self->{hits}/gs;
  s/_REQD_/$self->{required_hits}/gs;
  s/_SUMMARY_/$msg->{test_logs}/gs;
  s/_VER_/$VERSION/gs;
  s/_HOME_/$HOME_URL/gs;
  s/^/SPAM: /gm;
  
  $self->{report} = "\n".$_."\n";
  $self->{last_msg} = $msg;
  $self->{is_spam} = ($msg->{hits} >= $self->{conf}->{required_hits});

  return $self->{is_spam};
}

###########################################################################

sub rewrite {
  my ($self, $mail) = @_;

  if ($self->{is_spam}) {
    $self->rewrite_as_spam($mail);
  } else {
    $self->rewrite_as_non_spam($mail);
  }
}

sub rewrite_as_spam {
  my ($self, $mail) = @_;

  # First, rewrite the subject line.
  $_ = $mail->get ("Subject"); $_ ||= '';
  s/^/\*\*\*\*\*SPAM\*\*\*\*\* /g;
  $mail->{obj}->head->replace ("Subject", $_);

  # add some headers...
  $_ = sprintf ("Yes, hits=%d required=%d", $self->{hits},
	$self->{required_hits});
  $mail->put_header ("X-Spam-Status", $_);
  $mail->put_header ("X-Spam-Flag", 'YES');

  # defang HTML mail; change it to text-only.
  $mail->{obj}->head->replace ("Content-Type", "text/plain");
  $mail->{obj}->head->delete ("Content-type");  # just in case

  my $lines = $mail->{obj}->body();
  unshift (@{$lines}, split (/$/, $self->{report}));
  $mail->{obj}->body ($lines);
  $mail;
}

sub rewrite_as_non_spam {
  my ($self, $mail) = @_;

  $_ = sprintf ("No, hits=%d required=%d", $self->{hits},
	$self->{required_hits});
  $mail->put_header ("X-Spam-Status", $_);
  $mail;
}

###########################################################################

1;
