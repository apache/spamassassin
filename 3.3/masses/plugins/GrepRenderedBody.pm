# GrepRenderedBody - dump SpamAssassin memory structures to disk after each message
#
# use as follows:
#
#   ./mass-check --cf='loadplugin GrepRenderedBody plugins/GrepRenderedBody.pm' \
#     --cf='grep REGEXP' \
#     [normal mass-check arguments]
#
# e.g.
#
#   ./mass-check --cf='loadplugin GrepRenderedBody plugins/GrepRenderedBody.pm' \
#     --cf='grep This is a test\.' \
#     --net -n -o spam:dir:/local/cor/recent/spam/high.2007010*

package GrepRenderedBody;
use strict;
use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my ($class, $mailsa) = @_;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  warn "GrepRenderedBody plugin loaded";

  $mailsa->{conf}->{parser}->register_commands([{
          setting => 'grep',
          type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
        }]);

  $self->{conf} = $mailsa->{conf};

  bless ($self, $class);
  return $self;
}

sub mass_check_skip_message {
  my ($self, $opts) = @_;
  my $ary = $opts->{msg}->get_rendered_body_text_array();
  my $re = $self->{conf}->{grep};

  # no RE?  allow all msgs
  if (!defined $re) { return 0; }

  foreach my $l (@{$ary}) { if ($l =~ /${re}/s) { return 0; } }
  return 1;
}

1;
