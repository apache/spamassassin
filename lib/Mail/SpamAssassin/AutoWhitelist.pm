
package Mail::SpamAssassin::AutoWhitelist;

use strict;

use Mail::SpamAssassin;

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
  };

  bless ($self, $class);
  $self;
}

###########################################################################

sub check_and_inc_addr {
  my ($self, $addr) = @_;

  my $checker =
  	$self->{main}->{pers_addr_list_factory}->new_checker ($self->{main});

  my $entry = $checker->get_addr_entry ($addr);
  my $ok = 0;
  if ($entry->{count} >= 3) {
    $ok = 1; $checker->add_permanent_entry ($entry);
  } else {
    $checker->increment_accumulator_for_entry ($entry);
  }

  $checker->finish();
  return $ok;
}

###########################################################################

1;
