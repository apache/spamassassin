
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

  $self->{threshold} = $main->{conf}->{auto_whitelist_threshold};

  if (!defined $self->{main}->{pers_addr_list_factory}) {
    $self->{checker} = undef;
  } else {
    $self->{checker} =
  	$self->{main}->{pers_addr_list_factory}->new_checker ($self->{main});
  }

  bless ($self, $class);
  $self;
}

###########################################################################

sub check_address {
  my ($self, $addr) = @_;

  if (!defined $self->{checker}) {
    return 0;		# no factory defined; we can't check
  }

  $addr = lc $addr;
  $addr =~ s/[\000\;\'\"\!]/_/gs;	# paranoia
  $self->{entry} = $self->{checker}->get_addr_entry ($addr);

  if ($self->{entry}->{count} >= $self->{threshold}) {
    $self->{already_in_whitelist} = 1;
    return 1;
  } else {
    return 0;
  }
}

###########################################################################

sub increment_pass_accumulator {
  my ($self) = @_;

  if (!defined $self->{checker}) {
    return 0;		# no factory defined; we can't check
  }

  if (!$self->{already_in_whitelist}) {
    $self->{checker}->increment_accumulator_for_entry ($self->{entry});

  } elsif ($self->{entry}->{count} == $self->{threshold}) {
    $self->{checker}->add_permanent_entry ($self->{entry});
  }
}

###########################################################################

sub add_known_good_address {
  my ($self, $addr) = @_;

  if (!defined $self->{checker}) {
    return 0;		# no factory defined; we can't check
  }

  # this could be short-circuited, but for now I can't see a need.
  # other backend implementors can have a go, if they do.

  $addr = lc $addr;
  $addr =~ s/[\000\;\'\"\!]/_/gs;	# paranoia
  my $entry = $self->{checker}->get_addr_entry ($addr);

  if ($entry->{count} < $self->{threshold}) {
    $self->{checker}->add_permanent_entry ($entry);
    return 1;
  }

  return 0;
}

###########################################################################

sub remove_address {
  my ($self, $addr) = @_;

  if (!defined $self->{checker}) {
    return 0;		# no factory defined; we can't check
  }

  # this could be short-circuited, but for now I can't see a need.
  # other backend implementors can have a go, if they do.

  $addr = lc $addr;
  $addr =~ s/[\000\;\'\"\!]/_/gs;	# paranoia
  my $entry = $self->{checker}->get_addr_entry ($addr);

  if ($entry->{count} > 0) {
    $self->{checker}->remove_entry ($entry);
    return 1;
  }

  return 0;
}

###########################################################################

sub finish {
  my $self = shift;

  if (!defined $self->{checker}) { return; }
  $self->{checker}->finish();
}

###########################################################################

1;
