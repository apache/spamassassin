
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

  $self->{factor} = $main->{conf}->{auto_whitelist_factor};

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

=item $meanscore = awl->check_address($addr, $originating_ip);

This method will return the mean score of all messages associated with the
given address, or undef if the address hasn't been seen before.

If B<$originating_ip> is supplied, it will be used in the lookup.

=cut

sub check_address {
  my ($self, $addr, $origip) = @_;

  if (!defined $self->{checker}) {
    return undef;		# no factory defined; we can't check
  }

  $addr = lc $addr;
  $addr =~ s/[\000\;\'\"\!\|]/_/gs;	# paranoia

  $self->{entry} = undef;

  if (defined $origip) {
    $origip =~ s/\.\d{1,3}\.\d{1,3}$//gs;
    $origip =~ s/[\000\;\'\"\!\|]/_/gs;	# paranoia
    $self->{entry} = $self->{checker}->get_addr_entry ($addr."|ip=".$origip);
  }

  if (!defined $self->{entry}) {
    # fall back to more general style
    $self->{entry} = $self->{checker}->get_addr_entry ($addr);
  }

  if($self->{entry}->{count} == 0) { return undef; }

  return $self->{entry}->{totscore}/$self->{entry}->{count};
}

###########################################################################

=item awl->add_score($score);

This method will add the score to the current entry

=cut

sub add_score {
  my ($self,$score) = @_;

  if (!defined $self->{checker}) {
    return undef;		# no factory defined; we can't check
  }

  $self->{checker}->add_score($self->{entry},$score);
}

###########################################################################

=item awl->add_known_good_address($addr);

This method will add a score of -100 to the given address -- effectively
"bootstrapping" the address as being one that should be whitelisted.

=cut

sub add_known_good_address {
  my ($self, $addr) = @_;

  if (!defined $self->{checker}) {
    return undef;		# no factory defined; we can't check
  }

  $addr = lc $addr;
  $addr =~ s/[\000\;\'\"\!\|]/_/gs;	# paranoia
  my $entry = $self->{checker}->get_addr_entry ($addr);

  # remove any old entries (will remove per-ip entries as well)
  if ($entry->{count} > 0) {
    $self->{checker}->remove_entry ($entry);
  }
  $self->{checker}->add_score($entry,-100);

  return 0;
}

###########################################################################

=item awl->add_known_bad_address($addr);

This method will add a score of 100 to the given address -- effectively
"bootstrapping" the address as being one that should be blacklisted.

=cut

sub add_known_bad_address {
  my ($self, $addr) = @_;

  if (!defined $self->{checker}) {
    return undef;		# no factory defined; we can't check
  }

  $addr = lc $addr;
  $addr =~ s/[\000\;\'\"\!\|]/_/gs;	# paranoia
  my $entry = $self->{checker}->get_addr_entry ($addr);

  # remove any old entries (will remove per-ip entries as well)
  if ($entry->{count} > 0) {
    $self->{checker}->remove_entry ($entry);
  }
  $self->{checker}->add_score($entry,100);

  return 0;
}



###########################################################################

sub remove_address {
  my ($self, $addr) = @_;

  if (!defined $self->{checker}) {
    return undef;		# no factory defined; we can't check
  }

  $addr = lc $addr;
  $addr =~ s/[\000\;\'\"\!\|]/_/gs;	# paranoia

  my $entry = $self->{checker}->get_addr_entry ($addr);
  $self->{checker}->remove_entry ($entry) and return 1;

  return 0;
}

###########################################################################

sub finish {
  my $self = shift;

  if (!defined $self->{checker}) { return undef; }
  $self->{checker}->finish();
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
