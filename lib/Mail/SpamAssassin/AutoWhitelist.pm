
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

  # could not find an IP address to use, could be localhost mail
  if (!defined $origip) {
    $origip = 'none';
  } else {
    $origip =~ s/\.\d{1,3}\.\d{1,3}$//gs;
  }

  $origip =~ s/[\000\;\'\"\!\|]/_/gs;	# paranoia
  $self->{entry} = $self->{checker}->get_addr_entry ($addr."|ip=".$origip);

  if(!defined $self->{entry}->{count}) { return undef; }
  if($self->{entry}->{count} == 0) { return undef; }

  return $self->{entry}->{totscore}/$self->{entry}->{count};
}

###########################################################################

=item awl->add_score($score);

This method will add half the score to the current entry.  Half the
score is used, so that repeated use of the same From and IP address
combination will gradually reduce the score.

=cut

sub add_score {
  my ($self,$score) = @_;

  if (!defined $self->{checker}) {
    return undef;		# no factory defined; we can't check
  }

  $self->{entry}->{count} ||= 0;
  $self->{checker}->add_score($self->{entry}, $score);
}

###########################################################################

=item awl->add_known_good_address($addr);

This method will add a score of -100 to the given address -- effectively
"bootstrapping" the address as being one that should be whitelisted.

=cut

sub add_known_good_address {
  my ($self, $addr) = @_;

  return $self->modify_address($addr, -100);
}

###########################################################################

=item awl->add_known_bad_address($addr);

This method will add a score of 100 to the given address -- effectively
"bootstrapping" the address as being one that should be blacklisted.

=cut

sub add_known_bad_address {
  my ($self, $addr) = @_;

  return $self->modify_address($addr, 100);
}

###########################################################################

sub remove_address {
  my ($self, $addr) = @_;

  return $self->modify_address($addr, undef);
}

###########################################################################

sub modify_address {
  my ($self, $addr, $score) = @_;

  if (!defined $self->{checker}) {
    return undef;		# no factory defined; we can't check
  }

  $addr = lc $addr;
  $addr =~ s/[\000\;\'\"\!\|]/_/gs;	# paranoia
  my $entry = $self->{checker}->get_addr_entry ($addr);

  # remove any old entries (will remove per-ip entries as well)
  # always call this regardless, as the current entry may have 0
  # scores, but the per-ip one may have more
  $self->{checker}->remove_entry($entry);

  # remove address only, no new score to add
  if (!defined($score)) { return 1; }

  # else add score. get a new entry first
  $entry = $self->{checker}->get_addr_entry ($addr);
  $self->{checker}->add_score($entry, $score);

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
