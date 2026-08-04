package Mail::SpamAssassin::PDF::Context;
use strict;
use warnings FATAL => 'all';
use Storable qw(dclone);
use Carp;

sub new {
    my ($class,%opts) = @_;
    my $self = bless { %opts }, $class;
    $self->reset_state();
    $self;
}

sub reset_state {
    my $self = shift;

    # Graphics state
    $self->{gs} = {
        ctm => [ 1, 0, 0, 1, 0, 0 ], # Current Transformation Matrix
        pos => [ 0, 0 ]
    };

    $self->{stack} = [];
}

sub save_state {
    my $self = shift;
    push(@{$self->{stack}},dclone $self->{gs});
}

sub restore_state {
    my $self = shift;
    croak "Stack underflow" unless @{$self->{stack}};
    $self->{gs} = pop(@{$self->{stack}});
}

#
# This function performs matrix multiplication
# The operands are two 6-element arrays representing the following two 3x3 matrices
#
#   m0  m1  0           n0  n1  0
#   m2  m3  0     X     n2  n3  0
#   m4  m5  1           n4  n5  1
#
sub concat_matrix {
    my ($self,@m) = @_;

    my $n = $self->{gs}->{ctm};

    $self->{gs}->{ctm} = [
        $m[0]*$n->[0] + $m[1]*$n->[2],
        $m[0]*$n->[1] + $m[1]*$n->[3],
        $m[2]*$n->[0] + $m[3]*$n->[2],
        $m[2]*$n->[1] + $m[3]*$n->[3],
        $m[4]*$n->[0] + $m[5]*$n->[2] + $n->[4],
        $m[4]*$n->[1] + $m[5]*$n->[3] + $n->[5]
    ];
}

#
# transform one or more points from user space to device space.
#
# This function performs matrix multiplication between a 1x3 matrix and a 3x3 matrix
#
#                       n0  n1  0
#   m0  m1  1     X     n2  n3  0
#                       n4  n5  1
#
# The result is a 1x3 matrix, of which only the first two values are returned.
# If multiple pairs are provided, multiple pairs are returned.
#
sub transform {
    my $self = shift;
    my $n = $self->{gs}->{ctm};

    my @out;
    while (@_) {
        my($m0,$m1)=(shift,shift);
        push(
            @out,
            $m0*$n->[0] + $m1*$n->[2] + 1*$n->[4],
            $m0*$n->[1] + $m1*$n->[3] + 1*$n->[5]
        );
    }
    return @out;
}

1;