# Mail::SpamAssassin::NetSet - object to manipulate CIDR net IP addrs
package Mail::SpamAssassin::NetSet;

use strict;
use bytes;

use Mail::SpamAssassin::Util;

use vars qw{
  @ISA $TESTCODE $NUMTESTS
};

@ISA = qw();

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = { };
  bless $self, $class;

  $self;
}

###########################################################################

sub add_cidr {
  my ($self, @nets) = @_;
  local ($_);

  $self->{nets} ||= [ ];
  my $numadded = 0;

  foreach (@nets) {
    my ($ip, $bits) = m#^\s*([\d\.]+)(?:/(\d+))?\s*$#;

    my $err = "illegal network address given: '$_'\n";
    if (!defined $ip) {
      warn $err; next;

    } elsif ($ip =~ /\.$/) {
      # just use string matching; much simpler than doing smart stuff with arrays ;)
      if ($ip =~ /^(\d+)\./) { $ip = "$1.0.0.0"; $bits = 8; }
      elsif ($ip =~ /^(\d+)\.(\d+)\./) { $ip = "$1.$2.0.0"; $bits = 16; }
      elsif ($ip =~ /^(\d+)\.(\d+)\.(\d+)\./) { $ip = "$1.$2.$3.0"; $bits = 24; }
      else {
	warn $err; next;
      }
    }

    $bits = 32 if (!defined $bits);
    my $mask = 0xFFffFFff ^ ((2 ** (32-$bits)) - 1);

    push @{$self->{nets}}, {
      mask => $mask,
      ip   => Mail::SpamAssassin::Util::my_inet_aton($ip) & $mask
    };
    $numadded++;
  }

  $numadded;
}

sub contains_ip {
  my ($self, $ip) = @_;

  if (!defined $self->{nets}) { return 0; }

  $ip = Mail::SpamAssassin::Util::my_inet_aton($ip);
  foreach my $net (@{$self->{nets}}) {
    return 1 if (($ip & $net->{mask}) == $net->{ip});
  }
  0;
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

###########################################################################
# unit tests for CIDR specifications and IP matching.  Save memory by compiling
# this only when the test() function is run.

sub test_load_code { eval $TESTCODE or die "eval of test code failed: $@"; }
sub test { _test(@_); }

$NUMTESTS = 22;

$TESTCODE = q{

  sub tryone {
    my ($testip, @nets) = @_;
    my $nets = Mail::SpamAssassin::NetSet->new();
    foreach my $net (@nets) { $nets->add_cidr ($net); }

    if ($nets->contains_ip ($testip)) {
      print "\n$testip was in @nets\n"; return 1;
    } else {
      print "\n$testip was not in @nets\n"; return 0;
    }
  }

  sub _test {
    my ($okfunc) = @_;
    &$okfunc (tryone ("127.0.0.1", "127.0.0.1"));
    &$okfunc (!tryone ("127.0.0.2", "127.0.0.1"));

    &$okfunc (tryone ("127.0.0.1", "127."));
    &$okfunc (tryone ("127.0.0.254", "127."));
    &$okfunc (tryone ("127.0.0.1", "127/8"));
    &$okfunc (tryone ("127.0.0.1", "127.0/16"));
    &$okfunc (tryone ("127.0.0.1", "127.0.0/24"));
    &$okfunc (tryone ("127.0.0.1", "127.0.0.1/32"));
    &$okfunc (tryone ("127.0.0.1", "127.0.0.1/31"));
    &$okfunc (tryone ("127.0.0.1", "10.", "11.", "127.0.0.1"));
    &$okfunc (tryone ("127.0.0.1", "127.0."));
    &$okfunc (tryone ("127.0.0.1", "127.0.0."));
    &$okfunc (tryone ("127.0.0.1", "127."));

    &$okfunc (!tryone ("128.0.0.254", "127."));
    &$okfunc (!tryone ("128.0.0.1", "127/8"));
    &$okfunc (!tryone ("128.0.0.1", "127.0/16"));
    &$okfunc (!tryone ("128.0.0.1", "127.0.0/24"));
    &$okfunc (!tryone ("128.0.0.1", "127.0.0.1/32"));
    &$okfunc (!tryone ("128.0.0.1", "127.0.0.1/31"));
    &$okfunc (!tryone ("128.0.0.1", "127.0."));
    &$okfunc (!tryone ("128.0.0.1", "127.0.0."));
    &$okfunc (!tryone ("12.9.0.1", "10.", "11.", "127.0.0.1"));
  }

1; };

###########################################################################

1;
