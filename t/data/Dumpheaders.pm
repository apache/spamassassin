package Dumpheaders;
use strict;
use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my ($class, $mailsa) = @_;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless ($self, $class);
  return $self;
}

sub check_end {
  my ($self, $opts) = @_;

  local $_;
  $_ = $opts->{permsgstatus}->get("ALL:raw");
  s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs;

  # ignore the M:SpamAssassin:compile() test message
  return if /I need to make this message body somewhat long so TextCat preloads/;
  print STDOUT "text-all-raw: $_\n";

  $_ = $opts->{permsgstatus}->get("ALL");
  s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs;
  print STDOUT "text-all-noraw: $_\n";

  $_ = $opts->{permsgstatus}->get("From:raw");
  s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs;
  print STDOUT "text-from-raw: $_\n";

  $_ = $opts->{permsgstatus}->get("From");
  s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs;
  print STDOUT "text-from-noraw: $_\n";

  $_ = $opts->{permsgstatus}->get("From:addr");
  s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs;
  print STDOUT "text-from-addr: $_\n";

}

1;

