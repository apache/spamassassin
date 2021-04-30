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

  # ignore the M:SpamAssassin:compile() test message
  return if $self->{linting};
  #return if /I need to make this message body somewhat long so TextCat preloads/;

  ## pre-4.0 scalar context calls

  $_ = $opts->{permsgstatus}->get("ALL:raw");
  s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs;
  print STDOUT "scalar-text-all-raw: $_"."[END]\n";

  $_ = $opts->{permsgstatus}->get("ALL");
  s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs;
  print STDOUT "scalar-text-all-noraw: $_"."[END]\n";

  $_ = $opts->{permsgstatus}->get("From:raw");
  s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs;
  print STDOUT "scalar-text-from-raw: $_"."[END]\n";

  $_ = $opts->{permsgstatus}->get("From");
  s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs;
  print STDOUT "scalar-text-from-noraw: $_"."[END]\n";

  $_ = $opts->{permsgstatus}->get("From:addr");
  s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs;
  print STDOUT "scalar-text-from-addr: $_"."[END]\n";

  ## 4.0 list context tests

  my @l;
  my $s;

  @l = $opts->{permsgstatus}->get("ALL:raw");
  foreach (@l) { s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs; }
  print STDOUT "list-text-all-raw: ".join("[LIST]", @l)."[END]\n";

  @l = $opts->{permsgstatus}->get("ALL");
  foreach (@l) { s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs; }
  print STDOUT "list-text-all-noraw: ".join("[LIST]", @l)."[END]\n";

  @l = $opts->{permsgstatus}->get("From:raw");
  foreach (@l) { s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs; }
  print STDOUT "list-text-from-raw: ".join("[LIST]", @l)."[END]\n";

  @l = $opts->{permsgstatus}->get("From");
  foreach (@l) { s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs; }
  print STDOUT "list-text-from-noraw: ".join("[LIST]", @l)."[END]\n";

  @l = $opts->{permsgstatus}->get("From:addr");
  foreach (@l) { s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs; }
  print STDOUT "list-text-from-addr: ".join("[LIST]", @l)."[END]\n";

  @l = $opts->{permsgstatus}->get("From:first:addr");
  foreach (@l) { s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs; }
  print STDOUT "list-text-from-first-addr: ".join("[LIST]", @l)."[END]\n";

  @l = $opts->{permsgstatus}->get("From:last:addr");
  foreach (@l) { s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs; }
  print STDOUT "list-text-from-last-addr: ".join("[LIST]", @l)."[END]\n";

  @l = $opts->{permsgstatus}->get("MESSAGEID:host");
  foreach (@l) { s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs; }
  print STDOUT "list-text-msgid-host: ".join("[LIST]", @l)."[END]\n";

  @l = $opts->{permsgstatus}->get("MESSAGEID:domain");
  foreach (@l) { s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs; }
  print STDOUT "list-text-msgid-domain: ".join("[LIST]", @l)."[END]\n";

  @l = $opts->{permsgstatus}->get("Received:ip");
  foreach (@l) { s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs; }
  print STDOUT "list-text-received-ip: ".join("[LIST]", @l)."[END]\n";

  @l = $opts->{permsgstatus}->get("Received:revip");
  foreach (@l) { s/\n/[\\n]/gs; s/\t/[\\t]/gs; s/\n+//gs; }
  print STDOUT "list-text-received-revip: ".join("[LIST]", @l)."[END]\n";
}

1;

