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
  my $str = $opts->{permsgstatus}->get("ALL");
  $str =~ s/\n/\[\\n\]/gs;
  $str =~ s/\t/\[\\t\]/gs;
  $str =~ s/\n+//gs;

  # ignore the M:SpamAssassin:compile() test message
  return if ($str =~ 
        /I need to make this message body somewhat long so TextCat preloads/);

  print STDOUT "text: $str\n";
}

1;
