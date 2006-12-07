package Dumpmem;
use strict;
use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
our @ISA = qw(Mail::SpamAssassin::Plugin);

use Mail::SpamAssassin::Util::MemoryDump;

sub new {
  my ($class, $mailsa) = @_;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless ($self, $class);
  return $self;
}

sub per_msg_finish {
  my ($self, $opts) = @_;
  Mail::SpamAssassin::Util::MemoryDump::MEMDEBUG();
  Mail::SpamAssassin::Util::MemoryDump::MEMDEBUG_dump_obj(
                                $opts->{permsgstatus}->{main});
}

1;
