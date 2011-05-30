# Dumpmem - dump SpamAssassin memory structures to disk after each message
#
# use as follows:
#
#   MEMDEBUG=1 ./mass-check --cf='loadplugin Dumpmem plugins/Dumpmem.pm' \
#     [normal mass-check arguments]
#
# e.g.
#
#   MEMDEBUG=1 ./mass-check --cf='loadplugin Dumpmem plugins/Dumpmem.pm' \
#     --net -n -o spam:dir:/local/cor/recent/spam/high.2007010*

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
  warn "Dumpmem plugin loaded";
  if (!$ENV{'MEMDEBUG'}) {
    warn "you forgot to set MEMDEBUG=1!  are you sure you want that?";
  }
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
