=head1 

To try this out, write these lines to /etc/mail/spamassassin/plugintest.cf:

  loadplugin     Mail::SpamAssassin::Plugin::NetCache

=cut

## This is a plugin to store network check results in the message header
## the idea is that we store all results (positive and negative) in the
## headers, then during mass-check we pull the results out and use them for
## "live" data to give better results during score generation.
##
## Definitely still a WOP.  Needs more plugin hooks as appropriate, needs code
## to put results in header and to pull results back out from said headers, etc.

package Mail::SpamAssassin::Plugin::NetCache;

# Make the main dbg() accessible in our package w/o an extra function
*dbg=\&Mail::SpamAssassin::Plugin::dbg;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Util;
use strict;
use warnings;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  return $self;
}

sub process_razor_result {
  my($self, $options) = @_;
  my $output = '';
  my $oresult = 0;

  foreach my $result (@{$options->{results}}) {
    if (exists $result->{result}) {
      if ($result->{result}) {
        dbg('netcache: razor2: result=' . $result->{result});
        $oresult = $result->{result};
      }
    }
    elsif (!$result->{noresponse}) {
      # just make sure the values are in expected range
      $result->{contested} = 1 if $result->{contested};
      $result->{confidence} = 100 if $result->{confidence} > 100;
      $result->{part} = 31 if $result->{part} > 31;
      if ($result->{engine} > 8) {
        dbg('netcache: razor2 engine '.$result->{engine}.' out of range, skipping');
	next;
      }

      dbg('netcache: razor2: part=' . $result->{part} .
        ' engine=' .  $result->{engine} .
	' contested=' . $result->{contested} .
	' confidence=' . $result->{confidence});
      $output .= pack('CC', $result->{part} << 4 | $result->{engine},
        $result->{contested} << 7 | $result->{confidence});
    }
  }

  $output = pack('C', $oresult) . $output;
  dbg('netcache: razor2: '.Mail::SpamAssassin::Util::base64_encode($output));
}

1;
