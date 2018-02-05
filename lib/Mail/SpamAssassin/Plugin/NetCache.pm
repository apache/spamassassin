# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

=head1 NAME

Mail::SpamAssassin::Plugin::NetCache - store network check results in headers

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::NetCache

=head1 DESCRIPTION

This is a work-in-progress experimental plugin not for general use.

This plugin stores network check results in the message header.  The
idea is to store all results (positive and negative) in the headers,
then during mass-check, pull the results out and use them for "live"
data to give better results during SpamAssassin score generation.

This needs more plugin hooks as appropriate, needs code to put results
in header and to pull results back out from said headers, etc.

To try this plugin, write the above two lines in the synopsis to
C</etc/mail/spamassassin/plugintest.cf>.

=cut

package Mail::SpamAssassin::Plugin::NetCache;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Util;
use Mail::SpamAssassin::Logger;
use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw(Mail::SpamAssassin::Plugin);

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
