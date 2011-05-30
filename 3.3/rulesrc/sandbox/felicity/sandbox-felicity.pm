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

package Mail::SpamAssassin::Plugin::Sandbox::felicity;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
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

  # the important bit!
  $self->register_eval_rule ("check_quotedprintable_length");

  return $self;
}

sub check_quotedprintable_length {
  my $self = shift;
  my $pms = shift;
  shift; # body array, unnecessary
  my $min = shift;
  my $max = shift;

  if (!defined $pms->{quotedprintable_length}) {
    $pms->{quotedprintable_length} = $self->_check_quotedprintable_length($pms->{msg});
  }

  return 0 if (defined $max && $pms->{quotedprintable_length} > $max);
  return $pms->{quotedprintable_length} >= $min;
}

sub _check_quotedprintable_length {
  my $self = shift;
  my $msg = shift;

  my $result = 0;

  foreach my $p ($msg->find_parts(qr@.@, 1)) {
    my $ctype=
      Mail::SpamAssassin::Util::parse_content_type($p->get_header('content-type'));

    my $cte = lc $p->get_header('content-transfer-encoding') || '';
    next if ($cte !~ /^quoted-printable$/);
    foreach my $l ( @{$p->raw()} ) {
      my $len = length $l;
      $result = $len if ($len > $result);
    }
  }
  
  return $result;
}


1;
