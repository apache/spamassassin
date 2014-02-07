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

package Mail::SpamAssassin::Plugin::Sandbox::hstern;

use strict;
use warnings;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util;

use vars qw(@ISA);
our @ISA = qw(Mail::SpamAssassin::Plugin);


sub new {
  my $class = shift;
  my $mailsa = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless ($self, $class);

  $self->register_eval_rule("check_fast_forward");

  return $self;
}

sub check_fast_forward {
  my $self = shift;
  my $status = shift;
  my $body = $status->get_decoded_body_text_array();
  my $date = $status->get("Date");

  return undef unless $date;
  my $cdate = Mail::SpamAssassin::Util::parse_rfc822_date ($date, "+0000");
  return undef unless $cdate; # cannot parse date
  my (undef, $cdmin) = gmtime($cdate);

  foreach (@$body) {
    if ( /^Sent: (.*)/ ) {
      my $csent = Mail::SpamAssassin::Util::parse_rfc822_date ($1, "+0000");
      next unless $csent; # cannot parse date
      my (undef, $csmin) = gmtime($csent);
      return $cdmin == $csmin;
    }
  }

  return undef;
}

1;
