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

package Mail::SpamAssassin::Plugin::HTTPSMismatch;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use strict;
use warnings;
use bytes;
use re 'taint';

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
  $self->register_eval_rule ("check_https_http_mismatch");

  return $self;
}

# [lt]a href="http://baboz-njeryz.de/"[gt]https://bankofamerica.com/[lt]/a[gt]
# ("<" and ">" replaced with "[lt]" and "[gt]" to avoid Kaspersky Desktop AV
# false positive ;)
sub check_https_http_mismatch {
  my ($self, $permsgstatus, undef, $minanchors, $maxanchors) = @_;

  $minanchors ||= 1;

  if (!exists $permsgstatus->{chhm_hit}) {
    $permsgstatus->{chhm_hit} = 0;
    $permsgstatus->{chhm_anchors} = 0;

    foreach my $v ( values %{$permsgstatus->{html}->{uri_detail}} ) {
      # if the URI wasn't used for an anchor tag, or the anchor text didn't
      # exist, skip this.
      next unless (exists $v->{anchor_text} && @{$v->{anchor_text}});

      my $uri;
      foreach (@{$v->{cleaned}}) {
        if (m@^https?://([^/:]+)@i) {
	  $uri = $1;

	  # Skip IPs since there's another rule to catch that already
          if ($uri =~ /^\d+\.\d+\.\d+\.\d+$/) {
            undef $uri;
            next;
          }

	  # want to compare whole hostnames instead of domains?
	  # comment this next section to the blank line.
	  $uri = $self->{main}->{registryboundaries}->trim_domain($uri);
          undef $uri unless ($self->{main}->{registryboundaries}->is_domain_valid($uri));

	  last if $uri;
        }
      }

      next unless $uri;
      $permsgstatus->{chhm_anchors}++ if exists $v->{anchor_text};

      foreach (@{$v->{anchor_text}}) {
        if (m@https://([^/:]+)@i) {
          my $https = $1;

	  # want to compare whole hostnames instead of domains?
	  # comment this next section to the blank line.
          if ($https !~ /^\d+\.\d+\.\d+\.\d+$/) {
	    $https = $self->{main}->{registryboundaries}->trim_domain($https);
            undef $https unless ($self->{main}->{registryboundaries}->is_domain_valid($https));
          }
	  next unless $https;

	  dbg("https_http_mismatch: domains $uri -> $https");

	  next if $uri eq $https;
	  $permsgstatus->{chhm_hit} = 1;
	  last;
        }
      }
    }
    dbg("https_http_mismatch: anchors ".$permsgstatus->{chhm_anchors});
  }

  return ( $permsgstatus->{chhm_hit} && $permsgstatus->{chhm_anchors} >= $minanchors && (defined $maxanchors && $permsgstatus->{chhm_anchors} < $maxanchors) );
}

1;
