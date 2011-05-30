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

package Mail::SpamAssassin::Plugin::HTMLEval;

use strict;
use warnings;
use bytes;
use re 'taint';

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Locales;
use Mail::SpamAssassin::Util qw(untaint_var);

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
  $self->register_eval_rule("html_tag_balance");
  $self->register_eval_rule("html_image_only");
  $self->register_eval_rule("html_image_ratio");
  $self->register_eval_rule("html_charset_faraway");
  $self->register_eval_rule("html_tag_exists");
  $self->register_eval_rule("html_test");
  $self->register_eval_rule("html_eval");
  $self->register_eval_rule("html_text_match");
  $self->register_eval_rule("html_title_subject_ratio");
  $self->register_eval_rule("html_text_not_match");
  $self->register_eval_rule("html_range");
  $self->register_eval_rule("check_iframe_src");

  return $self;
}

sub html_tag_balance {
  my ($self, $pms, undef, $rawtag, $rawexpr) = @_;
  $rawtag =~ /^([a-zA-Z0-9]+)$/; my $tag = $1;
  $rawexpr =~ /^([\<\>\=\!\-\+ 0-9]+)$/; my $expr = $1;

  return 0 unless exists $pms->{html}{inside}{$tag};

  $pms->{html}{inside}{$tag} =~ /^([\<\>\=\!\-\+ 0-9]+)$/;
  my $val = $1;
  return eval "\$val $expr";
}

sub html_image_only {
  my ($self, $pms, undef, $min, $max) = @_;

  return (exists $pms->{html}{inside}{img} &&
	  exists $pms->{html}{length} &&
	  $pms->{html}{length} > $min &&
	  $pms->{html}{length} <= $max);
}

sub html_image_ratio {
  my ($self, $pms, undef, $min, $max) = @_;

  return 0 unless (exists $pms->{html}{non_space_len} &&
		   exists $pms->{html}{image_area} &&
		   $pms->{html}{image_area} > 0);
  my $ratio = $pms->{html}{non_space_len} / $pms->{html}{image_area};
  return ($ratio > $min && $ratio <= $max);
}

sub html_charset_faraway {
  my ($self, $pms) = @_;

  return 0 unless exists $pms->{html}{charsets};

  my @locales = Mail::SpamAssassin::Util::get_my_locales($pms->{conf}->{ok_locales});
  return 0 if grep { $_ eq "all" } @locales;

  my $okay = 0;
  my $bad = 0;
  for my $c (split(' ', $pms->{html}{charsets})) {
    if (Mail::SpamAssassin::Locales::is_charset_ok_for_locales($c, @locales)) {
      $okay++;
    }
    else {
      $bad++;
    }
  }
  return ($bad && ($bad >= $okay));
}

sub html_tag_exists {
  my ($self, $pms, undef, $tag) = @_;
  return exists $pms->{html}{inside}{$tag};
}

sub html_test {
  my ($self, $pms, undef, $test) = @_;
  return $pms->{html}{$test};
}

sub html_eval {
  my ($self, $pms, undef, $test, $rawexpr) = @_;
  my $expr;
  if ($rawexpr =~ /^[\<\>\=\!\-\+ 0-9]+$/) {
    $expr = untaint_var($rawexpr);
  }
  # workaround bug 3320: wierd perl bug where additional, very explicit
  # untainting into a new var is required.
  my $tainted = $pms->{html}{$test};
  return unless defined($tainted);
  my $val = $tainted;

  # just use the value in $val, don't copy it needlessly
  return eval "\$val $expr";
}

sub html_text_match {
  my ($self, $pms, undef, $text, $regexp) = @_;
  for my $string (@{ $pms->{html}{$text} }) {
    if (defined $string && $string =~ /${regexp}/) {
      return 1;
    }
  }
  return 0;
}

sub html_title_subject_ratio {
  my ($self, $pms, undef, $ratio) = @_;

  my $subject = $pms->get('Subject');
  if ($subject eq '') {
    return 0;
  }
  my $max = 0;
  for my $string (@{ $pms->{html}{title} }) {
    if ($string) {
      my $ratio = length($string) / length($subject);
      $max = $ratio if $ratio > $max;
    }
  }
  return $max > $ratio;
}

sub html_text_not_match {
  my ($self, $pms, undef, $text, $regexp) = @_;
  for my $string (@{ $pms->{html}{$text} }) {
    if (defined $string && $string !~ /${regexp}/) {
      return 1;
    }
  }
  return 0;
}

sub html_range {
  my ($self, $pms, undef, $test, $min, $max) = @_;

  return 0 unless exists $pms->{html}{$test};

  $test = $pms->{html}{$test};

  # not all perls understand what "inf" means, so we need to do
  # non-numeric tests!  urg!
  if (!defined $max || $max eq "inf") {
    return ($test eq "inf") ? 1 : ($test > $min);
  }
  elsif ($test eq "inf") {
    # $max < inf, so $test == inf means $test > $max
    return 0;
  }
  else {
    # if we get here everything should be a number
    return ($test > $min && $test <= $max);
  }
}

sub check_iframe_src {
  my ($self, $pms) = @_;

  foreach my $v ( values %{$pms->{html}->{uri_detail}} ) {
    return 1 if $v->{types}->{iframe};
  }

  return 0;
}

1;
