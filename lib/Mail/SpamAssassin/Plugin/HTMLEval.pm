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
# use bytes;
use re 'taint';

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Locales;
use Mail::SpamAssassin::Util qw(untaint_var compile_regexp);

our @ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # the important bit!
  $self->register_eval_rule("html_tag_balance", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("html_image_only", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("html_image_ratio", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("html_charset_faraway", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("html_tag_exists", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("html_test", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("html_eval", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("html_text_match", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("html_title_subject_ratio", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("html_text_not_match", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("html_range", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("check_iframe_src", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

  return $self;
}

sub html_tag_balance {
  my ($self, $pms, undef, $rawtag, $rawexpr) = @_;

  return 0 if $rawtag !~ /^([a-zA-Z0-9]+)$/;
  my $tag = $1;

  return 0 if $rawexpr !~ /^([\<\>\=\!\-\+ 0-9]+)$/;
  my $expr = untaint_var($1);

  foreach my $html (@{$pms->{html_all}}) {
    next unless exists $html->{inside}{$tag};
    $html->{inside}{$tag} =~ /^([\<\>\=\!\-\+ 0-9]+)$/;
    my $val = untaint_var($1);
    return 1 if eval "\$val $expr";
  }

  return 0;
}

sub html_image_only {
  my ($self, $pms, undef, $min, $max) = @_;

  foreach my $html (@{$pms->{html_all}}) {
    if (exists $html->{inside}{img} && exists $html->{length} &&
        $html->{length} > $min && $html->{length} <= $max)
    {
      return 1;
    }
  }

  return 0;
}

sub html_image_ratio {
  my ($self, $pms, undef, $min, $max) = @_;

  foreach my $html (@{$pms->{html_all}}) {
    next unless (exists $html->{non_space_len} &&
                 exists $html->{image_area} &&
                 $html->{image_area} > 0);
    my $ratio = $html->{non_space_len} / $html->{image_area};
    return 1 if $ratio > $min && $ratio <= $max;
  }

  return 0;
}

sub html_charset_faraway {
  my ($self, $pms) = @_;

  my @locales = Mail::SpamAssassin::Util::get_my_locales($pms->{conf}->{ok_locales});
  return 0 if grep { $_ eq "all" } @locales;

  foreach my $html (@{$pms->{html_all}}) {
    next unless exists $html->{charsets};
    my $okay = 0;
    my $bad = 0;
    foreach my $c (split(/\s+/, $html->{charsets})) {
      if (Mail::SpamAssassin::Locales::is_charset_ok_for_locales($c, @locales)) {
        $okay++;
      } else {
        $bad++;
      }
    }
    return 1 if $bad && $bad >= $okay;
  }

  return 0;
}

sub html_tag_exists {
  my ($self, $pms, undef, $tag) = @_;

  foreach my $html (@{$pms->{html_all}}) {
    return 1 if exists $html->{inside}{$tag};
  }

  return 0;
}

sub html_test {
  my ($self, $pms, undef, $test) = @_;

  foreach my $html (@{$pms->{html_all}}) {
    return 1 if $html->{$test};
  }

  return 0;
}

sub html_eval {
  my ($self, $pms, undef, $test, $rawexpr) = @_;

  return 0 if $rawexpr !~ /^([\<\>\=\!\-\+ 0-9]+)$/;
  my $expr = untaint_var($1);

  foreach my $html (@{$pms->{html_all}}) {
    # workaround bug 3320: weird perl bug where additional, very explicit
    # untainting into a new var is required.
    my $tainted = $html->{$test};
    next unless defined($tainted);
    my $val = $tainted;
    # just use the value in $val, don't copy it needlessly
    return 1 if eval "\$val $expr";
  }

  return 0;
}

sub html_text_match {
  my ($self, $pms, undef, $text, $regexp) = @_;

  my ($rec, $err) = compile_regexp($regexp, 0);
  if (!$rec) {
    warn "htmleval: html_text_match invalid regexp '$regexp': $err";
    return 0;
  }

  foreach my $html (@{$pms->{html_all}}) {
    next unless ref($html->{$text}) eq 'ARRAY';
    foreach my $string (@{$html->{$text}}) {
      next unless defined $string;
      if ($string =~ $rec) {
        return 1;
      }
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

  foreach my $html (@{$pms->{html_all}}) {
    my $max = 0;
    foreach my $string (@{$html->{title}}) {
      if ($string) {
        my $ratio_s = length($string) / length($subject);
        $max = $ratio_s if $ratio_s > $max;
      }
    }
    return 1 if $max > $ratio;
  }

  return 0;
}

sub html_text_not_match {
  my ($self, $pms, undef, $text, $regexp) = @_;

  my ($rec, $err) = compile_regexp($regexp, 0);
  if (!$rec) {
    warn "htmleval: html_text_not_match invalid regexp '$regexp': $err";
    return 0;
  }

  foreach my $html (@{$pms->{html_all}}) {
    next unless ref($html->{$text}) eq 'ARRAY';
    foreach my $string (@{$html->{$text}}) {
      if (defined $string && $string !~ $rec) {
        return 1;
      }
    }
  }

  return 0;
}

sub html_range {
  my ($self, $pms, undef, $test, $min, $max) = @_;

  foreach my $html (@{$pms->{html_all}}) {
    next unless defined $html->{$test};
    my $value = $html->{$test};
    # not all perls understand what "inf" means, so we need to do
    # non-numeric tests!  urg!
    if (!defined $max || $max eq "inf") {
      return 1 if $value > $min;
    }
    elsif ($value eq "inf") {
      # $max < inf, so $value == inf means $value > $max
      next;
    }
    else {
      # if we get here everything should be a number
      return 1 if $value > $min && $value <= $max;
    }
  }

  return 0;
}

sub check_iframe_src {
  my ($self, $pms) = @_;

  foreach my $html (@{$pms->{html_all}}) {
    foreach my $v (values %{$html->{uri_detail}}) {
      return 1 if $v->{types}->{iframe};
    }
  }

  return 0;
}

1;
