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

Mail::SpamAssassin::Plugin::ReplaceTags - tags for SpamAssassin rules

The plugin allows rules to contain regular expression tags to be used in
regular expression rules.  The tags make it much easier to maintain
complicated rules.

Warning: This plugin relies on data structures specific to this version of
SpamAssasin; it is not guaranteed to work with other versions of SpamAssassin.

=head1 SYNOPSIS

  loadplugin	Mail::SpamAssassin::Plugin::ReplaceTags

  replace_start	<
  replace_end	>

  replace_tag	A	[a@]
  replace_tag	G	[gk]
  replace_tag	I	[il|!1y\?\xcc\xcd\xce\xcf\xec\xed\xee\xef]
  replace_tag	R	[r3]
  replace_tag	V	(?:[vu]|\\\/)
  replace_tag	SP	[\s~_-]

  body		VIAGRA_OBFU	/(?!viagra)<V>+<SP>*<I>+<SP>*<A>+<SP>*<G>+<SP>*<R>+<SP>*<A>+/i
  describe	VIAGRA_OBFU	Attempt to obfuscate "viagra"

  replace_rules	VIAGRA_OBFU

=cut

package Mail::SpamAssassin::Plugin::ReplaceTags;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;

use strict;
use warnings;
use bytes;
use re 'taint';

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my ($class, $mailsa) = @_;
  $class = ref($class) || $class;

  my $self = $class->SUPER::new($mailsa);

  bless ($self, $class);

  $self->set_config($mailsa->{conf});

  return $self;
}

sub finish_parsing_end {
  my ($self, $opts) = @_;

  dbg("replacetags: replacing tags");

  my $conf = $opts->{conf};
  my $start = $conf->{replace_start};
  my $end = $conf->{replace_end};

  # this is the version-specific code
  for my $type (qw|body_tests rawbody_tests head_tests full_tests uri_tests|) {
    for my $priority (keys %{$conf->{$type}}) {
      while (my ($rule, $re) = each %{$conf->{$type}->{$priority}}) {
        # skip if not listed by replace_rules
        next unless $conf->{rules_to_replace}{$rule};

        if (would_log('dbg', 'replacetags') > 1) {
          dbg("replacetags: replacing $rule: $re");
        }

        my $passes = 0;
        my $doagain;

        do {
          my $pre_name;
          my $post_name;
          my $inter_name;
          $doagain = 0;

          # get modifier tags
          if ($re =~ s/${start}pre (.+?)${end}//) {
            $pre_name = $1;
          }
          if ($re =~ s/${start}post (.+?)${end}//) {
            $post_name = $1;
          }
          if ($re =~ s/${start}inter (.+?)${end}//) {
            $inter_name = $1;
          }

          # this will produce an array of tags to be replaced
          # for two adjacent tags, an element of "" will be between the two
          my @re = split(/(<[^<>]+>)/, $re);

          if ($pre_name) {
            my $pre = $conf->{replace_pre}->{$pre_name};
            if ($pre) {
              s{($start.+?$end)}{$pre$1}  for @re;
            }
          }
          if ($post_name) {
            my $post = $conf->{replace_post}->{$post_name};
            if ($post) {
              s{($start.+?$end)}{$1$post}g  for @re;
            }
          }
          if ($inter_name) {
            my $inter = $conf->{replace_inter}->{$inter_name};
            if ($inter) {
              s{^$}{$inter}  for @re;
            }
          }
          for (my $i = 0; $i < @re; $i++) {
            if ($re[$i] =~ m|$start(.+?)$end|g) {
              my $tag_name = $1;
              # if the tag exists, replace it with the corresponding phrase
              if ($tag_name) {
                my $replacement = $conf->{replace_tag}->{$tag_name};
                if ($replacement) {
                  $re[$i] =~ s|$start$tag_name$end|$replacement|g;
                  $doagain = 1 if !$doagain && $replacement =~ /<[^>]+>/;
                }
              }
            }
          }

          $re = join('', @re);

          # do the actual replacement
          $conf->{$type}->{$priority}->{$rule} = $re;

          if (would_log('dbg', 'replacetags') > 1) {
            dbg("replacetags: replaced $rule: $re");
          }

          $passes++;
        } while $doagain && $passes <= 5;
      }
    }
  }

  # free this up, if possible
  if (!$conf->{allow_user_rules}) {
    delete $conf->{rules_to_replace};
  }

  dbg("replacetags: done replacing tags");
}

sub user_conf_parsing_end {
  my ($self, $opts) = @_;
  return $self->finish_parsing_end($opts);
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

=head1 RULE DEFINITIONS AND PRIVILEGED SETTINGS

=over 4

=item replace_tag tagname expression

Assign a valid regular expression to tagname.

Note: It is not recommended to put quantifiers inside the tag, it's better to
put them inside the rule itself for greater flexibility.

=cut

  push(@cmds, {
    setting => 'replace_tag',
    is_priv => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
  });

=item replace_pre tagname expression

Assign a valid regular expression to tagname.  The expression will be
placed before each tag that is replaced.

=cut

  push(@cmds, {
    setting => 'replace_pre',
    is_priv => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
  });

=item replace_inter tagname expression

Assign a valid regular expression to tagname.  The expression will be
placed between each two immediately adjacent tags that are replaced.

=cut

  push(@cmds, {
    setting => 'replace_inter',
    is_priv => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
  });

=item replace_post tagname expression

Assign a valid regular expression to tagname.  The expression will be
placed after each tag that is replaced.

=cut

  push(@cmds, {
    setting => 'replace_post',
    is_priv => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
  });

=item replace_rules list_of_tests

Specify a list of symbolic test names (separated by whitespace) of tests which
should be modified using replacement tags.  Only simple regular expression
body, header, uri, full, rawbody tests are supported.

=cut

  push(@cmds, {
    setting => 'replace_rules',
    is_priv => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /\S+/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      foreach my $rule (split(' ', $value)) {
        $conf->{rules_to_replace}->{$rule} = 1;
      }
    }
  });

=item replace_start string

=item replace_end string

String(s) which indicate the start and end of a tag inside a rule.  Only tags
enclosed by the start and end strings are found and replaced.

=cut

  push(@cmds, {
    setting => 'replace_start',
    is_priv => 1,
    default => '<',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
  });

  push(@cmds, {
    setting => 'replace_end',
    is_priv => 1,
    default => '>',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
  });

  $conf->{parser}->register_commands(\@cmds);
}

1;

=back

=cut
