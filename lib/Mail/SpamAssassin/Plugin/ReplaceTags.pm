# <@LICENSE>
# Copyright 2004 Apache Software Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
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

Warning: This plugin replies on data structures specific to this version of
SpamAssasin; it is not guaranteed to work with other versions of SpamAssassin.

=head1 SYNOPSIS

  loadplugin	Mail::SpamAssassin::Plugin::ReplaceTags

  replace_start	<
  replace_end	>

  replace_tag	A	[a@]
  replace_tag	G	[gk]
  replace_tag	I	[il\|\!1y\?\xcc\xcd\xce\xcf\xec\xed\xee\xef]
  replace_tag	R	[r3]
  replace_tag	V	(?:[vu]|\\\/)
  replace_tag	SP	[\s~_-]

  body		VIAGRA_OBFU	/(?!viagra)<V>+<SP>*<I>+<SP>*<A>+<SP>*<G>+<SP>*<R>+<SP>*<A>+/i
  describe	VIAGRA_OBFU	Attempt to obfuscate "viagra"

  replace_rules	VIAGRA_OBFU

=cut

package Mail::SpamAssassin::Plugin::ReplaceTags;

# Make the main dbg() accessible in our package w/o an extra function
*dbg=\&Mail::SpamAssassin::Plugin::dbg;
*info=\&Mail::SpamAssassin::Plugin::info;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;

use strict;
use warnings;
use bytes;

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

  my $start = $opts->{conf}->{replace_start};
  my $end = $opts->{conf}->{replace_end};

  # this is the version-specific code
  for my $type (qw|body_tests rawbody_tests head_tests full_tests uri_tests|) {
    for my $priority (keys %{$opts->{conf}->{$type}}) {
      while (my ($rule, $re) = each %{$opts->{conf}->{$type}->{$priority}}) {
	# skip if not listed by replace_rules
	next unless $opts->{conf}->{rules_to_replace}{$rule};

	if (Mail::SpamAssassin::dbg_check('+replacetags')) {
	  dbg("replacetags: replacing $rule: $re");
	}

	if ($re =~ s/${start}pre (.+?)${end}//) {
	  my $pre_name = $1;
	  if ($pre_name) {
	    my $pre = $opts->{conf}->{replace_pre}->{$pre_name};
	    if ($pre) {
	      $re =~ s|($start.+?$end)|$pre$1|g;
	    }
	  }
	}
	if ($re =~ s/${start}inter (.+?)${end}//) {
	  my $inter_name = $1;
	  if ($inter_name) {
	    my $inter = $opts->{conf}->{replace_inter}->{$inter_name};
	    if ($inter) {
	      $re =~ s|($start.+?$end)($start.+?$end)|$1$inter$2|g;
	    }
	  }
	}
	if ($re =~ s/${start}post (.+?)${end}//) {
	  my $post_name = $1;
	  if ($post_name) {
	    my $post = $opts->{conf}->{replace_post}->{$post_name};
	    if ($post) {
	      $re =~ s|($start.+?$end)|$1$post|g;
	    }
	  }
	}
	while ($re =~ m|$start(.+?)$end|g) {
	  my $tag_name = $1;

	  # if the tag exists, replace it with the corresponding phrase
	  if ($tag_name) {
	    my $replacement = $opts->{conf}->{replace_tag}->{$tag_name};
	    if ($replacement) {
	      $re =~ s|$start$tag_name$end|$replacement|g;
	    }
	  }
        }

	# do the actual replacement
	$opts->{conf}->{$type}->{$priority}->{$rule} = $re;

	if (Mail::SpamAssassin::dbg_check('+replacetags')) {
	  dbg("replacetags: replaced $rule: $re");
	}
      }
    }
  }

  dbg("replacetags: done replacing tags");
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds = ();

=head1 CONFIGURATION

=over 4

=item replace_tag tagname expression

Assign a valid regular expression to tagname.

Note: It is not recommended to put quantifiers inside the tag, it's better to
put them inside the rule itself for greater flexibility.

=cut

  push(@cmds, {
    setting => 'replace_tag',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
  });

=item replace_pre tagname expression

Assign a valid regular expression to tagname.  The expression will be
placed before each tag that is replaced.

=cut

  push(@cmds, {
    setting => 'replace_pre',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
  });

=item replace_inter tagname expression

Assign a valid regular expression to tagname.  The expression will be
placed between each two immediately adjacent tags that are replaced.

=cut

  push(@cmds, {
    setting => 'replace_inter',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
  });

=item replace_post tagname expression

Assign a valid regular expression to tagname.  The expression will be
placed after each tag that is replaced.

=cut

  push(@cmds, {
    setting => 'replace_post',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
  });

=item replace_rules list_of_tests

Specify a list of symbolic test names (separated by whitespace) of tests which
should be modified using replacement tags.  Only simple regular expression
body, header, uri, full, rawbody tests are supported.

=cut

  push(@cmds, {
    setting => 'replace_rules',
    code => sub {
      my ($self, $key, $value, $line) = @_;
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
    default => '<',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
  });

  push(@cmds, {
    setting => 'replace_end',
    default => '>',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
  });

  $conf->{parser}->register_commands(\@cmds);
}

1;
