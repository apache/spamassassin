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

package Mail::SpamAssassin::Plugin::P595Body;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Plugin::BodyRuleBaseExtractor;

use strict;
use warnings;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my $class = shift;
  my $mailsaobject = shift;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  return $self;
}

###########################################################################

sub finish_parsing_end {
  my ($self, $params) = @_;
  my $conf = $params->{conf};

  my $main = $self->{main};
  $main->{base_extract} = 1;
  $main->{bases_must_be_casei} = 1;
  $main->{bases_can_use_alternations} = 0; # /(foo|bar|baz)/
  $main->{bases_can_use_quantifiers} = 0; # /foo.*bar/ or /foo*bar/ or /foooo?bar/
  $main->{bases_can_use_char_classes} = 0; # /fo[opqr]bar/
  $main->{bases_split_out_alternations} = 1; # /(foo|bar|baz)/ => ["foo", "bar", "baz"]

  my $ext_start = time;
  my $basextor = Mail::SpamAssassin::Plugin::BodyRuleBaseExtractor->new
			($self->{main});
  $basextor->extract_bases($conf);
  my $ext_dur = time - $ext_start;
  warn "base extraction took $ext_dur seconds\n";

  $conf->{skip_body_rules}   ||= { };
  $conf->{need_one_line_sub} ||= { };

  $self->setup_test_set ($conf, $conf->{body_tests}, 'body');
}

sub setup_test_set {
  my ($self, $conf, $test_set, $ruletype) = @_;
  foreach my $pri (keys %{$test_set}) {
    my $nicepri = $pri; $nicepri =~ s/-/neg/g;
    $self->setup_test_set_pri($conf, $test_set->{$pri}, $ruletype.'_'.$nicepri, $pri);
  }
}

sub setup_test_set_pri {
  my ($self, $conf, $rules, $ruletype, $pri) = @_;

  my $alternates = [];
  my $trie_rules = {};

  # while (my ($rule, $pat) = each %{$pms->{conf}->{body_tests}->{$priority}}) {
  # push @{$alternates}, $pat;
  # }

  foreach my $base (keys %{$conf->{base_string}->{$ruletype}})
  {
    push @{$alternates}, $base;
    my @rules = split(' ', $conf->{base_string}->{$ruletype}->{$base});
    $trie_rules->{$base} = \@rules;

    foreach my $rule (@rules) {
      # ignore rules marked for ReplaceTags work!
      # TODO: we should be able to order the 'finish_parsing_end'
      # plugin calls to do this.
      next if ($conf->{rules_to_replace}->{$rule});

      # TODO: need a cleaner way to do this.  I expect when rule types
      # are implementable in plugins, I can do it that way
      $conf->{skip_body_rules}->{$rule} = 1;

      # ensure that the one-liner version of the function call is
      # created, though
      $conf->{generate_body_one_line_sub}->{$rule} = 1;
    }
  }

  my $sub = '
    sub {
        our @matched = ();
        $_[0] =~ m#('.join('|', @{$alternates}).')(?{
            push @matched, $1;
          })(*FAIL)#i;
        return @matched;
      }
  ';
  # warn "JMD $sub";

  $conf->{$ruletype}->{trie_re_sub} = eval $sub;
  if ($@) { warn "trie sub compilation failed: $@"; }

  $conf->{$ruletype}->{trie_rules} = $trie_rules;
}

###########################################################################

sub run_body_hack {
  my ($self, $params) = @_;

  return unless ($params->{ruletype} eq 'body');

  my $pri = $params->{priority};
  my $nicepri = $params->{priority}; $nicepri =~ s/-/neg/g;
  my $ruletype = ($params->{ruletype}.'_'.$nicepri);
  my $scanner = $params->{permsgstatus};
  my $conf = $scanner->{conf};

  my $trie_re_sub = $conf->{$ruletype}->{trie_re_sub};
  my $trie_rules = $conf->{$ruletype}->{trie_rules};
  if (!$trie_re_sub || !$trie_rules)
  {
    dbg("zoom: run_body_hack for $ruletype skipped, no rules");
    return;
  }

  my $do_dbg = (would_log('dbg', 'zoom') > 1);
  my $scoresptr = $conf->{scores};

  dbg("zoom: run_body_hack for $ruletype start");

  {
    no strict "refs";
    foreach my $line (@{$params->{lines}})
    {
      my $sub = $trie_re_sub;
      my @caught = $sub->($line);
      next unless (scalar @caught > 0);

      my %alreadydone = ();
      foreach my $caught (@caught) {
        foreach my $rulename (@{$trie_rules->{$caught}})
        {
          # only try each rule once per line
          next if exists $alreadydone{$rulename};
          $alreadydone{$rulename} = undef;

          # ignore 0-scored rules, of course
          next unless $scoresptr->{$rulename};

          # dbg("zoom: base found for $rulename: $line");

          my $fn = 'Mail::SpamAssassin::Plugin::Check::'.
                                  $rulename.'_one_line_body_test';

          # run the real regexp -- on this line alone.
          if (!&{$fn} ($scanner, $line) && $do_dbg) {
            $self->{rule2xs_misses}->{$rulename}++;
          }
        }
      }
    }
    use strict "refs";
  }

  dbg("zoom: run_body_hack for $ruletype done");
}

sub finish {
  my ($self) = @_;

  my $do_dbg = (would_log('dbg', 'zoom') > 1);
  return unless $do_dbg;

  my $miss = $self->{rule2xs_misses};
  foreach my $r (sort { $miss->{$a} <=> $miss->{$b} } keys %{$miss}) {
    dbg "zoom: ".$miss->{$r}." misses for rule2xs rule $r\n";
  }
}

###########################################################################

1;
