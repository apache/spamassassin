# <@LICENSE>
# Copyright 2006 Apache Software Foundation
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

Mail::SpamAssassin::Plugin::BodyRuleBaseExtractor - extract "bases" from body ruleset

=head1 SYNOPSIS

This is a plugin to extract "base" strings from SpamAssassin 'body' rules,
suitable for use in Rule2XSBody rules or other parallel matching algorithms.

=cut

package Mail::SpamAssassin::Plugin::BodyRuleBaseExtractor;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util::Progress;

use strict;
use warnings;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

use constant DEBUG_RE_PARSING => 0;     # noisy!

# a few settings that control what kind of bases are output.

# treat all rules as lowercase for purposes of term extraction?
# $main->{bases_must_be_casei} = 1;
# $main->{bases_can_use_alternations} = 0; # /(foo|bar|baz)/
# $main->{bases_can_use_quantifiers} = 0; # /foo.*bar/ or /foo*bar/ or /foooo?bar/
# $main->{bases_can_use_char_classes} = 0; # /fo[opqr]bar/
# $main->{bases_split_out_alternations} = 1; # /(foo|bar|baz)/ => ["foo", "bar", "baz"]

# TODO: it would be nice to have a clean API to pass such settings
# through to plugins instead of hanging them off $main

###########################################################################

sub new {
  my $class = shift;
  my $mailsaobject = shift;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->{show_progress} = 1;           # default

  # $self->test(); exit;
  return $self;
}

###########################################################################

sub finish_parsing_end {
  my ($self, $params) = @_;
  my $conf = $params->{conf};
  $self->extract_bases($conf);
}

sub extract_bases {
  my ($self, $conf) = @_;

  my $main = $conf->{main};
  if (!$main->{base_extract}) { return; }

  info("base extraction starting.  this can take a while...");
  $self->extract_set($conf, $conf->{body_tests}, 'body');
}

sub extract_set {
  my ($self, $conf, $test_set, $ruletype) = @_;

  foreach my $pri (keys %{$test_set}) {
    my $nicepri = $pri; $nicepri =~ s/-/neg/g;
    $self->extract_set_pri($conf, $test_set->{$pri}, $ruletype.'_'.$nicepri);
  }
}

###########################################################################

sub extract_set_pri {
  my ($self, $conf, $rules, $ruletype) = @_;

  my @good_bases = ();
  my @failed = ();
  my $yes = 0;
  my $no = 0;

  my $start = time;
  $self->{main} = $conf->{main};	# for use in extract_hints()
  info ("extracting from rules of type $ruletype");

  # attempt to find good "base strings" (simplified regexp subsets) for each
  # regexp.  We try looking at the regexp from both ends, since there
  # may be a good long string of text at the end of the rule.

  # require this many chars in a base string for it to be viable
  my $min_chars = 3;

  my $count = 0;
  my $progress;

  $self->{show_progress} and $progress = Mail::SpamAssassin::Util::Progress->new({
                total => scalar keys %{$rules},
                itemtype => 'rules',
              });

  foreach my $name (keys %{$rules}) {
    my $rule = $rules->{$name};
    $self->{show_progress} and $progress->update(++$count);

    # ignore ReplaceTags rules
    # TODO: need cleaner way to do this
    next if ($conf->{rules_to_replace}->{$name});

    my ($qr, $mods) = $self->simplify_and_qr_regexp($rule);

    my @bases;
    eval {  # catch die()s
      @bases = $self->extract_hints($rule, $qr, $mods);
    };
    $@ and dbg("giving up on regexp: $@");

    # if any of the extracted hints in a set are too short, the entire
    # set is invalid; this is because each set of N hints represents just
    # 1 regexp.
    my $minlen;
    foreach my $str (@bases) {
      my $len = length $str;
      if ($len < $min_chars) { $minlen = undef; @bases = (); last; }
      elsif (!defined($minlen) || $len < $minlen) { $minlen = $len; }
    }

    if ($minlen && @bases) {
      # dbg("zoom: YES <base>$base</base> <origrule>$rule</origrule>");

      # figure out if we have e.g. ["foo", "foob", "foobar"]; in this
      # case, we only need to track ["foo"].
      my %subsumed = ();
      foreach my $base1 (@bases) {
        foreach my $base2 (@bases) {
          if ($base1 ne $base2 && $base1 =~ /\Q$base2\E/) {
            $subsumed{$base1} = 1; # base2 is inside base1; discard the longer
          }
        }
      }

      foreach my $base (@bases) {
        next if $subsumed{$base};
        push @good_bases, { base => $base, orig => $rule, name => $name };
      }
      $yes++;
    }
    else {
      dbg("zoom: NO $rule");
      push @failed, { orig => $rule };
      $no++;
    }
  }

  $self->{show_progress} and $progress->final();

  dbg ("$ruletype: found ".(scalar @good_bases).
        " usable base strings in ".
        "$yes rules, skipped $no rules");

  # NOTE: re2c will attempt to provide the longest pattern that matched; e.g.
  # ("food" =~ "foo" / "food") will return "food".  So therefore if a pattern
  # subsumes other patterns, we need to return hits for all of them.  We also
  # need to take care of the case where multiple regexps wind up sharing the
  # same base.   
  #
  # Another gotcha, an exception to the subsumption rule; if one pattern isn't
  # entirely subsumed (e.g. "food" =~ "foo" / "ood"), then they will be
  # returned as two hits, correctly.  So we only have to be smart about the
  # full-subsumption case; overlapping is taken care of for us, by re2c.
  #
  # TODO: there's a bug here.  Since the code in extract_hints() has been
  # modified to support more complex regexps, we can no longer simply assume
  # that if pattern A is not contained in pattern B, that means that pattern B
  # doesn't subsume it.  Consider, for example, A="foo*bar" and
  # B="morefobarry"; A is indeed subsumed by B, but we won't be able to test
  # that without running the A RE match itself somehow against B.
  # same issue remains with:
  #
  #   "foo?bar" / "fobar"
  #   "fo(?:o|oo|)bar" / "fobar"
  #   "fo(?:o|oo)?bar" / "fobar"
  #   "fo(?:o*|baz)bar" / "fobar"
  #   "(?:fo(?:o*|baz)bar|blargh)" / "fobar"
  #
  # it's worse with this:
  #
  #   "fo(?:o|oo|)bar" / "foo*bar"
  #
  # basically, this is impossible to compute without reimplementing most of
  # re2c, and it appears the re2c developers don't plan to offer this:
  # https://sourceforge.net/tracker/index.php?func=detail&aid=1540845&group_id=96864&atid=616203

  $conf->{base_orig}->{$ruletype} = { };
  $conf->{base_string}->{$ruletype} = { };

  $count = 0;
  $self->{show_progress} and $progress = Mail::SpamAssassin::Util::Progress->new({
                total => scalar @good_bases,
                itemtype => 'bases',
              });

  foreach my $set1 (@good_bases) {
    $self->{show_progress} and $progress->update(++$count);

    my $base1 = $set1->{base};
    my $orig1 = $set1->{orig};
    my $name1 = $set1->{name};
    next if ($base1 eq '' or $name1 eq '');

    $conf->{base_orig}->{$ruletype}->{$name1} = $orig1;

    foreach my $set2 (@good_bases) {
      next if ($set1 == $set2);

      my $base2 = $set2->{base};
      my $name2 = $set2->{name};

      # clobber exact dups; this can happen if a regexp outputs the 
      # same base string multiple times
      if ($orig1 eq $set2->{orig} &&
          $base1 eq $base2 &&
          $name1 eq $name2)
      {
        $set2->{name} = '';       # clobber
        $set2->{base} = '';
      }

      # skip if either already contains the other rule's name
      next if ($name1 =~ /\b\Q$name2\E\b/);
      next if ($name2 =~ /\b\Q$name1\E\b/);

      next if ($base2 eq '');
      next if (length $base1 < length $base2);
      next if ($base1 !~ /\Q$base2\E/);

      $set1->{name} .= " ".$name2;

      # base2 is just a subset of base1
      # dbg("zoom: subsuming '$base2' into '$base1': $set1->{name}");
    }
  }

  # we can still have duplicate cases; __FRAUD_PTS and __SARE_FRAUD_BADTHINGS
  # both contain "killed" for example, pointing at different rules, which
  # the above search hasn't found.  Collapse them here with a hash
  my %bases = ();
  foreach my $set (@good_bases) {
    my $base = $set->{base};
    next unless $base;
    if (defined $bases{$base}) {
      $bases{$base} .= " ".$set->{name};
    } else {
      $bases{$base} = $set->{name};
    }
  }

  foreach my $base (keys %bases) {
    # uniq the list, since there are probably dup rules listed
    my @list = split (' ', $bases{$base});
    my @uniqed;

    {
      my %u=(); @uniqed = grep {defined} map {
        if (exists $u{$_}) { undef; } else { $u{$_}=undef;$_; }
      } @list; undef %u;
    }

    my $key  = join ' ', sort @uniqed;
    $conf->{base_string}->{$ruletype}->{$base} = $key;
  }
  $self->{show_progress} and $progress->final();

  my $elapsed = time - $start;
  info ("$ruletype: ".
            (scalar keys %{$conf->{base_string}->{$ruletype}}).
            " base strings extracted in $elapsed seconds\n");
}

###########################################################################

# TODO:
# NO /no.{1,10}P(?:er|re)scription.{1,10}(?:needed|require|necessary)/i
#     => should extract 'scription' somehow
# /time to refinance|refinanc\w{1,3}\b.{0,16}\bnow\b/i
#     => should understand alternations; tricky

sub simplify_and_qr_regexp {
  my $self = shift;
  my $rule = shift;

  my $main = $self->{main};
  $rule = Mail::SpamAssassin::Util::regexp_remove_delimiters($rule);

  # remove the regexp modifiers, keep for later
  my $mods = '';
  while ($rule =~ s/^\(\?([a-z]*)\)//) { $mods .= $1; }

  # modifier removal
  while ($rule =~ s/^\(\?-([a-z]*)\)//) {
    foreach my $modchar (split '', $mods) {
      $mods =~ s/$modchar//g;
    }
  }

  # now: simplify aspects of the regexp.  Bear in mind that we can
  # simplify as long as we cause the regexp to become more general;
  # more hits is OK, since false positives will be discarded afterwards
  # anyway.  Simplification that causes the regexp to *not* hit
  # stuff that the "real" rule would hit, however, is a bad thing.

  if ($main->{bases_must_be_casei}) {
    $rule = lc $rule;
    $mods =~ s/i//;

    # always case-i: /A(?i:ct) N(?i:ow)/ => /Act Now/
    $rule =~ s/(?<!\\)\(\?i\:(.*?)\)/$1/gs;

    # always case-i: /A(?-i:ct)/ => /Act/
    $rule =~ s/(?<!\\)\(\?-i\:(.*?)\)/$1/gs;

    # remove (?i)
    $rule =~ s/\(\?i\)//gs;
  }
  else {
    die "case-i" if $rule =~ /\(\?i\)/;
    die "case-i" if $mods =~ /i/;
  }

  # remove /m and /s modifiers
  $mods =~ s/m//;
  $mods =~ s/s//;

  # remove (^|\b)'s
  # T_KAM_STOCKTIP23 /(EXTREME INNOVATIONS|(^|\b)EXTI($|\b))/is
  $rule =~ s/\(\^\|\\b\)//gs;
  $rule =~ s/\(\$\|\\b\)//gs;
  $rule =~ s/\(\\b\|\^\)//gs;
  $rule =~ s/\(\\b\|\$\)//gs;

  # remove (?!credit)
  $rule =~ s/\(\?\![^\)]+\)//gs;

  # remove \b's
  $rule =~ s/(?<!\\)\\b//gs;

  # remove the "?=" trick
  # (?=[dehklnswxy])(horny|nasty|hot|wild|young|....etc...)
  $rule =~ s/\(\?\=\[[^\]]+\]\)//gs;
  ($rule, $mods);
}

sub extract_hints {
  my $self = shift;
  my $rawrule = shift;
  my $rule = shift;
  my $mods = shift;

  my $main = $self->{main};
  my $orig = $rule;

  # if there are anchors, give up; we can't get much 
  # faster than these anyway
  die "anchors" if $rule =~ /^\(?(?:\^|\\A)/;

  # die "anchors" if $rule =~ /(?:\$|\\Z)\)?$/;
  # just remove end-of-string anchors; they're slow so could gain
  # from our speedup
  $rule =~ s/(?<!\\)(?:\$|\\Z)\)?$//;

  # simplify (?:..) to (..)
  $main->{bases_allow_noncapture_groups} or
            $rule =~ s/\(\?:/\(/g;

  # simplify some grouping arrangements so they're easier for us to parse
  # (foo)? => (foo|)
  $rule =~ s/\((.*?)\)\?/\($1\|\)/gs;
  # r? => (r|)
  $rule =~ s/(?<!\\)(\w)\?/\($1\|\)/gs;

  my ($tmpf, $tmpfh) = Mail::SpamAssassin::Util::secure_tmpfile();

  # attempt to find a safe regexp delimiter...
  # TODO: would prob be easier to just read this from $rawrule
  my $quos = "/"; if ($rule =~ m/\Q${quos}\E/) {
    $quos = "#"; if ($rule =~ m/\Q${quos}\E/) {
      $quos = "'"; if ($rule =~ m/\Q${quos}\E/) {
        $quos = "@"; if ($rule =~ m/\Q${quos}\E/) {
          $quos = "*"; if ($rule =~ m/\Q${quos}\E/) {
            $quos = "!";
          }
        }
      }
    }
  }
  print $tmpfh "m".$quos.$rule.$quos.$mods;
  close $tmpfh or die "cannot write to $tmpf";

  my $perl = $self->get_perl();
  open (IN, "$perl -c -Mre=debug $tmpf 2>&1 |") or die "cannot run $perl";
  my $fullstr = join('', <IN>);
  close IN;
  unlink $tmpf;

  # now parse the -Mre=debug output.
  # perl 5.10 format
  $fullstr =~ s/^.*\nFinal program:\n//gs;
  # perl 5.6/5.8 format
  $fullstr =~ s/^(?:.*\n|)size \d[^\n]*\n//gs;
  $fullstr =~ s/^(?:.*\n|)first at \d[^\n]*\n//gs;
  # common to all
  $fullstr =~ s/\nOffsets:.*$//gs;

  # clean up every other line that doesn't start with a space
  $fullstr =~ s/^\S.*$//gm;

  if ($fullstr !~ /((?:\s[^\n]+\n)+)/m) {
    die "failed to parse Mre=debug output: $fullstr m".$quos.$rule.$quos.$mods." $rawrule";
  }
  my $opsstr = $1;

  # what's left looks like this:
  #    1: EXACTF <v>(3)
  #    3: ANYOF[1ILil](14)
  #   14: EXACTF <a>(16)
  #   16: CURLY {2,7}(29)
  #   18:   ANYOF[A-Za-z](0)
  #   29: SPACE(30)
  #   30: EXACTF <http://>(33)
  #   33: END(0)
  #
  DEBUG_RE_PARSING and warn "Mre=debug output: $opsstr";

  my @ops = ();
  foreach my $op (split(/\n/s, $opsstr)) {
    next unless $op;
    if ($op =~ /^\s+\d+: (\s*)([A-Z]\w+)\b(.*)(?:\(\d+\))?$/) {
      push @ops, [ $1, $2, $3 ];
    }
    elsif ($op =~ /^      (\s*)<(.*)>\.\.\.\s*$/) {
      #    5:   TRIE-EXACT[im](44)
      #         <message contained attachments that have been blocked by guin>...
      my $spcs = $1;
      # we could use the entire length here, but it's easier to trim to
      # the length of a perl 5.8.x/5.6.x EXACT* string; that way our test
      # suite results will match, since the sa-update --list extraction will
      # be the same for all versions.  (The "..." trailer is important btw)
      my $str = substr ($2, 0, 55);
      push @ops, [ $spcs, '_moretrie', "<$str...>" ];
    }
    elsif ($op =~ /^      (\s*)(<.*>)\s*(?:\(\d+\))?$/) {
      #    5:   TRIE-EXACT[am](21)
      #         <am> (21)
      #         <might> (12)
      push @ops, [ $1, '_moretrie', $2 ];
    }
    elsif ($op =~ /^ at .+ line \d+$/) {
      next; # ' at /local/perl561/lib/5.6.1/i86pc-solaris/re.pm line 109': 
    }
    else {
      warn "cannot parse '$op': $opsstr";
      next;
    }
  }

  # unroll the branches; returns a list of versions.
  # e.g. /foo(bar|baz)argh/ => [ "foobarargh", "foobazargh" ]
  my @unrolled;
  if ($main->{bases_split_out_alternations}) {
    @unrolled = $self->unroll_branches(0, \@ops);
  } else {
    @unrolled = ( \@ops );
  }

  # now find the longest DFA-friendly string in each unrolled version
  my @longests = ();
  foreach my $opsarray (@unrolled) {
    my $longestexact = '';
    my $buf = '';

    # use a closure to keep the code succinct
    my $add_candidate = sub {
      if (length $buf > length $longestexact) { $longestexact = $buf; }
      $buf = '';
    };

    my $prevop;
    foreach my $op (@{$opsarray}) {
      my ($spcs, $item, $args) = @{$op};

      next if ($item eq 'NOTHING');

      # EXACT == case-sensitive
      # EXACTF == case-i
      # we can do both, since we canonicalize to lc.
      if (!$spcs && $item =~ /^EXACT/ && $args =~ /<(.*)>/)
      {
        $buf .= $1;
        if (length $1 >= 55 && $buf =~ s/\.\.\.$//) {
          # perl 5.8.x truncates with a "..." here!  cut and stop
          $add_candidate->();
        }
      }
      # _moretrie == a TRIE-EXACT entry
      elsif (!$spcs && $item =~ /^_moretrie/ && $args =~ /<(.*)>/)
      {
        $buf .= $1;
        if (length $1 >= 55 && $buf =~ s/\.\.\.$//) {
          # perl 5.8.x truncates with a "..." here!  cut and stop
          $add_candidate->();
        }
      }
      # /(?:foo|bar|baz){2}/ results in a CURLYX beforehand
      elsif ($item =~ /^EXACT/ &&
          $prevop && !$prevop->[0] && $prevop->[1] =~ /^CURLYX/ &&
                    $prevop->[2] =~ /\{(\d+),/ && $1 >= 1 &&
          $args =~ /<(.*)>/)
      {
        $buf .= $1;
        if (length $1 >= 55 && $buf =~ s/\.\.\.$//) {
          # perl 5.8.x truncates with a "..." here!  cut and stop
          $add_candidate->();
        }
      }
      # CURLYX, for perl >= 5.9.5
      elsif ($item =~ /^_moretrie/ &&
          $prevop && !$prevop->[0] && $prevop->[1] =~ /^CURLYX/ &&
                    $prevop->[2] =~ /\{(\d+),/ && $1 >= 1 &&
          $args =~ /<(.*)>/)
      {
        $buf .= $1;
        if (length $1 >= 60 && $buf =~ s/\.\.\.$//) {
          # perl 5.8.x truncates with a "..." here!  cut and stop
          $add_candidate->();
        }
      }
      else {
        # not an /^EXACT/; clear the buffer
        $add_candidate->();
      }
      $prevop = $op;
    }
    $add_candidate->();

    if (!$longestexact) {
      die "no long-enough string found in $rawrule";
      # all unrolled versions must have a long string, otherwise
      # we cannot reliably match all variants of the rule
    } else {
      push @longests, lc $longestexact;
    }
  }

  DEBUG_RE_PARSING and warn "longest base strings: /".join("/", @longests)."/";
  return @longests;
}

###########################################################################

sub unroll_branches {
  my ($self, $depth, $opslist) = @_;

  die "too deep" if ($depth++ > 5);

  my @ops = (@{$opslist});      # copy
  my @pre_branch_ops = ();
  my $branch_spcs;
  my $trie_spcs;
  my $open_spcs;

# our input looks something like this 2-level structure:
#  1: BOUND(2)
#  2: EXACT <Dear >(5)
#  5: BRANCH(9)
#  6:   EXACT <IT>(8)
#  8:   NALNUM(24)
#  9: BRANCH(23)
# 10:   EXACT <Int>(12)
# 12:   BRANCH(14)
# 13:     NOTHING(21)
# 14:   BRANCH(17)
# 15:     EXACT <a>(21)
# 17:   BRANCH(20)
# 18:     EXACT <er>(21)
# 20:   TAIL(21)
# 21:   EXACT <net>(24)
# 23: TAIL(24)
# 24: EXACT < shop>(27)
# 27: END(0)
#
# or:
#
#  1: OPEN1(3)
#  3:   BRANCH(6)
#  4:     EXACT <v>(9)
#  6:   BRANCH(9)
#  7:     EXACT <\\/>(9)
#  9: CLOSE1(11)
# 11: CURLY {2,5}(14)
# 13:   REG_ANY(0)
# 14: EXACT < g r a >(17)
# 17: ANYOF[a-z](28)
# 28: END(0)
#
# or:
#
#  1: EXACT <i >(3)
#  3: OPEN1(5)
#  5:   TRIE-EXACT[am](21)
#       <am> (21)
#       <might> (12)
# 12:     OPEN2(14)
# 14:       TRIE-EXACT[ ](19)
#           < be>
#           <>
# 19:     CLOSE2(21)
# 21: CLOSE1(23)
# 23: EXACT < c>(25)

  DEBUG_RE_PARSING and warn "starting parse";

  # this happens for /foo|bar/ instead of /(?:foo|bar)/ ; transform
  # it into the latter.  bit of a kludge to do this before the loop, but hey.
  # note that it doesn't fix the CLOSE1/END ordering to be correct
  if (scalar @ops > 1 && $ops[0]->[1] =~ /^BRANCH/) {
    my @newops = ([ "", "OPEN1", "" ]);
    foreach my $op (@ops) {
      push @newops, [ "  ".$op->[0], $op->[1], $op->[2] ];
    }
    push @newops, [ "", "CLOSE1", "" ];
    @ops = @newops;
  }

  # iterate until we start a branch set. using
  # /dkjfksl(foo|bar(baz|argh)boo)gab/ as an example, we're at "dkj..."
  # just hitting an OPEN is not enough; wait until we see a TRIE-EXACT
  # or a BRANCH, *then* unroll the most recent OPEN set.
  while (1) {
    my $op = shift @ops;
    last unless defined $op;

    my ($spcs, $item, $args) = @{$op};
    DEBUG_RE_PARSING and warn "pre: [$spcs] $item $args";

    if ($item =~ /^OPEN/) {
      $open_spcs = $spcs;
      next;         # next will be a BRANCH or TRIE

    } elsif ($item =~ /^TRIE/) {
      $trie_spcs = $spcs;
      last;

    } elsif ($item =~ /^BRANCH/) {
      $branch_spcs = $spcs;
      last;

    } elsif ($item =~ /^EXACT/ && defined $open_spcs) {
      # perl 5.9.5 does this; f(o|oish) => OPEN, EXACT, TRIE-EXACT
      push @pre_branch_ops, [ $open_spcs, $item, $args ];
      next;

    } elsif (defined $open_spcs) {
      # OPEN not followed immediately by BRANCH, EXACT or TRIE-EXACT:
      # ignore this OPEN block entirely and don't try to unroll it
      undef $open_spcs;

    } else {
      push @pre_branch_ops, $op;
    }
  }

  # no branches found?  we're done unrolling on this one!
  if (scalar @ops == 0) {
    return [ @pre_branch_ops ];
  }

  # otherwise we're at the start of a new branch set
  # /(foo|bar(baz|argh)boo)gab/
  my @alts = ();
  my @in_this_branch = ();

  DEBUG_RE_PARSING and warn "entering branch: ".
        "open='".(defined $open_spcs ? $open_spcs : 'undef')."' ".
        "branch='".(defined $branch_spcs ? $branch_spcs : 'undef')."' ".
        "trie='".(defined $trie_spcs ? $trie_spcs : 'undef')."'";

  # indentation level to remove from "normal" ops (using a s///)
  my $open_sub_spcs = ($branch_spcs ? $branch_spcs : "")."  ";
  my $trie_sub_spcs = "";
  while (1) {
    my $op = shift @ops;
    last unless defined $op;
    my ($spcs, $item, $args) = @{$op};
    DEBUG_RE_PARSING and warn "in:  [$spcs] $item $args";

    if (defined $branch_spcs && $branch_spcs eq $spcs && $item =~ /^BRANCH/) {  # alt
      push @alts, [ @pre_branch_ops, @in_this_branch ];
      @in_this_branch = ();
      $open_sub_spcs = $branch_spcs."  ";
      $trie_sub_spcs = "";
      next;
    }
    elsif (defined $branch_spcs && $branch_spcs eq $spcs && $item eq 'TAIL') { # end
      push @alts, [ @pre_branch_ops, @in_this_branch ];
      undef $branch_spcs;
      $open_sub_spcs = "";
      $trie_sub_spcs = "";
      last;
    }
    elsif (defined $trie_spcs && $trie_spcs eq $spcs && $item eq '_moretrie') {
      if (scalar @in_this_branch > 0) {
        push @alts, [ @pre_branch_ops, @in_this_branch ];
      }
      # use $open_spcs instead of $trie_spcs (which is 2 spcs further indented)
      @in_this_branch = ( [ $open_spcs, $item, $args ] );
      $open_sub_spcs = ($branch_spcs ? $branch_spcs : "")."  ";
      $trie_sub_spcs = "  ";
      next;
    }
    elsif (defined $open_spcs && $open_spcs eq $spcs && $item =~ /^CLOSE/) {   # end
      push @alts, [ @pre_branch_ops, @in_this_branch ];
      undef $branch_spcs;
      undef $open_spcs;
      undef $trie_spcs;
      $open_sub_spcs = "";
      $trie_sub_spcs = "";
      last;
    }
    elsif ($item eq 'END') {  # of string
      push @alts, [ @pre_branch_ops, @in_this_branch ];
      undef $branch_spcs;
      undef $open_spcs;
      undef $trie_spcs;
      $open_sub_spcs = "";
      $trie_sub_spcs = "";
      last;
    }
    else {
      if ($open_sub_spcs) {
        # deindent the space-level to match the opening brace
        $spcs =~ s/^$open_sub_spcs//;
        # tries also add one more indent level in
        $spcs =~ s/^$trie_sub_spcs//;
      }
      push @in_this_branch, [ $spcs, $item, $args ];
      # note that we ignore ops at a deeper $spcs level entirely (until later!)
    }
  }

  if (defined $branch_spcs) {
    die "fell off end of string with a branch open: '$branch_spcs'";
  }

  # we're now after the branch set: /gab/
  # @alts looks like [ /dkjfkslfoo/ , /dkjfkslbar(baz|argh)boo/ ]
  foreach my $alt (@alts) {
    push @{$alt}, @ops;     # add all remaining ops to each one
    # note that this could include more (?:...); we don't care, since
    # those can be handled by recursing
  }

  # ok, parsed the entire ops list
  # @alts looks like [ /dkjfkslfoogab/ , /dkjfkslbar(baz|argh)boogab/ ]

  if (DEBUG_RE_PARSING) {
    print "unrolled: "; foreach my $alt (@alts) { foreach my $o (@{$alt}) { print "{/$o->[0]/$o->[1]/$o->[2]} "; } print "\n"; }
  }

  # now recurse, to unroll the remaining branches (if any exist)
  my @rets = ();
  foreach my $alt (@alts) {
    push @rets, $self->unroll_branches($depth, $alt);
  }

  if (DEBUG_RE_PARSING) {
    print "unrolled post-recurse: "; foreach my $alt (@rets) { foreach my $o (@{$alt}) { print "{/$o->[0]/$o->[1]/$o->[2]} "; } print "\n"; }
  }

  return @rets;
}

###########################################################################

sub test {
  my ($self) = @_;

  $self->test_split_alt("foo", "/foo/");
  $self->test_split_alt("(foo)", "/foo/");
  $self->test_split_alt("foo(bar)baz", "/foobarbaz/");
  $self->test_split_alt("x(foo|)", "/xfoo/ /x/");
  $self->test_split_alt("fo(o|)", "/foo/ /fo/");
  $self->test_split_alt("(foo|bar)", "/foo/ /bar/");
  $self->test_split_alt("foo|bar", "/foo/ /bar/");
  $self->test_split_alt("foo (bar|baz) argh", "/foo bar argh/ /foo baz argh/");
  $self->test_split_alt("foo (bar|baz|bl(arg|at)) cough", "/foo bar cough/ /foo baz cough/ /foo blarg cough/ /foo blat cough/");
  $self->test_split_alt("(s(otc|tco)k)", "/sotck/ /stcok/");
  $self->test_split_alt("(business partner(s|ship|)|silent partner(s|ship|))", "/business partners/ /silent partners/ /business partnership/ /silent partnership/ /business partner/ /silent partner/");
}

sub test_split_alt {
  my ($self, $in, $out) = @_;

  my @got = $self->split_alt($in);
  $out =~ s/^\///;
  $out =~ s/\/$//;
  my @want = split(/\/ \//, $out);

  my $failed = 0;
  if (scalar @want != scalar @got) {
    warn "FAIL: results count don't match";
    $failed++;
  }
  else {
    my %got = map { $_ => 1 } @got;
    foreach my $w (@want) {
      if (!$got{$w}) {
        warn "FAIL: '$w' not found";
        $failed++;
      }
    }
  }

  if ($failed) {
    print "want: /".join('/ /', @want)."/\n";
    print "got:  /".join('/ /', @got)."/\n";
    return 0;
  } else {
    print "ok\n";
    return 1;
  }
}

###########################################################################

sub get_perl {
  my ($self) = @_;
  my $perl;

  # allow user override of the perl interpreter to use when
  # extracting base strings.
  # TODO: expose this via sa-compile command-line option
  my $fromconf = $self->{main}->{conf}->{re_parser_perl};

  if ($fromconf) {
    $perl = $fromconf;
  } elsif ($^X =~ m|^/|) {
    $perl = $^X;
  } else {
    use Config;
    $perl = $Config{perlpath};
    $perl =~ s|/[^/]*$|/$^X|;
  }
  $perl =~ /^(.*)$/;
  return $1;
}

###########################################################################

1;
