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
use Mail::SpamAssassin::Util qw(untaint_var qr_to_string);
use Mail::SpamAssassin::Util::Progress;

use Errno qw(ENOENT EACCES EEXIST);
use Data::Dumper;

use strict;
use warnings;
# use bytes;
use re 'taint';

# Not a constant hashref for 5.6 compat
use constant SLOT_BASE => 0;
use constant SLOT_NAME => 1;
use constant SLOT_ORIG => 2;
use constant SLOT_LEN_BASE => 3;
use constant SLOT_BASE_INITIAL => 4;
use constant SLOT_HAS_MULTIPLE => 5;

use constant CLOBBER => '';

our @ISA = qw(Mail::SpamAssassin::Plugin);

use constant DEBUG_RE_PARSING => 0;     # noisy!

# a few settings that control what kind of bases are output.

# treat all rules as lowercase for purposes of term extraction?
# $main->{bases_must_be_casei} = 1;
# $main->{bases_can_use_alternations} = 0; # /(foo|bar|baz)/
# $main->{bases_can_use_quantifiers} = 0; # /foo.*bar/ or /foo*bar/ or /foooo?bar/
# $main->{bases_can_use_char_classes} = 0; # /fo[opqr]bar/
# $main->{bases_split_out_alternations} = 1; # /(foo|bar|baz)/ => ["foo", "bar", "baz"]
# $main->{base_quiet} = 0;      # silences progress output

# TODO: it would be nice to have a clean API to pass such settings
# through to plugins instead of hanging them off $main

##############################################################################

# testing purposes only
my $fixup_re_test;
#$fixup_re_test = 1; fixup_re("fr()|\\\\|"); die;
#$fixup_re_test = 1; fixup_re("\\x{1b}\$b"); die;
#$fixup_re_test = 1; fixup_re("\\33\$b"); die;
#$fixup_re_test = 1; fixup_re("[link]"); die;
#$fixup_re_test = 1; fixup_re("please do not resend your original message."); die;

###########################################################################

sub new {
  my $class = shift;
  my $mailsaobject = shift;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->{show_progress} = !$mailsaobject->{base_quiet};

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

  $self->{show_progress} and
        info("base extraction starting.  this can take a while...");

  $self->extract_set($conf, $conf->{body_tests}, 'body');
}

sub extract_set {
  my ($self, $conf, $test_set, $ruletype) = @_;

  foreach my $pri (keys %{$test_set}) {
    my $nicepri = $pri; $nicepri =~ s/-/neg/g;
    $self->extract_set_pri($conf, $test_set->{$pri}, $ruletype.'_'.$nicepri);
  }

  # Clear extract_hints tmpfile
  if ($self->{tmpf}) {
    unlink $self->{tmpf};
    delete $self->{tmpf};
  }
}

###########################################################################

sub extract_set_pri {
  my ($self, $conf, $rules, $ruletype) = @_;

  my @good_bases;
  my @failed;
  my $yes = 0;
  my $no = 0;
  my $count = 0;
  my $start = time;
  $self->{main} = $conf->{main};	# for use in extract_hints()
  $self->{show_progress} and info ("extracting from rules of type $ruletype");
  my $tflags = $conf->{tflags};

  # attempt to find good "base strings" (simplified regexp subsets) for each
  # regexp.  We try looking at the regexp from both ends, since there
  # may be a good long string of text at the end of the rule.

  # require this many chars in a base string + delimiters for it to be viable
  my $min_chars = 5;

  my $progress;
  $self->{show_progress} and $progress = Mail::SpamAssassin::Util::Progress->new({
                total => (scalar keys %{$rules} || 1),
                itemtype => 'rules',
              });

  my $cached = { };
  my $cachefile;

  if ($self->{main}->{bases_cache_dir}) {
    $cachefile = $self->{main}->{bases_cache_dir}."/rules.$ruletype";
    dbg("zoom: reading cache file $cachefile");
    $cached = $self->read_cachefile($cachefile);
  }

NEXT_RULE:
  foreach my $name (keys %{$rules}) {
    $self->{show_progress} and $progress and $progress->update(++$count);

    #my $rule = $rules->{$name};
    my $rule = qr_to_string($conf->{test_qrs}->{$name});
    if (!defined $rule) {
      die "zoom: error: regexp for $rule not found\n";
    }
    my $cachekey = $name.'#'.$rule;

    my $cent = $cached->{rule_bases}->{$cachekey};
    if (defined $cent) {
      if (defined $cent->{g}) {
        dbg("zoom: YES (cached) $rule $name");
        foreach my $ent (@{$cent->{g}}) {
          # note: we have to copy these, since otherwise later
          # modifications corrupt the cached data
          push @good_bases, {
            base => $ent->{base}, orig => $ent->{orig}, name => $ent->{name}
          };
        }
        $yes++;
      }
      else {
        dbg("zoom: NO (cached) $rule $name");
        push @failed, { orig => $rule };    # no need to cache this
        $no++;
      }
      next NEXT_RULE;
    }

    # ignore ReplaceTags rules, and regex capture template rules
    my $is_a_replace_rule = $conf->{replace_rules}->{$name} ||
                            $conf->{capture_rules}->{$name} ||
                            $conf->{capture_template_rules}->{$name};
    my ($minlen, $lossy, @bases);

    if (!$is_a_replace_rule) {
      eval {  # catch die()s
        my ($qr, $mods) = $self->simplify_and_qr_regexp($rule);
        ($lossy, @bases) = $self->extract_hints($rule, $qr, $mods);
      # dbg("zoom: %s %s -> %s", $name, $rule, join(", ", @bases));
        1;
      } or do {
        my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
        $eval_stat =~ s/ at .*//s;
        dbg("zoom: giving up on regexp: $eval_stat");
      };

      #if ($lossy && ($tflags->{$name}||'') =~ /\bmultiple\b/) {
      #  warn "\nzoom: $vers rule $name will loop on SpamAssassin older than 3.3.2 ".
      #       "running under Perl 5.12 or older, Bug 6558\n";
      #}

      # if any of the extracted hints in a set are too short, the entire
      # set is invalid; this is because each set of N hints represents just
      # 1 regexp.
      foreach my $str (@bases) {
        my $len = length fixup_re($str); # bug 6143: count decoded characters
        if ($len < $min_chars) { $minlen = undef; @bases = (); last; }
        elsif (!defined($minlen) || $len < $minlen) { $minlen = $len; }
      }
    }

    if ($is_a_replace_rule || !$minlen || !@bases) {
      dbg("zoom: ignoring rule %s, %s", $name,
          $is_a_replace_rule ? 'is a replace rule'
          : !@bases ? 'no bases' : 'no minlen');
      push @failed, { orig => $rule };
      $cached->{rule_bases}->{$cachekey} = { };
      $no++;
    }
    else {
      # dbg("zoom: YES <base>$base</base> <origrule>$rule</origrule>");

      # figure out if we have e.g. ["foo", "foob", "foobar"]; in this
      # case, we only need to track ["foo"].
      my %subsumed;
      foreach my $base1 (@bases) {
        foreach my $base2 (@bases) {
          if ($base1 ne $base2 && $base1 =~ /\Q$base2\E/) {
            $subsumed{$base1} = 1; # base2 is inside base1; discard the longer
          }
        }
      }

      my @forcache;
      foreach my $base (@bases) {
        next if $subsumed{$base};
        push @good_bases, {
            base => $base, orig => $rule, name => "$name,[l=$lossy]"
          };
        # *separate* copies for cache -- we modify the @good_bases entry
        push @forcache, {
            base => $base, orig => $rule, name => "$name,[l=$lossy]"
          };
      }

      $cached->{rule_bases}->{$cachekey} = { g => \@forcache };
      $yes++;
    }
  }

  $self->{show_progress} and $progress and $progress->final();

  dbg("zoom: $ruletype: found ".(scalar @good_bases).
      " usable base strings in $yes rules, skipped $no rules");

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
                total => (scalar @good_bases || 1),
                itemtype => 'bases',
              });

  # this bit is annoyingly O(N^2).  Rewrite the data -- the @good_bases
  # array -- into a more efficient format, using arrays and with a little
  # bit of precomputation, to go (quite a bit) faster
  my @rewritten;
  foreach my $set1 (@good_bases) {
    my $base = $set1->{base};
    next if (!$base || !$set1->{name});
    push @rewritten, [
      $base,                # 0 - SLOT_BASE
      $set1->{name},        # 1 - SLOT_NAME
      $set1->{orig},        # 2 - SLOT_ORIG
      length $base,         # 3 - SLOT_LEN_BASE
      $base,                # 4 - SLOT_BASE_INITIAL
      0                     # 5 - SLOT_HAS_MULTIPLE, has_multiple flag
    ];
  }

  @good_bases = sort {
    $b->[SLOT_LEN_BASE] <=> $a->[SLOT_LEN_BASE] ||
    $a->[SLOT_BASE] cmp $b->[SLOT_BASE] ||
    $a->[SLOT_NAME] cmp $b->[SLOT_NAME] ||
    $a->[SLOT_ORIG] cmp $b->[SLOT_ORIG]
  } @rewritten;


  my $base_orig =  $conf->{base_orig}->{$ruletype};
  my $next_base_position = 0;
  for my $set1 (@good_bases) {
    $next_base_position++;
    $self->{show_progress} and $progress and $progress->update(++$count);
    my $base1 = $set1->[SLOT_BASE] or next;  # got clobbered
    my $name1 = $set1->[SLOT_NAME];
    my $orig1 = $set1->[SLOT_ORIG];
    my $len1 = $set1->[SLOT_LEN_BASE];
    $base_orig->{$name1} = $orig1;

    foreach my $set2 (@good_bases[$next_base_position .. $#good_bases]) { # order from smallest to largest
      # clobber false and exact dups; this can happen if a regexp outputs the
      # same base string multiple times
      if (!$set2->[SLOT_BASE] ||
		(
		  $base1 eq $set2->[SLOT_BASE] &&
		  $name1 eq $set2->[SLOT_NAME] &&
		  $orig1 eq $set2->[SLOT_ORIG]
		)
	)
      {
        #dbg("clobbering: [base2][$set2->[SLOT_BASE]][name2][$set2->[SLOT_NAME]][orig][$set2->[SLOT_ORIG]]");
        $set2->[SLOT_BASE] = CLOBBER;       # clobber
        next;
      }

      # Cannot be a subset if it does not contain the other base string
      next if index($base1,$set2->[SLOT_BASE_INITIAL]) == -1;

      # skip if either already contains the other rule's name
      # optimize: this can only happen if the base has more than
      # one rule already attached, ie [5]
      next if ($set2->[SLOT_HAS_MULTIPLE] && index($set2->[SLOT_NAME],$name1) > -1 && $set2->[SLOT_NAME] =~ /(?: |^)\Q$name1\E(?: |$)/);

      # don't use $name1 here, since another base in the set2 loop
      # may have added $name2 since we set that
      next if ($set1->[SLOT_HAS_MULTIPLE] && index($set1->[SLOT_NAME],$set2->[SLOT_NAME]) > -1 && $set1->[SLOT_NAME] =~ /(?: |^)\Q$set2->[SLOT_NAME]\E(?: |$)/);

      # $set2->[SLOT_BASE] is just a subset of base1
      #dbg("zoom: subsuming '$set2->[SLOT_BASE]' ($set2->[SLOT_NAME]) into '$base1': [SLOT_BASE]=$set1->[SLOT_BASE] [SLOT_HAS_MULTIPLE]=$set1->[SLOT_HAS_MULTIPLE]");
      $set1->[SLOT_NAME] .= " ".$set2->[SLOT_NAME];
      $set1->[SLOT_HAS_MULTIPLE] = 1;
    }
  }

  # we can still have duplicate cases; __FRAUD_PTS and __SARE_FRAUD_BADTHINGS
  # both contain "killed" for example, pointing at different rules, which
  # the above search hasn't found.  Collapse them here with a hash
  my %bases;
  foreach my $set (@good_bases) {
    my $base = $set->[0];
    next unless $base;

    if (defined $bases{$base}) {
      $bases{$base} .= " ".$set->[1];
    } else {
      $bases{$base} = $set->[1];
    }
  }
  undef @good_bases;

  my $base_string =  $conf->{base_string}->{$ruletype};
  foreach my $base (keys %bases) {
    # uniq the list, since there are probably dup rules listed
    my %u;
    for my $i (split ' ', $bases{$base}) {
      next if exists $u{$i}; undef $u{$i}; 
    }
    $base_string->{$base} = join ' ', sort keys %u;
  }

  $self->{show_progress} and $progress and $progress->final();

  if ($cachefile) {
    $self->write_cachefile ($cachefile, $cached);
  }

  my $elapsed = time - $start;
  $self->{show_progress} and info ("$ruletype: ".
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


  my $mods = '';

  # remove the regexp modifiers, keep for later
  while ($rule =~ s/^\(\?([a-z]*)\)//) {
    $mods .= $1;
  }

  # modifier removal
  while ($rule =~ s/^\(\?-([a-z]*)\)//) {
    foreach my $modchar (split '', $mods) {
      $mods =~ s/$modchar//g;
    }
  }

  my $lossy = 0;

  # now: simplify aspects of the regexp.  Bear in mind that we can
  # simplify as long as we cause the regexp to become more general;
  # more hits is OK, since false positives will be discarded afterwards
  # anyway.  Simplification that causes the regexp to *not* hit
  # stuff that the "real" rule would hit, however, is a bad thing.

  if ($main->{bases_must_be_casei}) {
    $rule = lc $rule;

    $lossy = 1;
    $mods =~ s/i// and $lossy = 0;

    # always case-i: /A(?i:ct) N(?i:ow)/ => /Act Now/
    $rule =~ s/(?<!\\)\(\?i\:(.*?)\)/$1/gs and $lossy++;

    # always case-i: /A(?-i:ct)/ => /Act/
    $rule =~ s/(?<!\\)\(\?-i\:(.*?)\)/$1/gs and $lossy++;

    # remove (?i)
    $rule =~ s/\(\?i\)//gs;
  }
  else {
    die "case-i" if $rule =~ /\(\?i\)/;
    die "case-i" if index($mods, 'i') >= 0;

    # always case-i: /A(?i:ct) N(?i:ow)/ => /Act Now/
    $rule =~ s/(?<!\\)\(\?i\:(.*?)\)/$1/gs and die "case-i";

    # we're already non-case-i so this is a no-op: /A(?-i:ct)/ => /Act/
    $rule =~ s/(?<!\\)\(\?-i\:(.*?)\)/$1/gs;
  }

  # remove /m and /s modifiers
  $mods =~ s/m// and $lossy++;
  $mods =~ s/s// and $lossy++;

  # remove (^|\b)'s
  # T_KAM_STOCKTIP23 /(EXTREME INNOVATIONS|(^|\b)EXTI($|\b))/is
  $rule =~ s/\(\^\|\\b\)//gs and $lossy++;
  $rule =~ s/\(\$\|\\b\)//gs and $lossy++;
  $rule =~ s/\(\\b\|\^\)//gs and $lossy++;
  $rule =~ s/\(\\b\|\$\)//gs and $lossy++;

  # remove (?!credit)
  $rule =~ s/\(\?\![^\)]+\)//gs and $lossy++;

  # remove \b's
  $rule =~ s/(?<!\\)\\b//gs and $lossy++;

  # remove the "?=" trick
  # (?=[dehklnswxy])(horny|nasty|hot|wild|young|....etc...)
  $rule =~ s/\(\?\=\[[^\]]+\]\)//gs;

  $mods .= "L" if $lossy;
  ($rule, $mods);
}

sub extract_hints {
  my ($self, $rawrule, $rule, $mods) = @_;

  my $main = $self->{main};
  my $orig = $rule;

  my $lossy = 0;
  $mods =~ s/L// and $lossy++;

  # if there are anchors, give up; we can't get much 
  # faster than these anyway
  die "anchors" if $rule =~ /^\(?(?:\^|\\A)/;

  # die "anchors" if $rule =~ /(?:\$|\\Z)\)?$/;
  # just remove end-of-string anchors; they're slow so could gain
  # from our speedup
  $rule =~ s/(?<!\\)(?:\$|\\Z)\)?$// and $lossy++;

  # simplify (?:..) to (..)
  $main->{bases_allow_noncapture_groups} or
            $rule =~ s/\(\?:/\(/g;

  # simplify some grouping arrangements so they're easier for us to parse
  # (foo)? => (foo|)
  $rule =~ s/\((.*?)\)\?/\($1\|\)/gs;
  # r? => (r|)
  $rule =~ s/(?<!\\)(\w)\?/\($1\|\)/gs;

  # Create single tmpfile for extract_hints to use, instead of thousands
  if (!$self->{tmpf}) {
    ($self->{tmpf}, my $tmpfh) = Mail::SpamAssassin::Util::secure_tmpfile();
    $tmpfh  or die "failed to create a temporary file";
    close $tmpfh;
    $self->{tmpf} = untaint_var($self->{tmpf});
  }

  open(my $tmpfh, '>'.$self->{tmpf})
    or die "error opening $self->{tmpf}: $!";
  binmode $tmpfh;
  print $tmpfh "use bytes; m{" . $rule . "}" . $mods
    or die "error writing to $self->{tmpf}: $!";
  close $tmpfh  or die "error closing $self->{tmpf}: $!";

  $self->{perl} = $self->get_perl()  if !exists $self->{perl};
  local *IN;
  open (IN, "$self->{perl} -c -Mre=debug $self->{tmpf} 2>&1 |")
    or die "cannot run $self->{perl}: ".exit_status_str($?,$!);

  my($inbuf,$nread,$fullstr); $fullstr = '';
  while ( $nread=read(IN,$inbuf,16384) ) { $fullstr .= $inbuf }
  defined $nread  or die "error reading from pipe: $!";

  close IN      or die "error closing pipe: $!";
  defined $fullstr  or warn "empty result from a pipe";

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
    die "failed to parse Mre=debug output: $fullstr m{".$rule."}".$mods." $rawrule";
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

  my @ops;
  foreach my $op (split(/\n/s, $opsstr)) {
    next unless $op;

    if ($op =~ /^\s+\d+: (\s*)([A-Z]\w+)\b(.*?)\s*(?:\(\d+\))?$/) {
      # perl 5.8:              <xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx...>(18)
      # perl 5.10, 5.12, 5.14: <xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx>... (18)
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
  my @longests;
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
        my $str = $1;
        $buf .= $str;
        if ($buf =~ s/\\x\{[0-9a-fA-F]{4,}\}.*$//) {
          # a high Unicode codepoint, interpreted by perl 5.8.x.  cut and stop
          $add_candidate->();
        }
        if (length $str >= 55 && $buf =~ s/\.\.\.$//) {
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
        if ($item !~ /^(?:END|CLOSE\d|MINMOD)$/)
        {
          $lossy = 1;
          DEBUG_RE_PARSING and warn "item $item makes regexp lossy";
        }
      }
      $prevop = $op;
    }
    $add_candidate->();

    if (!$longestexact) {
      die "no long-enough string found in $rawrule\n";
      # all unrolled versions must have a long string, otherwise
      # we cannot reliably match all variants of the rule
    } else {
      push @longests, ($main->{bases_must_be_casei}) ?
                            lc $longestexact : $longestexact;
    }
  }

  DEBUG_RE_PARSING and warn "longest base strings: /".join("/", @longests)."/";
  return ($lossy, @longests);
}

###########################################################################

sub unroll_branches {
  my ($self, $depth, $opslist) = @_;

  die "too deep" if ($depth++ > 5);

  my @ops = (@{$opslist});      # copy
  my @pre_branch_ops;
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
  my @alts;
  my @in_this_branch;

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
  my @rets;
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
    print "want: /".join('/ /', @want)."/\n"  or die "error writing: $!";
    print "got:  /".join('/ /', @got)."/\n"   or die "error writing: $!";
    return 0;
  } else {
    print "ok\n"  or die "error writing: $!";
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
  untaint_var(\$perl);
  return $perl;
}

###########################################################################

sub read_cachefile {
  my ($self, $cachefile) = @_;
  local *IN;
  if (open(IN, "<".$cachefile)) {
    my($inbuf,$nread,$str); $str = '';
    while ( $nread=read(IN,$inbuf,16384) ) { $str .= $inbuf }
    defined $nread  or die "error reading from $cachefile: $!";
    close IN  or die "error closing $cachefile: $!";

    untaint_var(\$str);
    my $VAR1;              # Data::Dumper
    if (eval $str) {
      return $VAR1;        # Data::Dumper's naming
    }
  }
  return { };
}

sub write_cachefile {
  my ($self, $cachefile, $cached) = @_;

  my $dump = Data::Dumper->new ([ $cached ]);
  $dump->Deepcopy(1);
  $dump->Purity(1);
  $dump->Indent(1);

  my $cachedir = $self->{main}->{bases_cache_dir};
  if (mkdir($cachedir)) {
    # successfully created
  } elsif ($! == EEXIST) {
    dbg("zoom: ok, cache directory already existed");
  } else {
    warn "zoom: could not create cache directory: $cachedir ($!)\n";
    return;
  }
  open(CACHE, ">$cachefile")  or warn "cannot write to $cachefile";
  print CACHE ($dump->Dump, ";1;")  or die "error writing: $!";
  close CACHE  or die "error closing $cachefile: $!";
}

=over 4

=item my ($cleanregexp) = fixup_re($regexp);

Converts encoded characters in a regular expression pattern into their
equivalent characters

=back

=cut

sub fixup_re {
  my $re = shift;
  
  if ($fixup_re_test) { print "INPUT: /$re/\n"  or die "error writing: $!" }
  
  my $output = "";
  my $TOK = qr([\"\\]);

  my $STATE;
  local ($1,$2);
  while ($re =~ /\G(.*?)($TOK)/gcs) {
    my $pre = $1;
    my $tok = $2;

    if (length($pre)) {
      $output .= "\"$pre\"";
    }

    if ($tok eq '"') {
      $output .= '"\\""';
    }
    elsif ($tok eq '\\') {
      $re =~ /\G(x\{[^\}]+\}|[0-7]{1,3}|.)/gcs or die "\\ at end of string!";
      my $esc = $1;
      if ($esc eq '"') {
        $output .= '"\\""';
      } elsif ($esc eq '\\') {
        $output .= '"**BACKSLASH**"';   # avoid hairy escape-parsing
      } elsif ($esc =~ /^x\{(\S+)\}\z/) {
        $output .= '"'.chr(hex($1)).'"';
      } elsif ($esc =~ /^[0-7]{1,3}\z/) {
        $output .= '"'.chr(oct($esc)).'"';
      } else {
        $output .= "\"$esc\"";
      }
    }
    elsif ($fixup_re_test) {
      print "PRE: $pre\nTOK: $tok\n"  or die "error writing: $!";
    }
  }
  
  if (!defined(pos($re))) {
    # no matches
    $output .= "\"$re\"";
    # Bug 6649: protect NL, NULL, ^Z, (and controls to stay on the safe side)
    $output =~ s{([\000-\037\177\200\377])}{sprintf("\\%03o",ord($1))}gse;
  }
  elsif (pos($re) <= length($re)) {
    $output =~ s{([\000-\037\177\200\377])}{sprintf("\\%03o",ord($1))}gse;
    $output .= fixup_re(substr($re, pos($re)));
  }

  $output =~ s/^""/"/;  # protect start and end quotes
  $output =~ s/(?<!\\)""\z/"/;
  $output =~ s/(?<!\\)""//g; # strip empty strings, or turn "abc""def" -> "abcdef"
  $output =~ s/\*\*BACKSLASH\*\*/\\\\/gs;

  if ($fixup_re_test) { print "OUTPUT: $output\n"  or die "error writing: $!" }

  utf8::encode($output)  if utf8::is_utf8($output); # force octets
  return $output;
}

1;
