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

This is a work-in-progress plugin to extract "base" strings from SpamAssassin
'body' rules, suitable for use in Rule2XSBody rules.

=cut

package Mail::SpamAssassin::Plugin::BodyRuleBaseExtractor;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;

use strict;
use warnings;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# a few settings that control what kind of bases are output:

# treat all rules as lowercase for purposes of term extraction?
my $BASES_MUST_BE_CASE_I = 1;
my $BASES_CAN_USE_ALTERNATIONS = 0;    # /(foo|bar|baz)/
my $BASES_CAN_USE_QUANTIFIERS = 0;     # /foo.*bar/ or /foo*bar/ or /foooo?bar/
my $BASES_CAN_USE_CHAR_CLASSES = 0;    # /fo[opqr]bar/
my $SPLIT_OUT_ALTERNATIONS = 1;        # /(foo|bar|baz)/ => ["foo", "bar", "baz"]

###########################################################################

sub new {
  my $class = shift;
  my $mailsaobject = shift;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

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

  # TODO: need a better way to do this rather than using an env
  # var as a back channel
  my $rawf = $ENV{'RULE_REGEXP_DUMP_FILE'};
  my $f;

  if ($rawf) {
    $rawf =~ /^(.*)$/;
    $f = $1;        # untaint; allow anything here, it's from %ENV and safe
  }
  else {
    return;         # TODO: comment this for Rabin-Karp
  }

  $self->extract_set($f, $conf, $conf->{body_tests}, 'body');
}

sub extract_set {
  my ($self, $dumpfile, $conf, $test_set, $ruletype) = @_;

  foreach my $pri (keys %{$test_set}) {
    my $nicepri = $pri; $nicepri =~ s/-/neg/g;
    $self->extract_set_pri($conf, $test_set->{$pri}, $ruletype.'_'.$nicepri);

    if ($dumpfile) {
      $self->dump_base_strings($dumpfile, $conf, $ruletype.'_'.$nicepri);
    }
  }
}

###########################################################################

sub extract_set_pri {
  my ($self, $conf, $rules, $ruletype) = @_;

  my @good_bases = ();
  my @failed = ();
  my $yes = 0;
  my $no = 0;

  dbg("zoom: base extraction start for type $ruletype");

  # attempt to find good "base strings" (simplified regexp subsets) for each
  # regexp.  We try looking at the regexp from both ends, since there
  # may be a good long string of text at the end of the rule.

  # require this many chars in a base string, for it to be viable
  my $min_chars = 4;

  foreach my $name (keys %{$rules}) {
    my $rule = $rules->{$name};

    # ignore ReplaceTags rules
    # TODO: need cleaner way to do this
    next if ($conf->{rules_to_replace}->{$name});

    my @bases1 = ();
    my @bases2 = ();
    eval {  # catch die()s
      @bases1 = $self->extract_hints($rule, 0);
    };
    $@ and dbg("giving up on that direction: $@");
    eval {
      @bases2 = $self->extract_hints($rule, 1);
    };
    $@ and dbg("giving up on that direction: $@");

    # if any of the extracted hints in a set are too short, the entire
    # set is invalid; this is because each set of N hints represents just
    # 1 regexp.
    my $minlen1;
    foreach my $str (@bases1) {
      my $len = length $str;
      if ($len < $min_chars) { $minlen1 = undef; @bases1 = (); last; }
      elsif (!defined($minlen1) || $len < $minlen1) { $minlen1 = $len; }
    }
    my $minlen2;
    foreach my $str (@bases2) {
      my $len = length $str;
      if ($len < $min_chars) { $minlen2 = undef; @bases2 = (); last; }
      elsif (!defined($minlen2) || $len < $minlen2) { $minlen2 = $len; }
    }

    if (defined $minlen1 && !defined $minlen2) {
      # keep using @bases1
    }
    elsif (!defined $minlen1 && defined $minlen2) {
      # change to using @bases2
      @bases1 = @bases2;
    }
    elsif (defined $minlen1 && defined $minlen2) {
      # both are valid; use the end with the longer hints
      if ($minlen2 > $minlen1) {
        @bases1 = @bases2;
      }
    }

    if ($minlen1 && @bases1) {
      # dbg("zoom: YES <base>$base</base> <origrule>$rule</origrule>");
      foreach my $base (@bases1) {
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

  foreach my $set1 (@good_bases) {
    my $base1 = $set1->{base};
    my $orig1 = $set1->{orig};
    my $key1  = $set1->{name};
    next if ($base1 eq '' or $key1 eq '');

    $conf->{base_orig}->{$ruletype}->{$key1} = $orig1;

    foreach my $set2 (@good_bases) {
      next if ($set1 == $set2);
      next if ($set1->{name} =~ /\b\Q$set2->{name}\E\b/);
      next if ($set2->{name} =~ /\b\Q$set1->{name}\E\b/);

      my $base2 = $set2->{base};
      next if ($base2 eq '');
      next if (length $base1 < length $base2);
      next if ($base1 !~ /\Q$base2\E/);

      $set1->{name} .= " ".$set2->{name};

      if ($base1 eq $base2) {
        # an exact duplicate!  kill the latter entirely
        $set2->{name} = '';
        $set2->{base} = '';
      }
      # otherwise, base2 is just a subset of base1

      # dbg("zoom: subsuming '$base2' into '$base1': $set1->{name}");
    }
  }

  foreach my $set (@good_bases) {
    my $base = $set->{base};
    my $key  = $set->{name};
    next unless $base;
    $conf->{base_string}->{$ruletype}->{$base} = $key;
  }

  warn ("zoom: base extraction complete for $ruletype: yes=$yes no=$no\n");
}

###########################################################################

sub dump_base_strings {
  my ($self, $dumpfile, $conf, $ruletype) = @_;

  open (OUT, ">$dumpfile") or die "cannot write to $dumpfile!";
  print OUT "name $ruletype\n";

  foreach my $key1 (sort keys %{$conf->{base_orig}->{$ruletype}}) {
    print OUT "orig $key1 $conf->{base_orig}->{$ruletype}->{$key1}\n";
  }

  foreach my $key (sort keys %{$conf->{base_string}->{$ruletype}}) {
    print OUT "r $key:$conf->{base_string}->{$ruletype}->{$key}\n";
  }
  close OUT or die "close failed on $dumpfile!";

  warn ("zoom: bases written to '$dumpfile'\n");
}

###########################################################################

# TODO:
# NO /no.{1,10}P(?:er|re)scription.{1,10}(?:needed|require|necessary)/i
#     => should extract 'scription' somehow
# /time to refinance|refinanc\w{1,3}\b.{0,16}\bnow\b/i
#     => should understand alternations; tricky

sub extract_hints {
  my $self = shift;
  my $rule = shift;
  my $is_reversed = shift;

  my $orig = $rule;
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

  if ($BASES_MUST_BE_CASE_I) {
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

  # remove \b's
  $rule =~ s/\\b//gs;

  # remove the "?=" trick
  # (?=[dehklnswxy])(horny|nasty|hot|wild|young|....etc...)
  $rule =~ s/\(\?\=\[[^\]]+\]\)//gs;

  # if there are anchors, give up; we can't get much 
  # faster than these anyway
  die "anchors" if $rule =~ /^\(?(?:\^|\\A)/;
  die "anchors" if $rule =~ /(?:\$|\\Z)\)?$/;

  # simplify (?:..) to (..)
  $rule =~ s/\(\?:/\(/g;

  # here's the trick; we can use the truncate regexp below simply by
  # reversing the string and taking care to fix "\z" 2-char escapes.
  # TODO: this breaks stuff like "\s+" or "\S{4,12}", but since the
  # truncation regexp below is pretty simple-minded, that's ok.
  if ($is_reversed) {
    $rule = join ('', reverse (split '', $rule));
    $rule = de_reverse_multi_char_regexp_statements($rule);
  }

  # truncate the pattern at the first unhandleable metacharacter
  # or range
  $rule =~ s/(?<!\\)(?:
              \(\?\!|
              \\[abce-rt-vx-z]|
              \\[ABCE-RT-VX-Z]
            ).*$//gsx;

  $BASES_CAN_USE_CHAR_CLASSES or $rule =~ s/(?<!\\)(?:
              \\\w|
              \.|
              \[|
              \]
            ).*$//gsx;

  if ($BASES_CAN_USE_ALTERNATIONS||$SPLIT_OUT_ALTERNATIONS) {
    # /foo (bar)? baz/ simplify to /foo (bar|) baz/
    $rule =~ s/(?<!\\)(\([^\(\)]*)\)\?/$1\|\)/gs;

    # /foo bar? baz/ simplify to /foo ba(r|) baz/
    $rule =~ s/(?<!\\)(.)\?/($1\|\)/gs;
  }

  $BASES_CAN_USE_QUANTIFIERS or $rule =~ s/(?<!\\)(?:
              .\*|	# remove the quantified char, too
              .\+|
              .\?|
              .\{
            ).*$//gsx;

  ($BASES_CAN_USE_ALTERNATIONS||$SPLIT_OUT_ALTERNATIONS) or
            $rule =~ s/(?<!\\)(?:
              \(|
              \)
            ).*$//gsx;

  if ($is_reversed) {
    $rule = join ('', reverse (split '', $rule));
    $rule = de_reverse_multi_char_regexp_statements($rule);
  }

  # drop this one, after the reversing
  $rule =~ s/\(\?\!.*$//gsx;

  # still problematic; kill all "x?" statements
  $rule =~ s/.\?.*$//gsx;

  # simplify (..)? and (..|) to (..|z{0})
  # this wierd construct is to work around an re2c bug; (..|) doesn't
  # do what it should
  if ($BASES_CAN_USE_ALTERNATIONS) {
    $rule =~ s/\((.*?)\)\?/\($1\|z{0}\)/gs;
    $rule =~ s/\((.*?)\|\)/\($1\|z{0}\)/gs;
    $rule =~ s/\(\|(.*?)\)/\($1\|z{0}\)/gs;
  }

  # re2xs doesn't like escaped brackets;
  # brackets in general, in fact
  $rule =~ s/\:.*//g;

  # replace \s, \d, \S with char classes that (nearly) match them
  # TODO: \w, \W need to know about utf-8, ugh

  # [a-f\s]
  $rule =~ s/(\[[^\]]*)\\s([^\]]*\])/$1 \\t\\n$2/gs;
  # [a-f\S]: we can't support this, cut the string here
  $rule =~ s/(\[[^\]]*)\\S([^\]]*\]).*//gs;
  $rule =~ s/(\[[^\]]*)\\d([^\]]*\])/${1}0-9$2/gs;
  $rule =~ s/(\[[^\]]*)\\D([^\]]*\]).*//gs;
  $rule =~ s/(\[[^\]]*)\\w([^\]]*\])/${1}a-z0-9$2/gs;
  $rule =~ s/(\[[^\]]*)\\W([^\]]*\]).*//gs;

  # \s, etc. outside of existing char class blocks
  $rule =~ s/\\S/[^ \\t\\n]/gs;
  $rule =~ s/\\s/[ \\t\\n]/gs;
  $rule =~ s/\\S/[^ \\t\\n]/gs;
  $rule =~ s/\\d/[0-9]/gs;
  $rule =~ s/\\D/[^0-9]/gs;
  $rule =~ s/\\w/[_a-z0-9]/gs;
  $rule =~ s/\\W/[^_a-z0-9]/gs;

  # {loop here, to catch __DRUGS_SLEEP1:
  # 0,3}([ \t\n]|z{0})
  while (1) 
  {
    my $startrule = $rule;

    # exit early if the pattern starts with a class in a group;
    # we can't reliably kill these
    # r ([a-z0-9]+\*[,[ \t\n]]+){2}:TVD_BODY_END_STAR
    if ($rule =~ /^\((?:
              \.?[\*\?\+] |
              \.?\{?[^\{]*\} |
              \[ |
              [^\[]*\]
            )/sx)
    {
      die "pattern starts with a class in a group";
    }

    # kill quantifiers right at the start of the string.
    # this (a) reduces algorithmic complexity of the produced code,
    # and (b) can also improve overall speed as a side-effect of (a)
    $rule =~ s/^(?:
              \.?[\*\?\+] |
              \.?\{?[^\{]*\} |
              [^\(]*\) |
              \[?[^\[]*\]
            )+//gsx;

    # kill quantifiers right at the end of the string, too;
    # they can hide hits if they overlap with other patterns
    0 and $rule =~ s/(?:
              \.[\*\?\+] |
              \.\{?[^\{]*\} |
              \. |
              \([^\)]* |
              \[[^\[]*\]?
            )+$//gsx;

    last if $startrule eq $rule;
  }

  # return for things we know we can't handle.
  if (!($BASES_CAN_USE_ALTERNATIONS||$SPLIT_OUT_ALTERNATIONS)) {
    if ($rule =~ /\|/) {
      # /time to refinance|refinanc\w{1,3}\b.{0,16}\bnow\b/i
      die "alternations";
    }
  }


  {
    # count (...braces...) to ensure the numbers match up
    my @c = ($rule =~ /(?<!\\)\(/g); my $brace_i = scalar @c;
       @c = ($rule =~ /(?<!\\)\)/g); my $brace_o = scalar @c;
    if ($brace_i != $brace_o) { die "brace mismatch"; }
  }

  # do the same for [charclasses]
  {
    my @c = ($rule =~ /(?<!\\)\[/g); my $brace_i = scalar @c;
       @c = ($rule =~ /(?<!\\)\]/g); my $brace_o = scalar @c;
    if ($brace_i != $brace_o) { die "charclass mismatch"; }
  }

  # and {quantifiers}
  {
    my @c = ($rule =~ /(?<!\\)\{/g); my $brace_i = scalar @c;
       @c = ($rule =~ /(?<!\\)\}/g); my $brace_o = scalar @c;
    if ($brace_i != $brace_o) { die "quantifier mismatch"; }
  }

  # lookaheads that are just too far for the re2c parser
  # r your .{0,40}account .{0,40}security
  if ($rule =~ /\.\{(\d+),?(\d+?)\}/ and ($1+$2 > 20)) {
    die "too far lookahead";
  }

  # re2xs doesn't like escaped brackets
  if ($rule =~ /\\:/) {
    die "escaped bracket";
  }

  my @rules;
  if ($SPLIT_OUT_ALTERNATIONS && $rule =~ /\|/) {
    @rules = $self->split_alt($rule);
  }
  else {
    @rules = ($rule);
  }

  # finally, reassemble a usable regexp / set of regexps
  if ($mods ne '') {
    $mods = "(?$mods)";
  }

  return map {
    $mods.$_;
  } @rules;
}

sub count_regexp_statements {
  my $self = shift;
  my $rule = shift;

  # collapse various common metachar sequences into 1 char,
  # or their shortest form
  $rule =~ s/(?<!\\)(?:
            \[.+?\][\?\*]|
            \{0\}\?|
            \{.+?\}\?
          )//gs;

  $rule =~ s/\[.+?\]/R/gs;
  $rule =~ s/\{.+?\}/Q/gs;
  $rule =~ s/.\?//gs;
  $rule =~ s/.\*//gs;

  return length $rule;
}

sub de_reverse_multi_char_regexp_statements {
  my $rule = shift;

  # fix:
  #    "S\" => "\S"
  #    "+S\" => "\S+"
  #    "}41,2{S\" => "\S{2,14}"
  #    "?}41,2{S\" => "\S{2,14}?"

  $rule =~ s/
        (
          \? |
        )
        (
          \}(?:\d*\,)?\d*\{ |
          \* |
          \+ |
          \? |
        )
        (.)(\\?)/$4$3$2$1/gsx;

  return $rule;
}

###########################################################################

sub split_alt {
  my ($self, $re) = @_;

  # warn "JMD in $re";
  # use "($re)" instead of "$re" to handle /foo|baz/ -- implied group
  my @res = $self->_split_alt_recurse(0, '('.$re.')');
  # warn "JMD out ".join('/ /', @res);
  return @res;
}

sub _split_alt_recurse {
  my ($self, $depth, $re) = @_;

  $depth++;
  "die recursed too far in alternation splitting" if ($depth > 5);

  # trim unnecessary group markers, e.g. /f(oo)/ => /foo/
  $re =~ s/\(([^\(\)\|]*)\)/$1/gs;

  # identify the deepest-nested (...|...) scope
  $re =~ m{
      ^(.*)
      (?<!\\)\(([^\(\)]*?\|[^\(\)]*?)\)
      (.*)$
    }xs;

  my $pre  = $1;
  my $alts = $2;
  my $post = $3;

  if (!defined $post) {
    $re =~ s/\(([^\(\)\|]*)\)/$1/gs;
    return ($re);       # didn't match; no groups
  }

  # and expand it
  my @out = ();

  # the 999999 actually does have an effect; otherwise '(foo|)' is
  # split as ('foo') instead of ('foo', '') for some reason
  foreach my $str (split (/(?<!\\)\|/, $alts, 999999)) {
    $str = $pre.$str.$post;
    # are there unresolved groups left?
    if ($str =~ /(?<!\\)[\(\|\)]/) {
      push @out, $self->_split_alt_recurse($depth, $str);
    } else {
      push @out, $str;
    }
  }

  { # uniq
    my %u=(); @out = grep {defined} map {
      if (exists $u{$_}) { undef; } else { $u{$_}=undef;$_; }
    } @out; undef %u;
  }

  return @out;
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

1;
