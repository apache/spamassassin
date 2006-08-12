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

package Mail::SpamAssassin::Plugin::Rule2XSBody;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;

my $re2xs_out = "re.in";

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

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds = ();

  # push (@cmds, {
  # setting => 'whitelist_from',
  # type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST
  # });

  $conf->{parser}->register_commands(\@cmds);
}

###########################################################################

sub finish_parsing_end {
  my ($self, $params) = @_;
  my $conf = $params->{conf};
  $self->zoomify_test_set ($conf->{body_tests}, 'body');
}

sub zoomify_test_set {
  my ($self, $test_set, $ruletype) = @_;
  foreach my $pri (keys %{$test_set}) {
    my $nicepri = $pri; $nicepri =~ s/-/neg/g;
    $self->extract_all($test_set->{$pri}, $ruletype.'_'.$nicepri);
  }
}

###########################################################################

sub extract_all {
  my ($self, $rules, $ruletype) = @_;
  my $yes = 0;
  my $no = 0;
  my @good_bases = ();
  my @failed = ();

  dbg("zoom: base extraction start for type $ruletype");

  foreach my $name (keys %{$rules}) {
    my $rule = $rules->{$name};
    my $orig = $rule;

    my $base  = $self->extract_base($rule, 0);
    my $base2 = $self->extract_base($rule, 1);
    if ($base2 && (!$base || (length $base2 > length $base))) {
      $base = $base2;
    }

    if (length $base < 3) { $base = undef; }

    if ($base) {
      # dbg("zoom: YES <base>$base</base> <origrule>$orig</origrule>");
      push @good_bases, { base => $base, orig => $orig, name => $name };
      $yes++;
    }
    else {
      dbg("zoom: NO $orig");
      push @failed, { orig => $orig };
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

  my %newbases = ();
  foreach my $set1 (@good_bases) {
    my $base1 = $set1->{base};
    my $key1  = $set1->{name};

    foreach my $set2 (@good_bases) {
      next if ($set1 == $set2);

      my $base2 = $set2->{base};
      next if ($base2 eq '');
      next if (length $base1 < length $base2);
      next if ($base1 !~ /\Q$base2\E/);

      $set1->{name} .= " ".$set2->{name};

      # dbg("zoom: subsuming '$base2' into '$base1': $set1->{name}");
    }
  }

  open (OUT, ">$re2xs_out") or die "cannot write to $re2xs_out!";
  foreach my $set (@good_bases) {
    my $base = $set->{base};
    my $key  = $set->{name};
    print OUT "$base:$key\n";
  }
  close OUT or die "close failed on $re2xs_out!";

  # TODO: run re2xs

  dbg ("zoom: base extraction complete for $ruletype: yes=$yes no=$no");
}

###########################################################################

# TODO:
# NO /no.{1,10}P(?:er|re)scription.{1,10}(?:needed|require|necessary)/i
#     => should extract 'scription' somehow
# /time to refinance|refinanc\w{1,3}\b.{0,16}\bnow\b/i
#     => should understand alternations; tricky

sub extract_base {
  my $self = shift;
  my $rule = shift;
  my $is_reversed = shift;

  my $orig = $rule;

  $rule = Mail::SpamAssassin::Util::regexp_remove_delimiters($rule);

  # remove those mods, keep for later
  $rule =~ s/^(\(?[a-z]*\))//;
  my $mods = $1;
  $mods ||= '';

  # now: simplify aspects of the regexp.  Bear in mind that we can
  # simplify as long as we cause the regexp to become more general;
  # more hits is OK, since false positives will be discarded afterwards
  # anyway.

  # treat all rules as lowercase for purposes of term extraction
  $rule = lc $rule;
  $mods =~ s/i//;

  # always case-i: /A(?i:ct) N(?i:ow)/ => /Act Now/
  $rule =~ s/(?<!\\)\(\?i\:(.*?)\)/$1/gs;

  # remove /m and /s modifiers
  $mods =~ s/m//;
  $mods =~ s/s//;

  # remove \b's
  $rule =~ s/\\b//gs;

  # here's the trick; we can use the truncate regexp below simply by
  # reversing the string and taking care to fix "\z" 2-char escapes
  if ($is_reversed) {
    $rule = join ('', reverse (split '', $rule));
    $rule =~ s/(.)\\/\\$1/gs;
  }

  # truncate the pattern at the first unhandleable metacharacter
  # or range
  $rule =~ s/(?<!\\)(?:
              \^|
              \$|
              \.|
              \(|
              \)|
              .\?|
              \+|
              \*|
              \:|
              \{|
              \}|
              \\\w|
              \]|
              \[
            ).*$//gsx;

  if ($is_reversed) {
    # de-reverse back into correct order!
    $rule =~ s/\\(.)/$1\\/gs;
    $rule = join ('', reverse (split '', $rule));
  }

  # return for things we know we can't handle
  if ($rule =~ /\|/) {
    # /time to refinance|refinanc\w{1,3}\b.{0,16}\bnow\b/i
    return;
  }

  # finally, reassemble a usable regexp
  $rule = $mods . $rule;
  return $rule;
}

1;
