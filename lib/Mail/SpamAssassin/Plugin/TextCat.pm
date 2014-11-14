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

Mail::SpamAssassin::Plugin::TextCat - TextCat language guesser

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::TextCat

=head1 DESCRIPTION

This plugin will try to guess the language used in the message body text.

You can use the "ok_languages" directive to set which languages are
considered okay for incoming mail and if the guessed language is not okay,
C<UNWANTED_LANGUAGE_BODY> is triggered.

It will always add the results to a "X-Language" name-value pair in the
message metadata data structure. This may be useful as Bayes tokens and
can also be used in rules for scoring. The results can also be added to
marked-up messages using "add_header", with the _LANGUAGES_ tag. See
L<Mail::SpamAssassin::Conf> for details.

Note: the language cannot always be recognized with sufficient confidence.
In that case, no action is taken.

=cut

package Mail::SpamAssassin::Plugin::TextCat;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use strict;
use warnings;
use bytes;
use re 'taint';

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# language models
my @nm;

sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # load language models once
  if (! @nm) {
    if (!defined $mailsaobject->{languages_filename}) {
      warn "textcat: languages filename not defined\n";
    }
    else {
      load_models($mailsaobject->{languages_filename});
    }
  }

  $self->register_eval_rule("check_language");
  $self->register_eval_rule("check_body_8bits");

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

=head1 USER OPTIONS

=over 4

=item ok_languages xx [ yy zz ... ]		(default: all)

This option is used to specify which languages are considered okay for
incoming mail.  SpamAssassin will try to detect the language used in the
message body text.

Note that the language cannot always be recognized with sufficient
confidence. In that case, no action is taken.

The rule C<UNWANTED_LANGUAGE_BODY> is triggered if none of the languages
detected are in the "ok" list. Note that this is the only effect of the
"ok" list. It does not act as a whitelist against any other form of spam
scanning.

In your configuration, you must use the two or three letter language
specifier in lowercase, not the English name for the language.  You may
also specify C<all> if a desired language is not listed, or if you want to
allow any language.  The default setting is C<all>.

Examples:

  ok_languages all         (allow all languages)
  ok_languages en          (only allow English)
  ok_languages en ja zh    (allow English, Japanese, and Chinese)

Note: if there are multiple ok_languages lines, only the last one is used.

Select the languages to allow from the list below:

=over 4

=item af	- Afrikaans

=item am	- Amharic

=item ar	- Arabic

=item be	- Byelorussian

=item bg	- Bulgarian

=item bs	- Bosnian

=item ca	- Catalan

=item cs	- Czech

=item cy	- Welsh

=item da	- Danish

=item de	- German

=item el	- Greek

=item en	- English

=item eo	- Esperanto

=item es	- Spanish

=item et	- Estonian

=item eu	- Basque

=item fa	- Persian

=item fi	- Finnish

=item fr	- French

=item fy	- Frisian

=item ga	- Irish Gaelic

=item gd	- Scottish Gaelic

=item he	- Hebrew

=item hi	- Hindi

=item hr	- Croatian

=item hu	- Hungarian

=item hy	- Armenian

=item id	- Indonesian

=item is	- Icelandic

=item it	- Italian

=item ja	- Japanese

=item ka	- Georgian

=item ko	- Korean

=item la	- Latin

=item lt	- Lithuanian

=item lv	- Latvian

=item mr	- Marathi

=item ms	- Malay

=item ne	- Nepali

=item nl	- Dutch

=item no	- Norwegian

=item pl	- Polish

=item pt	- Portuguese

=item qu	- Quechua

=item rm	- Rhaeto-Romance

=item ro	- Romanian

=item ru	- Russian

=item sa	- Sanskrit

=item sco	- Scots

=item sk	- Slovak

=item sl	- Slovenian

=item sq	- Albanian

=item sr	- Serbian

=item sv	- Swedish

=item sw	- Swahili

=item ta	- Tamil

=item th	- Thai

=item tl	- Tagalog

=item tr	- Turkish

=item uk	- Ukrainian

=item vi	- Vietnamese

=item yi	- Yiddish

=item zh	- Chinese (both Traditional and Simplified)

=item zh.big5	- Chinese (Traditional only)

=item zh.gb2312	- Chinese (Simplified only)

=back

Z<>

=cut

  push (@cmds, {
    setting => 'ok_languages',
    default => 'all',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
  });

=item inactive_languages xx [ yy zz ... ]		(default: see below)

This option is used to specify which languages will not be considered
when trying to guess the language.  For performance reasons, supported
languages that have fewer than about 5 million speakers are disabled by
default.  Note that listing a language in C<ok_languages> automatically
enables it for that user.

The default setting is:

=over 4

=item bs cy eo et eu fy ga gd is la lt lv rm sa sco sl yi

=back

That list is Bosnian, Welsh, Esperanto, Estonian, Basque, Frisian, Irish
Gaelic, Scottish Gaelic, Icelandic, Latin, Lithuanian, Latvian,
Rhaeto-Romance, Sanskrit, Scots, Slovenian, and Yiddish.

=cut

  push (@cmds, {
    setting => 'inactive_languages',
    default => 'bs cy eo et eu fy ga gd is la lt lv rm sa sco sl yi',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
  });

=item textcat_max_languages N (default: 3)

The maximum number of languages any one message can simultaneously match
before its classification is considered unknown.

=cut

  push (@cmds, {
    setting => 'textcat_max_languages',
    default => 3,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

=item textcat_optimal_ngrams N (default: 0)

If the number of ngrams is lower than this number then they will be removed.  This
can be used to speed up the program for longer inputs.  For shorter inputs, this
should be set to 0.

=cut

  push (@cmds, {
    setting => 'textcat_optimal_ngrams',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

=item textcat_max_ngrams N (default: 400)

The maximum number of ngrams that should be compared with each of the languages
models (note that each of those models is used completely).

=cut

  push (@cmds, {
    setting => 'textcat_max_ngrams',
    default => 400,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

=item textcat_acceptable_score N (default: 1.02)

Include any language that scores at least C<textcat_acceptable_score> in the
returned list of languages. 

=cut

  push (@cmds, {
    setting => 'textcat_acceptable_score',
    default => 1.02,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub load_models {
  my ($languages_filename) = @_;

  my @lm;
  my $ngram = {};
  my $rang = 1;
  dbg("textcat: loading languages file %s", $languages_filename);

  local *LM;
  if (!open(LM, $languages_filename)) {
    warn "textcat: cannot open languages file $languages_filename: $!\n";
    return;
  }

  { my($inbuf,$nread,$text); $text = '';
    while ( $nread=read(LM,$inbuf,16384) ) { $text .= $inbuf }
    defined $nread  or die "error reading $languages_filename: $!";
    @lm = split(/\n/, $text, -1);
  }

  close(LM)  or die "error closing $languages_filename: $!";
  # create language ngram maps once
  for (@lm) {
    # look for end delimiter
    if (/^0 (.+)/) {
      $ngram->{"language"} = $1;
      push(@nm, $ngram);
      # reset for next language
      $ngram = {};
      $rang = 1;
    }
    else {
      $ngram->{$_} = $rang++;
    }
  }
  if (! @nm) {
    warn "textcat: no language models loaded\n";
  }
  else {
    dbg("textcat: loaded " . scalar(@nm) . " language models");
  }
}

sub classify {
  my ($inputptr, $conf, %skip) = @_;
  my %results;
  my $maxp = $conf->{textcat_max_ngrams};

  # create ngrams for input
  # limit to 10000 characters, enough for accuracy and still fast enough
  my @unknown = create_lm($inputptr, $conf);

  # test each language
  foreach my $ngram (@nm) {
    my $language = $ngram->{"language"};
    my $short = $language;
    $short =~ s/\..*//;
    next if defined $skip{$short};
    my $i = 0;
    my $p = 0;

    # compute result for language
    for (@unknown) {
      $p += exists($ngram->{$_}) ? abs($ngram->{$_} - $i) : $maxp;
      $i++;
    }
    $results{$language} = $p;
  }
  my @results = sort { $results{$a} <=> $results{$b} } keys %results;

  my $best = $results{$results[0]};

  my @answers = (shift(@results));
  while (@results && $results{$results[0]} < ($conf->{textcat_acceptable_score} * $best)) {
    @answers = (@answers, shift(@results));
  }
  if (@answers > $conf->{textcat_max_languages}) {
    dbg("textcat: can't determine language uniquely enough");
    return ();
  }
  else {
    dbg("textcat: language possibly: " . join(",", @answers));
    return @answers;
  }
}

sub create_lm {
  my ($inputptr, $conf) = @_;
  my %ngram;
  my @sorted;

  # my $non_word_characters = qr/[0-9\s]/;
  for my $word (split(/[0-9\s]+/, ${$_[0]}))
  {
    # Bug 6229: Current TextCat database only works well with
    # lowercase input, lets work around it until it's properly
    # generated and/or locale issues are resolved..
    $word =~ tr/A-Z\xc0-\xd6\xd8-\xde/a-z\xe0-\xf6\xf8-\xfe/
        if $word =~ /[A-Z]/ && $word =~ /[a-zA-Z\xc0-\xd6\xd8-\xde\xe0-\xf6\xf8-\xfe]{4}/;
    $word = "\000" . $word . "\000";
    my $len = length($word);
    my $flen = $len;
    my $i;
    for ($i = 0; $i < $flen; $i++) {
      $len--;
      $ngram{substr($word, $i, 1)}++;
      ($len < 1) ? next : $ngram{substr($word, $i, 2)}++;
      ($len < 2) ? next : $ngram{substr($word, $i, 3)}++;
      ($len < 3) ? next : $ngram{substr($word, $i, 4)}++;
      if ($len > 3) { $ngram{substr($word, $i, 5)}++ };
    }
  }

  if ($conf->{textcat_optimal_ngrams} > 0) {
    # as suggested by Karel P. de Vos <k.vos@elsevier.nl> we speed
    # up sorting by removing singletons, however I have very bad
    # results for short inputs, this way
    @sorted = sort { $ngram{$b} <=> $ngram{$a} }
		   (grep { $ngram{$_} > $conf->{textcat_optimal_ngrams} } keys %ngram);
  }
  else {
    @sorted = sort { $ngram{$b} <=> $ngram{$a} } keys %ngram;
  }
  splice(@sorted, $conf->{textcat_max_ngrams}) if (@sorted > $conf->{textcat_max_ngrams});

  return @sorted;
}

# ---------------------------------------------------------------------------

sub extract_metadata {
  my ($self, $opts) = @_;

  my $msg = $opts->{msg};

  my $body = $msg->get_rendered_body_text_array();
  $body = join("\n", @{$body});
  $body =~ s/^Subject://i;

  my $len = length($body);
  # truncate after 10k; that should be plenty to classify it
  if ($len > 10000) {
    substr($body, 10000) = '';
    $len = 10000;
  }
  # note input length since the check_languages() eval rule also uses it
  $msg->put_metadata("X-Languages-Length", $len);

  # need about 256 bytes for reasonably accurate match (experimentally derived)
  my @matches;
  if ($len >= 256) {
    # generate list of languages to skip
    my %skip;
    $skip{$_} = 1 for split(' ', $opts->{conf}->{inactive_languages});
    delete $skip{$_} for split(' ', $opts->{conf}->{ok_languages});
    dbg("textcat: classifying, skipping: " . join(" ", keys %skip));
    @matches = classify(\$body, $opts->{conf}, %skip);
  }
  else {
    dbg("textcat: message too short for language analysis");
  }

  # free that memory
  undef $body;

  my $matches_str = join(' ', @matches);
  $msg->put_metadata("X-Languages", $matches_str);
  dbg("textcat: X-Languages: \"$matches_str\", X-Languages-Length: $len");
}

# UNWANTED_LANGUAGE_BODY
sub check_language {
  my ($self, $scan) = @_;

  my $msg = $scan->{msg};

  my @languages = split(' ', $scan->{conf}->{ok_languages});

  if (grep { $_ eq "all" } @languages) {
    return 0;
  }

  my $len = $msg->get_metadata("X-Languages-Length");
  my @matches = split(' ', $msg->get_metadata("X-Languages"));

  # not able to get a match, assume it's okay
  return 0 if ! @matches;

  # map of languages that are very often mistaken for another, perhaps with
  # more than 0.02% false positives.  This is used when we're less certain
  # about the result.
  my %mistakable;
  if ($len < 1024 * (scalar @matches)) {
    $mistakable{sco} = 'en';
  }

  # see if any matches are okay
  foreach my $match (@matches) {
    $match =~ s/\..*//;
    $match = $mistakable{$match} if exists $mistakable{$match};
    foreach my $language (@languages) {
      $language = $mistakable{$language} if exists $mistakable{$language};
      if ($match eq $language) {
	return 0;
      }
    }
  }

  return 1;
}

sub check_body_8bits {
  my ($self, $scan, $body) = @_;

  my @languages = split(' ', $scan->{conf}->{ok_languages});

  for (@languages) {
    return 0 if $_ eq "all";
    # this list is initially conservative, it includes any language with
    # a common n-gram sequence of 2+ consecutive bytes matching [\x80-\xff]
    # here are the one more likely to be removed: cs=czech, et=estonian,
    # fi=finnish, hi=hindi, is=icelandic, pt=portuguese, tr=turkish,
    # uk=ukrainian, vi=vietnamese
    return 0 if /^(?:am|ar|be|bg|cs|el|et|fa|fi|he|hi|hy|is|ja|ka|ko|mr|pt|ru|ta|th|tr|uk|vi|yi|zh)$/;
  }

  foreach my $line (@$body) {
    return 1 if $line =~ /[\x80-\xff]{8}/;
  }
  return 0;
}

1;

=back

=cut
