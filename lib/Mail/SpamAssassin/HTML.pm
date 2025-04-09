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

# HTML decoding TODOs
# - add URIs to list for faster URI testing

package Mail::SpamAssassin::HTML;

use strict;
use warnings;
use re 'taint';

use HTML::Parser 3.43 ();
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Constants qw(:sa);
use Mail::SpamAssassin::Util qw(untaint_var);
use Mail::SpamAssassin::HTML::Color;

our @ISA = qw(HTML::Parser);

# elements defined by the HTML 4.01 and XHTML 1.0 DTDs (do not change them!)
# does not include XML
my %elements = map {; $_ => 1 }
  # strict
  qw( a abbr acronym address area b base bdo big blockquote body br button caption cite code col colgroup dd del dfn div dl dt em fieldset form h1 h2 h3 h4 h5 h6 head hr html i img input ins kbd label legend li link map meta noscript object ol optgroup option p param pre q samp script select small span strong style sub sup table tbody td textarea tfoot th thead title tr tt ul var ),
  # loose
  qw( applet basefont center dir font frame frameset iframe isindex menu noframes s strike u ),
  # non-standard tags
  qw( nobr x-sigsep x-tab ),
;

# elements that we want to render, but not count as valid
my %tricks = map {; $_ => 1 }
  # non-standard and non-valid tags
  qw( bgsound embed listing plaintext xmp ),
  # other non-standard tags handled in popfile
  #   blink ilayer multicol noembed nolayer spacer wbr
;

# elements that change text style
my %elements_text_style = map {; $_ => 1 }
  qw( body font table tr th td big small marquee span p div a strong em b i sup sub ),
;

# elements that insert whitespace
my %elements_whitespace = map {; $_ => 1 }
  qw( br div li th td dt dd p hr blockquote pre embed listing plaintext xmp title 
    h1 h2 h3 h4 h5 h6 ),
;

# elements that push URIs
my %elements_uri = map {; $_ => 1 }
  qw( body table tr td a area link img frame iframe embed script form base bgsound meta ),
;

# style attribute not accepted
#my %elements_no_style = map {; $_ => 1 }
#  qw( base basefont head html meta param script style title ),
#;

# permitted element attributes
my %ok_attributes;
$ok_attributes{body}{$_} = 1 for qw( text bgcolor link alink vlink background );
$ok_attributes{font}{$_} = 1 for qw( color face size );
$ok_attributes{marquee}{$_} = 1 for qw( bgcolor background );
$ok_attributes{table}{$_} = 1 for qw( bgcolor style );
$ok_attributes{td}{$_} = 1 for qw( bgcolor style );
$ok_attributes{th}{$_} = 1 for qw( bgcolor style );
$ok_attributes{tr}{$_} = 1 for qw( bgcolor style );
$ok_attributes{span}{$_} = 1 for qw( style );
$ok_attributes{p}{$_} = 1 for qw( style );
$ok_attributes{div}{$_} = 1 for qw( style );
$ok_attributes{a}{$_} = 1 for qw( style );
$ok_attributes{strong}{$_} = 1 for qw( style );
$ok_attributes{em}{$_} = 1 for qw( style );
$ok_attributes{b}{$_} = 1 for qw( style );
$ok_attributes{i}{$_} = 1 for qw( style );
$ok_attributes{big}{$_} = 1 for qw( style );
$ok_attributes{small}{$_} = 1 for qw( style );
$ok_attributes{sup}{$_} = 1 for qw( style );
$ok_attributes{sub}{$_} = 1 for qw( style );

# Map font "size" attribute to font size in pixels
my @font_size_map = (undef, 10, 13, 16, 18, 24, 32, 48);

# Map font-size keyword to font size in pixels
my %font_keyword_map = (
  'xx-small' => 9,
  'x-small' => 10,
  'small' => 13,
  'medium' => 16,
  'large' => 18,
  'x-large' => 24,
  'xx-large' => 32,
);

sub new {
  my ($class, $character_semantics_input, $character_semantics_output) = @_;
  my $self = $class->SUPER::new(
		api_version => 3,
		handlers => [
			start_document => ["html_start", "self"],
			start => ["html_tag", "self,tagname,attr,'+1'"],
			end_document => ["html_end", "self"],
			end => ["html_tag", "self,tagname,attr,'-1'"],
			text => ["html_text", "self,dtext"],
			comment => ["html_comment", "self,text"],
			declaration => ["html_declaration", "self,text"],
		],
		marked_sections => 1);
  $self->{SA_character_semantics_input} = $character_semantics_input;
  $self->{SA_encode_results} =
    $character_semantics_input && !$character_semantics_output;
  $self;
}

sub html_start {
  my ($self) = @_;

  # trigger HTML_MESSAGE
  $self->put_results(html => 1);

  # initial display attributes
  my %default = (tag => "default",
		 fgcolor => Mail::SpamAssassin::HTML::Color->new("black"),
		 bgcolor => Mail::SpamAssassin::HTML::Color->new("white"),
		 font_size => 16);
  push @{ $self->{text_style} }, \%default;
}

sub html_end {
  my ($self) = @_;

  delete $self->{text_style};

  my @uri;

  # add the canonicalized version of each uri to the detail list
  if (defined $self->{uri}) {
    @uri = keys %{$self->{uri}};
  }

  # these keep backward compatibility, albeit a little wasteful
  $self->put_results(uri => \@uri);
  $self->put_results(anchor => $self->{anchor});

  $self->put_results(uri_detail => $self->{uri});
  $self->put_results(uri_truncated => $self->{uri_truncated});

  # final results scalars
  $self->put_results(image_area => $self->{image_area});
  $self->put_results(length => $self->{length});
  $self->put_results(min_size => $self->{min_size});
  $self->put_results(max_size => $self->{max_size});
  if (exists $self->{tags}) {
    $self->put_results(closed_extra_ratio =>
		       ($self->{closed_extra} / $self->{tags}));
  }

  # final result arrays
  $self->put_results(comment => $self->{comment});
  $self->put_results(script => $self->{script});
  $self->put_results(title => $self->{title});

  # final result hashes
  $self->put_results(inside => $self->{inside});

  # end-of-document result values that don't require looking at the text
  if (exists $self->{backhair}) {
    $self->put_results(backhair_count => scalar keys %{ $self->{backhair} });
  }
  if (exists $self->{elements} && exists $self->{tags}) {
    $self->put_results(bad_tag_ratio =>
		       ($self->{tags} - $self->{elements}) / $self->{tags});
  }
  if (exists $self->{elements_seen} && exists $self->{tags_seen}) {
    $self->put_results(non_element_ratio =>
		       ($self->{tags_seen} - $self->{elements_seen}) /
		       $self->{tags_seen});
  }
  if (exists $self->{tags} && exists $self->{obfuscation}) {
    $self->put_results(obfuscation_ratio =>
		       $self->{obfuscation} / $self->{tags});
  }
}

sub put_results {
  my $self = shift;
  my %results = @_;

  while (my ($k, $v) = each %results) {
    $self->{results}{$k} = $v;
  }  
}

sub get_results {
  my ($self) = @_;

  return $self->{results};
}

sub get_rendered_text {
  my $self = shift;
  my %options = @_;

  return join('', @{ $self->{text} }) unless %options;

  my $mask;
  while (my ($k, $v) = each %options) {
    next if !defined $self->{"text_$k"};
    if (!defined $mask) {
      $mask |= $v ? $self->{"text_$k"} : ~ $self->{"text_$k"};
    }
    else {
      $mask &= $v ? $self->{"text_$k"} : ~ $self->{"text_$k"};
    }
  }

  my $text = '';
  my $i = 0;
  for (@{ $self->{text} }) { $text .= $_ if vec($mask, $i++, 1); }
  return $text;
}

sub parse {
  my ($self, $text) = @_;

  $self->{image_area} = 0;
  $self->{title_index} = -1;
  $self->{max_size} = 16;	# start at default size
  $self->{min_size} = 16;	# start at default size
  $self->{closed_html} = 0;
  $self->{closed_body} = 0;
  $self->{closed_extra} = 0;
  $self->{text} = [];		# rendered text
  $self->{length} += untaint_var(length($text));

  # NOTE: We *only* need to fix the rendering when we verify that it
  # differs from what people see in their MUA.  Testing is best done with
  # the most common MUAs and browsers, if you catch my drift.

  # NOTE: HTML::Parser can cope with: <?xml pis>, <? with space>, so we
  # don't need to fix them here.

  # # (outdated claim) HTML::Parser converts &nbsp; into a question mark ("?")
  # # for some reason, so convert them to spaces.  Confirmed in 3.31, at least.
  # ... Actually it doesn't, it is correctly converted into Unicode NBSP,
  # nevertheless it does not hurt to treat it as a space.
  $text =~ s/&nbsp;/ /g;

  # bug 4695: we want "<br/>" to be treated the same as "<br>", and
  # the HTML::Parser API won't do it for us
  $text =~ s/<(\w+)\s*\/>/<$1>/gi;

  # Normalize unicode quotes, messes up attributes parsing
  # U+201C e2 80 9c LEFT DOUBLE QUOTATION MARK
  # U+201D e2 80 9d RIGHT DOUBLE QUOTATION MARK
  # Examples of input:
  # <a href=\x{E2}\x{80}\x{9D}https://foobar.com\x{E2}\x{80}\x{9D}>
  # .. results in uri "\x{E2}\x{80}\x{9D}https://foobar.com\x{E2}\x{80}\x{9D}"
  if (utf8::is_utf8($text)) {
    $text =~ s/(?:\x{201C}|\x{201D})/"/g;
  } else {
    $text =~ s/\x{E2}\x{80}(?:\x{9C}|\x{9D})/"/g;
  }

  if (!$self->UNIVERSAL::can('utf8_mode')) {
    # utf8_mode is cleared by default, only warn if it would need to be set
    warn "message: cannot set utf8_mode, module HTML::Parser is too old\n"
      if !$self->{SA_character_semantics_input};
  } else {
    $self->SUPER::utf8_mode($self->{SA_character_semantics_input} ? 0 : 1);
    my $utf8_mode = $self->SUPER::utf8_mode;
    dbg("message: HTML::Parser utf8_mode %s",
        $utf8_mode ? "on (assumed UTF-8 octets)"
                   : "off (default, assumed Unicode characters)");
  }

  eval {
    local $SIG{__WARN__} = sub {
      my $err = $_[0];
      $err =~ s/\s+/ /gs; $err =~ s/(.*) at .*/$1/s;
      info("message: HTML::Parser warning: $err");
    };
    $self->SUPER::parse($text);
  };

  # bug 7437: deal gracefully with HTML::Parser misbehavior on unclosed <style> and <script> tags
  # (typically from not passing the entire message to spamc, but possibly a DoS attack)
  $self->SUPER::parse("</style>") while exists $self->{inside}{style} && $self->{inside}{style} > 0;
  $self->SUPER::parse("</script>") while exists $self->{inside}{script} && $self->{inside}{script} > 0;

  $self->SUPER::eof;

  return $self->{text};
}

sub html_tag {
  my ($self, $tag, $attr, $num) = @_;
  utf8::encode($tag) if $self->{SA_encode_results};

  my $maybe_namespace = ($tag =~ m@^(?:o|st\d):[\w-]+/?$@);

  if (exists $elements{$tag} || $maybe_namespace) {
    $self->{elements}++;
    $self->{elements_seen}++ if !exists $self->{inside}{$tag};
  }
  $self->{tags}++;
  $self->{tags_seen}++ if !exists $self->{inside}{$tag};
  $self->{inside}{$tag} += $num;
  if ($self->{inside}{$tag} < 0) {
    $self->{inside}{$tag} = 0;
    $self->{closed_extra}++;
  }

  return if $maybe_namespace;

  # ignore non-elements
  if (exists $elements{$tag} || exists $tricks{$tag}) {
    $self->text_style($tag, $attr, $num) if exists $elements_text_style{$tag};

    # bug 5009: things like <p> and </p> both need dealing with
    $self->html_whitespace($tag) if exists $elements_whitespace{$tag};

    # start tags
    if ($num == 1) {
      $self->html_uri($tag, $attr) if exists $elements_uri{$tag};
      $self->html_tests($tag, $attr, $num);
    }
    # end tags
    else {
      $self->{closed_html} = 1 if $tag eq "html";
      $self->{closed_body} = 1 if $tag eq "body";
    }
  }
}

sub html_whitespace {
  my ($self, $tag) = @_;

  # ordered by frequency of tag groups, note: whitespace is always "visible"
  if ($tag eq "br" || $tag eq "div") {
    $self->display_text("\n", whitespace => 1);
  }
  elsif ($tag =~ /^(?:li|t[hd]|d[td]|embed|h\d)$/) {
    $self->display_text(" ", whitespace => 1);
  }
  elsif ($tag =~ /^(?:p|hr|blockquote|pre|listing|plaintext|xmp|title)$/) {
    $self->display_text("\n\n", whitespace => 1);
  }
}

# puts the uri onto the internal array
# note: uri may be blank (<a href=""></a> obfuscation, etc.)
sub push_uri {
  my ($self, $type, $uri) = @_;

  $uri = $self->canon_uri($uri);
  return if $uri eq '';
  utf8::encode($uri) if $self->{SA_encode_results};

  if ($uri =~ /^(?:data|mailto|file|cid|tel):/i) {
    # No target handling required
    $self->{uri}->{$uri}->{types}->{$type} = 1;
  } else {
    my $target = target_uri($self->{base_href} || "", $uri);
    # skip things like <iframe src="" ...>
    $self->{uri}->{$target}->{types}->{$type} = 1  if $target ne '';
  }
}

sub canon_uri {
  my ($self, $uri) = @_;

  # URIs don't have leading/trailing whitespace ...
  $uri =~ s/^[\s\xA0]+//;
  $uri =~ s/[\s\xA0]+$//;

  # Make sure all the URIs are nice and short
  if (length $uri > MAX_URI_LENGTH) {
    $self->{'uri_truncated'} = 1;
    $uri = substr $uri, 0, MAX_URI_LENGTH;
  }

  return $uri;
}

sub html_uri {
  my ($self, $tag, $attr) = @_;

  # ordered by frequency of tag groups
  if ($tag =~ /^(?:body|table|tr|td)$/) {
    if (defined $attr->{background}) {
      $self->push_uri($tag, $attr->{background});
    }
  }
  elsif ($tag =~ /^(?:a|area|link)$/) {
    while ( my ( $k, $v ) = each %$attr ) {
      # read uris from bad formatted html as well
      if($k =~ /\w{1,8}\/href/) {
        delete($attr->{$k});
        $attr->{href} = $v;
      }
    }
    if (defined $attr->{href}) {
      # Remove the Unicode "replacement character" from the url
      if (utf8::is_utf8($attr->{href})) {
        $attr->{href} =~ s/\x{FEFF}//g;
      } else {
        $attr->{href} =~ s/\x{EF}\x{BB}\x{BF}//g;
      }
      $self->push_uri($tag, $attr->{href});
    }
    if (defined $attr->{'data-saferedirecturl'}) {
      $self->push_uri($tag, $attr->{'data-saferedirecturl'});
    }
  }
  elsif ($tag =~ /^(?:img|frame|iframe|embed|script|bgsound)$/) {
    while ( my ( $k, $v ) = each %$attr ) {
      # read uris from bad formatted html as well
      if($k =~ /\w{1,8}\/src/) {
        delete($attr->{$k});
        $attr->{src} = $v;
      }
    }
    if (defined $attr->{src}) {
      $self->push_uri($tag, $attr->{src});
    }
  }
  elsif ($tag eq "form") {
    if (defined $attr->{action}) {
      $self->push_uri($tag, $attr->{action});
    }
  }
  elsif ($tag eq "base") {
    if (my $uri = $attr->{href}) {
      $uri = $self->canon_uri($uri);

      # use <BASE HREF="URI"> to turn relative links into absolute links

      # even if it is a base URI, handle like a normal URI as well
      $self->push_uri($tag, $uri);

      # a base URI will be ignored by browsers unless it is an absolute
      # URI of a standard protocol
      if ($uri =~ m@^(?:https?|ftp):/{0,2}@i) {
	# remove trailing filename, if any; base URIs can have the
	# form of "http://foo.com/index.html"
	$uri =~ s@^([a-z]+:/{0,2}[^/]+/.*?)[^/\.]+\.[^/\.]{2,4}$@$1@i;

	# Make sure it ends in a slash
	$uri .= "/" unless $uri =~ m@/$@;
        utf8::encode($uri) if $self->{SA_encode_results};
	$self->{base_href} = $uri;
      }
    }
  }
  elsif ($tag eq "meta" &&
    exists $attr->{'http-equiv'} &&
    exists $attr->{content} &&
    $attr->{'http-equiv'} =~ /refresh/i &&
    $attr->{content} =~ /\burl\s*=/i)
  {
      my $uri = $attr->{content};
      $uri =~ s/^.*\burl\s*=\s*//i;
      $uri =~ s/\s*;.*//i;
      $self->push_uri($tag, $uri);
  }
}

# this might not be quite right, may need to pay attention to table nesting
sub close_table_tag {
  my ($self, $tag) = @_;

  # don't close if never opened
  return unless grep { $_->{tag} eq $tag } @{ $self->{text_style} };

  my $top;
  while (@{ $self->{text_style} } && ($top = $self->{text_style}[-1]->{tag})) {
    if (($tag eq "td" && ($top eq "font" || $top eq "td")) ||
	($tag eq "tr" && $top =~ /^(?:font|td|tr)$/))
    {
      pop @{ $self->{text_style} };
    }
    else {
      last;
    }
  }
}

sub close_tag {
  my ($self, $tag) = @_;

  # don't close if never opened
  return if !grep { $_->{tag} eq $tag } @{ $self->{text_style} };

  # close everything up to and including tag
  while (my %current = %{ pop @{ $self->{text_style} } }) {
    last if $current{tag} eq $tag;
  }
}

sub text_style {
  my ($self, $tag, $attr, $num) = @_;

  # treat <th> as <td>
  $tag = "td" if $tag eq "th";

  # open
  if ($num == 1) {
    # HTML browsers generally only use first <body> for colors,
    # so only push if we haven't seen a body tag yet
    if ($tag eq "body") {
      # TODO: skip if we've already seen body
    }

    # close elements with optional end tags
    $self->close_table_tag($tag) if ($tag eq "td" || $tag eq "tr");

    # copy current text state
    my %new = %{ $self->{text_style}[-1] };

    # change tag name!
    $new{tag} = $tag;

    # big and small tags
    if ($tag eq "big") {
      $new{font_size} *= 1.2;
    }
    if ($tag eq "small") {
      $new{font_size} /= 1.2;
    }

    # tag attributes
    for my $name (keys %$attr) {
      next unless exists $ok_attributes{$tag}{$name};
      if ($name eq "text" || $name eq "color") {
	# two different names for text color
        eval {
          $new{fgcolor} = Mail::SpamAssassin::HTML::Color->new($attr->{$name});
          1;
        } or do {
          $self->put_results(font_invalid_color => 1);
        }
      }
      elsif ($name eq "bgcolor") {
        eval {
          $new{bgcolor} = Mail::SpamAssassin::HTML::Color->new($attr->{bgcolor});
          1;
        } or do {
          $self->put_results(font_invalid_color => 1);
        }
      }
      elsif ($name eq "size") {
        my $size;
	if ($attr->{size} =~ /^\s*([+-]\d+)/) {
	  # relative font size
          $size = 3 + $1;
	}
	elsif ($attr->{size} =~ /^\s*(\d+)/) {
	  # absolute font size
	  $size = $1;
        }
        if (defined($size)) {
          if ($size < 1) {
            $size = 1;
            $self->put_results(font_invalid_size => 1);
          } elsif ($size > 7) {
            $size = 7;
            $self->put_results(font_invalid_size => 1);
          }
          $new{font_size} = $font_size_map[$size];
        } else {
          $self->put_results(font_invalid_size => 1);
        }
      }
      elsif ($name eq 'style') {
        $new{style} = $attr->{style};
	my @parts = split(/;/, $new{style});
	foreach (@parts) {
          s/\s*!\s*important$//i; # Remove !important flag
          if (/^\s*(background-)?color:\s*(.+?)\s*$/i) {
            my $whcolor = $1 ? 'bgcolor' : 'fgcolor';
            my $value = lc($2);

            if ($value eq 'currentcolor') {
              # inherit color from parent foreground
              $new{$whcolor} = $self->{text_style}[-1]->{fgcolor};
            } elsif ($value ne 'inherit') {
              eval {
                $new{$whcolor} = Mail::SpamAssassin::HTML::Color->new($value);
                1;
              } or do {
                $self->put_results(font_invalid_color => 1);
              }
            }
          }
          elsif (/^\s*background:\s*(.+?)\s*$/i) {
            # parse CSS background property (Bug 8210)
            my $layers = parse_css_background($1);
            # loop through values in the bottom layer and look for valid colors
            for my $value (@{$layers->[-1]}) {
              if (lc($value) eq 'currentcolor') {
                # inherit color from parent foreground
                $new{bgcolor} = $self->{text_style}[-1]->{fgcolor};
                last;
              }
              my $color = eval { Mail::SpamAssassin::HTML::Color->new($value) };
              if (defined $color) {
                $new{bgcolor} = $color;
                last;
              }
            }
	  }
          elsif (/^\s*font-size:\s*(.+?)\s*$/i) {
            eval {
              $new{font_size} = $self->parse_font_size($1);
              1;
            } or do {
              $self->put_results(font_invalid_size => 1);
            }
          }
	  elsif (/^\s*([a-z_-]+)\s*:\s*(\S.*?)\s*$/i) {
	    # "display: none", "visibility: hidden", etc.
	    $new{'style_'.lc($1)} = lc($2);
	  }
	}
      }
      else {
        # attribute is probably okay
	$new{$name} = $attr->{$name};
      }

      # blend new background color with parent background color
      # Note: blending has no effect if the color is opaque (alpha = 1)
      $new{bgcolor}->blend($self->{text_style}[-1]->{bgcolor});
      # blend new text color with new background color
      $new{fgcolor}->blend($new{bgcolor});

      if ($new{font_size} > $self->{max_size}) {
	$self->{max_size} = $new{font_size};
      }
      elsif ($new{font_size} < $self->{min_size}) {
	$self->{min_size} = $new{font_size};
      }
    }
    push @{ $self->{text_style} }, \%new;
  }
  # explicitly close a tag
  else {
    if ($tag ne "body") {
      # don't close body since browsers seem to render text after </body>
      $self->close_tag($tag);
    }
  }
}

# Parses a CSS background property value.
# Returns an arrayref of layers, each layer is an arrayref of values such as
# [
#   'rgb(255, 192, 0)',
#   '35%',
#   'url("../../media/examples/lizard.png")'
# ]
# https://developer.mozilla.org/en-US/docs/Web/CSS/background
sub parse_css_background {
  my ($background) = @_;

  my @layers;
  my @tokens;
  my @stack;
  my ($state,$token) = (0,'');
  for (my $i=0;$i < length($background);$i++) {
    my $ch = substr($background, $i, 1);
    if ($state == 0) {
      if ($ch eq ' ') {
        push @tokens, $token if $token ne '';
        $token = '';
      } elsif ($ch eq '(') {
        $token .= $ch;
        push @stack, $state;
        $state = 1;
      } elsif ($ch eq '"') {
        $token .= $ch;
        push @stack, $state;
        $state = 2;
      } elsif ($ch eq q(')) {
        $token .= $ch;
        push @stack, $state;
        $state = 3;
      } elsif ($ch eq ',') {
        push @tokens, $token if $token ne '';
        $token = '';
        push @layers, [ @tokens ];
        @tokens = ();
      } else {
        $token .= $ch;
      }
    } elsif ($state == 1) {
      if ($ch eq ')') {
        $token .= $ch;
        push @tokens, $token;
        $token = '';
        $state = pop @stack;
      } elsif ($ch eq '"') {
        $token .= $ch;
        push(@stack, $state);
        $state = 2;
      } elsif ($ch eq q(')) {
        $token .= $ch;
        push(@stack, $state);
        $state = 3;
      } else {
        $token .= $ch;
      }
    } elsif ($state == 2) {
      if ($ch eq '"') {
        $token .= $ch;
        $state = pop @stack;
      } else {
        $token .= $ch;
      }
    } elsif ($state == 3) {
      if ($ch eq q(')) {
        $token .= $ch;
        $state = pop @stack;
      } else {
        $token .= $ch;
      }
    }
  }

  if ($token ne '') {
    push @tokens, $token;
  }
  if ( scalar @tokens > 0 ) {
    push @layers, [ @tokens ];
  }

  return \@layers;

}

# Parses a font-size value.
# Returns the size in pixels.
sub parse_font_size {
  my $self = shift;
  my $size = lc(shift);

  $size =~ s/^\s+|\s+$//g; # trim whitespace

  if ($size =~ /^([\d.]+)\s*(px|pt|r?em|ex|%)?$/) {
    my $value = $1;
    my $unit = $2 // 'px';
    if ($unit eq 'px') {
      return $value;
    }
    elsif ($unit eq 'pt') {
      return $value * 1.33;
    }
    elsif ($unit eq 'em') {
      return $value * $self->{text_style}[-1]->{font_size};
    }
    elsif ($unit eq 'rem') {
      return $value * 16;
    }
    elsif ($unit eq 'ex') {
      return $value * 7;
    }
    elsif ($unit eq '%') {
      return $value / 100 * $self->{text_style}[-1]->{font_size};
    }
  }
  elsif (exists($font_keyword_map{$size})) {
    return $font_keyword_map{lc $size};
  }
  elsif ($size eq 'larger') {
    return $self->{text_style}[-1]->{font_size} * 1.2;
  }
  elsif ($size eq 'smaller') {
    return $self->{text_style}[-1]->{font_size} / 1.2;
  }
  elsif ($size eq 'inherit') {
    return $self->{text_style}[-1]->{font_size};
  }
  elsif ($size eq 'initial') {
    return 16;
  }

  die "Invalid font size: $size";
}

sub html_font_invisible {
  my ($self, $text) = @_;

  my $fg = $self->{text_style}[-1]->{fgcolor};
  my $bg = $self->{text_style}[-1]->{bgcolor};
  my $font_size = $self->{text_style}[-1]->{'font_size'};
  my $display = $self->{text_style}[-1]->{style_display};
  my $visibility = $self->{text_style}[-1]->{style_visibility};

  # size too small
  if ($font_size < 8) {
    return 1;
  }

  # <span style="display: none">
  if ($display && lc $display eq 'none') {
    return 1;
  }

  # <span style="visibility: hidden">
  if ($visibility && lc $visibility eq 'hidden') {
    return 1;
  }

  # low-contrast text
  # the text is very difficult to read if the distance is under 12,
  # a limit of 14 to 16 might be okay if the usage significantly
  # increases (near-invisible text is at about 0.95% of spam and
  # 1.25% of HTML spam right now), but please test any changes first
  if ($fg->distance($bg) < 12 ) {
    $self->put_results(font_low_contrast => 1);
    return 1;
  }

  return 0;
}

sub html_tests {
  my ($self, $tag, $attr, $num) = @_;

  if ($tag eq "font" && exists $attr->{face}) {
    # Fixes from Bug 5956, 7312
    # Examples seen in ham:
    #  "Tahoma", Verdana, Arial, sans-serif
    #  'Montserrat', sans-serif
    #  Arial,Helvetica,Sans-Serif;
    #  .SFUIDisplay
    #  hirakakupro-w3
    # TODO: There's still the problem completely foreign unicode strings,
    # probably this rule should be deprecated.
    if ($attr->{face} !~ /^\s*["'.]?[a-z ][a-z -]*[a-z]\d?["']?(?:,\s*["']?[a-z][a-z -]*[a-z]\d?["']?)*;?$/i) {
      $self->put_results(font_face_bad => 1);
    }
  }
  if ($tag eq "img" && exists $self->{inside}{a} && $self->{inside}{a} > 0) {
    my $uri = $self->{anchor_last};
    utf8::encode($uri) if $self->{SA_encode_results};
    $self->{uri}->{$uri}->{anchor_text}->[-1] .= "<img>\n";
    $self->{anchor}->[-1] .= "<img>\n";
  }

  if ($tag eq "img" && exists $attr->{width} && exists $attr->{height}) {
    my $width = 0;
    my $height = 0;
    my $area = 0;

    # assume 800x600 screen for percentage values
    if ($attr->{width} =~ /^(\d+)(\%)?$/) {
      $width = $1;
      $width *= 8 if (defined $2 && $2 eq "%");
    }
    if ($attr->{height} =~ /^(\d+)(\%)?$/) {
      $height = $1;
      $height *= 6 if (defined $2 && $2 eq "%");
    }
    # guess size
    $width = 200 if $width <= 0;
    $height = 200 if $height <= 0;
    if ($width > 0 && $height > 0) {
      $area = $width * $height;
      $self->{image_area} += $area;
    }
  }
  if ($tag eq "form" && exists $attr->{action}) {
    $self->put_results(form_action_mailto => 1) if $attr->{action} =~ /mailto:/i
  }
  if ($tag eq "object" || $tag eq "embed") {
    $self->put_results(embeds => 1);
  }

  # special text delimiters - <a> and <title>
  if ($tag eq "a") {
    my $uri = $self->{anchor_last} =
      (exists $attr->{href} ? $self->canon_uri($attr->{href}) : "");
    utf8::encode($uri) if $self->{SA_encode_results};
    push(@{$self->{uri}->{$uri}->{anchor_text}}, '');
    push(@{$self->{anchor}}, '');
  }
  if ($tag eq "title") {
    $self->{title_index}++;
    $self->{title}->[$self->{title_index}] = "";
  }

  if ($tag eq "meta" &&
      exists $attr->{'http-equiv'} &&
      exists $attr->{content} &&
      $attr->{'http-equiv'} =~ /Content-Type/i &&
      $attr->{content} =~ /\bcharset\s*=\s*["']?([^"']+)/i)
  {
    $self->{charsets} .= exists $self->{charsets} ? " $1" : $1;
  }

  # todo: capture URI from meta refresh tag
}

sub display_text {
  my $self = shift;
  my $text = shift;
  my %display = @_;

  # Unless it's specified to be invisible, then it's not invisible. ;)
  if (!exists $display{invisible}) {
    $display{invisible} = 0;
  }

  if ($display{whitespace}) {
    # trim trailing whitespace from previous element if it was not whitespace
    # and it was not invisible
    if (@{ $self->{text} } &&
	(!defined $self->{text_whitespace} ||
	 !vec($self->{text_whitespace}, $#{$self->{text}}, 1)) &&
	(!defined $self->{text_invisible} ||
	 !vec($self->{text_invisible}, $#{$self->{text}}, 1)))
    {
      $self->{text}->[-1] =~ s/ $//;
    }
  }
  else {
    # NBSP:  UTF-8: C2 A0, ISO-8859-*: A0
    $text =~ s/[ \t\n\r\f\x0b]+|\xc2\xa0/ /gs;
    # trim leading whitespace if previous element was whitespace 
    # and current element is not invisible
    if (@{ $self->{text} } && !$display{invisible} &&
	defined $self->{text_whitespace} &&
	vec($self->{text_whitespace}, $#{$self->{text}}, 1))
    {
      $text =~ s/^ //;
    }
  }
  push @{ $self->{text} }, $text;
  while (my ($k, $v) = each %display) {
    my $textvar = "text_".$k;
    if (!exists $self->{$textvar}) { $self->{$textvar} = ''; }
    vec($self->{$textvar}, $#{$self->{text}}, 1) = $v;
  }
}

sub html_text {
  my ($self, $text) = @_;
  utf8::encode($text) if $self->{SA_encode_results};

  # text that is not part of body
  if (exists $self->{inside}{script} && $self->{inside}{script} > 0)
  {
    push @{ $self->{script} }, $text;
    return;
  }
  if (exists $self->{inside}{style} && $self->{inside}{style} > 0) {
    return;
  }

  # text that is part of body and also stored separately
  if (exists $self->{inside}{a} && $self->{inside}{a} > 0) {
    # this doesn't worry about nested anchors
    my $uri = $self->{anchor_last};
    utf8::encode($uri) if $self->{SA_encode_results};
    $self->{uri}->{$uri}->{anchor_text}->[-1] .= $text;
    $self->{anchor}->[-1] .= $text;
  }
  if (exists $self->{inside}{title} && $self->{inside}{title} > 0) {
    $self->{title}->[$self->{title_index}] .= $text;
  }

  my $invisible_for_bayes = 0;

  # NBSP:  UTF-8: C2 A0, ISO-8859-*: A0
  # Bug 7374 - regex recursion limit exceeded
  #if ($text !~ /^(?:[ \t\n\r\f\x0b]|\xc2\xa0)*\z/s) {
  # .. alternative way, remove from string and see if there's anything left
  if (do {(my $tmp = $text) =~ s/(?:[ \t\n\r\f\x0b]|\xc2\xa0)//gs; length($tmp)}) {
    $invisible_for_bayes = $self->html_font_invisible($text);
  }

  if (exists $self->{text}->[-1]) {
    # ideas discarded since they would be easy to evade:
    # 1. using \w or [A-Za-z] instead of \S or non-punctuation
    # 2. exempting certain tags
    # no re "strict";  # since perl 5.21.8: Ranges of ASCII printables...
    if ($text =~ /^[^\s\x21-\x2f\x3a-\x40\x5b-\x60\x7b-\x7e]/s &&
	$self->{text}->[-1] =~ /[^\s\x21-\x2f\x3a-\x40\x5b-\x60\x7b-\x7e]\z/s)
    {
      $self->{obfuscation}++;
    }
    if ($self->{text}->[-1] =~
	/\b([^\s\x21-\x2f\x3a-\x40\x5b-\x60\x7b-\x7e]{1,7})\z/s)
    {
      my $start = length($1);
      if ($text =~ /^([^\s\x21-\x2f\x3a-\x40\x5b-\x60\x7b-\x7e]{1,7})\b/s) {
	$self->{backhair}->{$start . "_" . length($1)}++;
      }
    }
  }

  if ($invisible_for_bayes) {
    $self->display_text($text, invisible => 1);
  }
  else {
    $self->display_text($text);
  }
}

# note: $text includes <!-- and -->
sub html_comment {
  my ($self, $text) = @_;
  utf8::encode($text) if $self->{SA_encode_results};

  push @{ $self->{comment} }, $text;
}

sub html_declaration {
  my ($self, $text) = @_;
  utf8::encode($text) if $self->{SA_encode_results};

  if ($text =~ /^<!doctype/i) {
    my $tag = "!doctype";
    $self->{elements}++;
    $self->{tags}++;
    $self->{inside}{$tag} = 0;
  }
}

###########################################################################

sub dec2hex {
  my ($dec) = @_;
  my ($pre) = '';

  if ($dec < 16) {
    $pre = '0';
  }

  return sprintf("$pre%lx", $dec);
}


use constant URI_STRICT => 0;

# resolving relative URIs as defined in RFC 2396 (steps from section 5.2)
# using draft http://www.gbiv.com/protocols/uri/rev-2002/rfc2396bis.html
sub _parse_uri {
  my ($u) = @_;
  my %u;
  ($u{scheme}, $u{authority}, $u{path}, $u{query}, $u{fragment}) =
    $u =~ m|^(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|;
  return %u;
}

sub _remove_dot_segments {
  my ($input) = @_;
  my $output = "";

  $input =~ s@^(?:\.\.?/)@/@;

  while ($input) {
    if ($input =~ s@^/\.(?:$|/)@/@) {
    }
    elsif ($input =~ s@^/\.\.(?:$|/)@/@) {
      $output =~ s@/?[^/]*$@@;
    }
    elsif ($input =~ s@(/?[^/]*)@@) {
      $output .= $1;
    }
  }
  return $output;
}

sub _merge_uri {
  my ($base_authority, $base_path, $r_path) = @_;

  if (defined $base_authority && !$base_path) {
    return "/" . $r_path;
  }
  else {
    if (index($base_path, '/') >= 0) {
      $base_path =~ s|(?<=/)[^/]*$||;
    }
    else {
      $base_path = "";
    }
    return $base_path . $r_path;
  }
}

sub target_uri {
  my ($base, $r) = @_;

  my %r = _parse_uri($r);	# parsed relative URI
  my %base = _parse_uri($base);	# parsed base URI
  my %t;			# generated temporary URI

  if ((not URI_STRICT) and
      (defined $r{scheme} && defined $base{scheme}) and
      ($r{scheme} eq $base{scheme}))
  {
    undef $r{scheme};
  }

  if (defined $r{scheme}) {
    $t{scheme} = $r{scheme};
    $t{authority} = $r{authority};
    $t{path} = _remove_dot_segments($r{path});
    $t{query} = $r{query};
  }
  else {
    if (defined $r{authority}) {
      $t{authority} = $r{authority};
      $t{path} = _remove_dot_segments($r{path});
      $t{query} = $r{query};
    }
    else {
      if ($r{path} eq "") {
	$t{path} = $base{path};
	if (defined $r{query}) {
	  $t{query} = $r{query};
	}
	else {
	  $t{query} = $base{query};
	}
      }
      else {
	if ($r{path} =~ m|^/|) {
	  $t{path} = _remove_dot_segments($r{path});
	}
	else {
	  $t{path} = _merge_uri($base{authority}, $base{path}, $r{path});
	  $t{path} = _remove_dot_segments($t{path});
	}
	$t{query} = $r{query};
      }
      $t{authority} = $base{authority};
    }
    $t{scheme} = $base{scheme};
  }
  $t{fragment} = $r{fragment};

  # recompose URI
  my $result = "";
  if ($t{scheme}) {
    $result .= $t{scheme} . ":";
  }
  elsif (defined $t{authority}) {
    # this block is not part of the RFC
    # TODO: figure out what MUAs actually do with unschemed URIs
    # maybe look at URI::Heuristic
    if ($t{authority} =~ /^www\d*\./i) {
      # some spammers are using unschemed URIs to escape filters
      $result .= "http:";
    }
    elsif ($t{authority} =~ /^ftp\d*\./i) {
      $result .= "ftp:";
    }
  }
  if (defined $t{authority}) {
    $result .= "//" . $t{authority};
  }
  $result .= $t{path};
  if (defined $t{query}) {
    $result .= "?" . $t{query};
  }
  if (defined $t{fragment}) {
    $result .= "#" . $t{fragment};
  }
  return $result;
}

1;
__END__
