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

require 5.008;     # need basic Unicode support for HTML::Parser::utf8_mode
# require 5.008008;  # Bug 3787; [perl #37950]: Malformed UTF-8 character ...

use HTML::Parser 3.43 ();
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Constants qw(:sa);
use Mail::SpamAssassin::Util qw(untaint_var);

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
  qw( body font table tr th td big small basefont marquee span p div ),
;

# elements that insert whitespace
my %elements_whitespace = map {; $_ => 1 }
  qw( br div li th td dt dd p hr blockquote pre embed listing plaintext xmp title 
    h1 h2 h3 h4 h5 h6 ),
;

# elements that push URIs
my %elements_uri = map {; $_ => 1 }
  qw( body table tr td a area link img frame iframe embed script form base bgsound ),
;

# style attribute not accepted
#my %elements_no_style = map {; $_ => 1 }
#  qw( base basefont head html meta param script style title ),
#;

# permitted element attributes
my %ok_attributes;
$ok_attributes{basefont}{$_} = 1 for qw( color face size );
$ok_attributes{body}{$_} = 1 for qw( text bgcolor link alink vlink background );
$ok_attributes{font}{$_} = 1 for qw( color face size );
$ok_attributes{marquee}{$_} = 1 for qw( bgcolor background );
$ok_attributes{table}{$_} = 1 for qw( bgcolor );
$ok_attributes{td}{$_} = 1 for qw( bgcolor );
$ok_attributes{th}{$_} = 1 for qw( bgcolor );
$ok_attributes{tr}{$_} = 1 for qw( bgcolor );
$ok_attributes{span}{$_} = 1 for qw( style );
$ok_attributes{p}{$_} = 1 for qw( style );
$ok_attributes{div}{$_} = 1 for qw( style );

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
  $self->{basefont} = 3;
  my %default = (tag => "default",
		 fgcolor => "#000000",
		 bgcolor => "#ffffff",
		 size => $self->{basefont});
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
  $self->{max_size} = 3;	# start at default size
  $self->{min_size} = 3;	# start at default size
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
  # ... Actually it doesn't, it is correctly coverted into Unicode NBSP,
  # nevertheless it does not hurt to treat it as a space.
  $text =~ s/&nbsp;/ /g;

  # bug 4695: we want "<br/>" to be treated the same as "<br>", and
  # the HTML::Parser API won't do it for us
  $text =~ s/<(\w+)\s*\/>/<$1>/gi;

  if (!$self->UNIVERSAL::can('utf8_mode')) {
    # utf8_mode is cleared by default, only warn if it would need to be set
    warn "message: cannot set utf8_mode, module HTML::Parser is too old\n"
      if !$self->{SA_character_semantics_input};
  } else {
    $self->SUPER::utf8_mode($self->{SA_character_semantics_input} ? 0 : 1);
    dbg("message: HTML::Parser utf8_mode %s",
        $self->SUPER::utf8_mode ? "on (assumed UTF-8 octets)"
                                : "off (default, assumed Unicode characters)");
  }
  $self->SUPER::parse($text);
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
  utf8::encode($uri) if $self->{SA_encode_results};

  my $target = target_uri($self->{base_href} || "", $uri);

  # skip things like <iframe src="" ...>
  $self->{uri}->{$uri}->{types}->{$type} = 1  if $uri ne '';
}

sub canon_uri {
  my ($self, $uri) = @_;

  # URIs don't have leading/trailing whitespace ...
  $uri =~ s/^\s+//;
  $uri =~ s/\s+$//;

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
    if (defined $attr->{href}) {
      $self->push_uri($tag, $attr->{href});
    }
  }
  elsif ($tag =~ /^(?:img|frame|iframe|embed|script|bgsound)$/) {
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

    # change basefont (only change size)
    if ($tag eq "basefont" &&
	exists $attr->{size} && $attr->{size} =~ /^\s*(\d+)/)
    {
      $self->{basefont} = $1;
      return;
    }

    # close elements with optional end tags
    $self->close_table_tag($tag) if ($tag eq "td" || $tag eq "tr");

    # copy current text state
    my %new = %{ $self->{text_style}[-1] };

    # change tag name!
    $new{tag} = $tag;

    # big and small tags
    if ($tag eq "big") {
      $new{size} += 1;
      push @{ $self->{text_style} }, \%new;
      return;
    }
    if ($tag eq "small") {
      $new{size} -= 1;
      push @{ $self->{text_style} }, \%new;
      return;
    }

    # tag attributes
    for my $name (keys %$attr) {
      next unless exists $ok_attributes{$tag}{$name};
      if ($name eq "text" || $name eq "color") {
	# two different names for text color
	$new{fgcolor} = name_to_rgb($attr->{$name});
      }
      elsif ($name eq "size") {
	if ($attr->{size} =~ /^\s*([+-]\d+)/) {
	  # relative font size
	  $new{size} = $self->{basefont} + $1;
	}
	elsif ($attr->{size} =~ /^\s*(\d+)/) {
	  # absolute font size
	  $new{size} = $1;
        }
      }
      elsif ($name eq 'style') {
        $new{style} = $attr->{style};
	my @parts = split(/;/, $new{style});
	foreach (@parts) {
	  if (/^\s*(background-)?color:\s*(.+)\s*$/i) {
	    my $whcolor = $1 ? 'bgcolor' : 'fgcolor';
	    my $value = lc $2;

	    if ($value =~ /rgb/) {
	      $value =~ tr/0-9,//cd;
	      my @rgb = split(/,/, $value);
              $new{$whcolor} = sprintf("#%02x%02x%02x",
                                       map { !$_ ? 0 : $_ > 255 ? 255 : $_ }
                                           @rgb[0..2]);
            }
	    else {
	      $new{$whcolor} = name_to_rgb($value);
	    }
	  }
	  elsif (/^\s*([a-z_-]+)\s*:\s*(\S.*?)\s*$/i) {
	    # "display: none", "visibility: hidden", etc.
	    $new{'style_'.$1} = $2;
	  }
	}
      }
      elsif ($name eq "bgcolor") {
	# overwrite with hex value, $new{bgcolor} is set below
        $attr->{bgcolor} = name_to_rgb($attr->{bgcolor});
      }
      else {
        # attribute is probably okay
	$new{$name} = $attr->{$name};
      }

      if ($new{size} > $self->{max_size}) {
	$self->{max_size} = $new{size};
      }
      elsif ($new{size} < $self->{min_size}) {
	$self->{min_size} = $new{size};
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

sub html_font_invisible {
  my ($self, $text) = @_;

  my $fg = $self->{text_style}[-1]->{fgcolor};
  my $bg = $self->{text_style}[-1]->{bgcolor};
  my $size = $self->{text_style}[-1]->{size};
  my $display = $self->{text_style}[-1]->{style_display};
  my $visibility = $self->{text_style}[-1]->{style_visibility};

  # invisibility
  if (substr($fg,-6) eq substr($bg,-6)) {
    $self->put_results(font_low_contrast => 1);
    return 1;
  # near-invisibility
  } elsif ($fg =~ /^\#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/) {
    my ($r1, $g1, $b1) = (hex($1), hex($2), hex($3));

    if ($bg =~ /^\#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/) {
      my ($r2, $g2, $b2) = (hex($1), hex($2), hex($3));

      my $r = ($r1 - $r2);
      my $g = ($g1 - $g2);
      my $b = ($b1 - $b2);

      # geometric distance weighted by brightness
      # maximum distance is 191.151823601032
      my $distance = ((0.2126*$r)**2 + (0.7152*$g)**2 + (0.0722*$b)**2)**0.5;

      # the text is very difficult to read if the distance is under 12,
      # a limit of 14 to 16 might be okay if the usage significantly
      # increases (near-invisible text is at about 0.95% of spam and
      # 1.25% of HTML spam right now), but please test any changes first
      if ($distance < 12) {
	$self->put_results(font_low_contrast => 1);
	return 1;
      }
    }
  }

  
  # invalid color
  if ($fg eq 'invalid' or $bg eq 'invalid') {
    $self->put_results(font_invalid_color => 1);
    return 1;
  }

  # size too small
  if ($size <= 1) {
    return 1;
  }

  # <span style="display: none">
  if ($display && lc $display eq 'none') {
    return 1;
  }

  if ($visibility && lc $visibility eq 'hidden') {
    return 1;
  }

  return 0;
}

sub html_tests {
  my ($self, $tag, $attr, $num) = @_;

  if ($tag eq "font" && exists $attr->{face}) {
    if ($attr->{face} !~ /^[a-z ][a-z -]*[a-z](?:,\s*[a-z][a-z -]*[a-z])*$/i) {
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
  if ($text !~ /^(?:[ \t\n\r\f\x0b]|\xc2\xa0)*\z/s) {
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

my %html_color = (
  # HTML 4 defined 16 colors
  aqua => 0x00ffff,
  black => 0x000000,
  blue => 0x0000ff,
  fuchsia => 0xff00ff,
  gray => 0x808080,
  green => 0x008000,
  lime => 0x00ff00,
  maroon => 0x800000,
  navy => 0x000080,
  olive => 0x808000,
  purple => 0x800080,
  red => 0xff0000,
  silver => 0xc0c0c0,
  teal => 0x008080,
  white => 0xffffff,
  yellow => 0xffff00,
  # colors specified in CSS3 color module
  aliceblue => 0xf0f8ff,
  antiquewhite => 0xfaebd7,
  aqua => 0x00ffff,
  aquamarine => 0x7fffd4,
  azure => 0xf0ffff,
  beige => 0xf5f5dc,
  bisque => 0xffe4c4,
  black => 0x000000,
  blanchedalmond => 0xffebcd,
  blue => 0x0000ff,
  blueviolet => 0x8a2be2,
  brown => 0xa52a2a,
  burlywood => 0xdeb887,
  cadetblue => 0x5f9ea0,
  chartreuse => 0x7fff00,
  chocolate => 0xd2691e,
  coral => 0xff7f50,
  cornflowerblue => 0x6495ed,
  cornsilk => 0xfff8dc,
  crimson => 0xdc143c,
  cyan => 0x00ffff,
  darkblue => 0x00008b,
  darkcyan => 0x008b8b,
  darkgoldenrod => 0xb8860b,
  darkgray => 0xa9a9a9,
  darkgreen => 0x006400,
  darkgrey => 0xa9a9a9,
  darkkhaki => 0xbdb76b,
  darkmagenta => 0x8b008b,
  darkolivegreen => 0x556b2f,
  darkorange => 0xff8c00,
  darkorchid => 0x9932cc,
  darkred => 0x8b0000,
  darksalmon => 0xe9967a,
  darkseagreen => 0x8fbc8f,
  darkslateblue => 0x483d8b,
  darkslategray => 0x2f4f4f,
  darkslategrey => 0x2f4f4f,
  darkturquoise => 0x00ced1,
  darkviolet => 0x9400d3,
  deeppink => 0xff1493,
  deepskyblue => 0x00bfff,
  dimgray => 0x696969,
  dimgrey => 0x696969,
  dodgerblue => 0x1e90ff,
  firebrick => 0xb22222,
  floralwhite => 0xfffaf0,
  forestgreen => 0x228b22,
  fuchsia => 0xff00ff,
  gainsboro => 0xdcdcdc,
  ghostwhite => 0xf8f8ff,
  gold => 0xffd700,
  goldenrod => 0xdaa520,
  gray => 0x808080,
  green => 0x008000,
  greenyellow => 0xadff2f,
  grey => 0x808080,
  honeydew => 0xf0fff0,
  hotpink => 0xff69b4,
  indianred => 0xcd5c5c,
  indigo => 0x4b0082,
  ivory => 0xfffff0,
  khaki => 0xf0e68c,
  lavender => 0xe6e6fa,
  lavenderblush => 0xfff0f5,
  lawngreen => 0x7cfc00,
  lemonchiffon => 0xfffacd,
  lightblue => 0xadd8e6,
  lightcoral => 0xf08080,
  lightcyan => 0xe0ffff,
  lightgoldenrodyellow => 0xfafad2,
  lightgray => 0xd3d3d3,
  lightgreen => 0x90ee90,
  lightgrey => 0xd3d3d3,
  lightpink => 0xffb6c1,
  lightsalmon => 0xffa07a,
  lightseagreen => 0x20b2aa,
  lightskyblue => 0x87cefa,
  lightslategray => 0x778899,
  lightslategrey => 0x778899,
  lightsteelblue => 0xb0c4de,
  lightyellow => 0xffffe0,
  lime => 0x00ff00,
  limegreen => 0x32cd32,
  linen => 0xfaf0e6,
  magenta => 0xff00ff,
  maroon => 0x800000,
  mediumaquamarine => 0x66cdaa,
  mediumblue => 0x0000cd,
  mediumorchid => 0xba55d3,
  mediumpurple => 0x9370db,
  mediumseagreen => 0x3cb371,
  mediumslateblue => 0x7b68ee,
  mediumspringgreen => 0x00fa9a,
  mediumturquoise => 0x48d1cc,
  mediumvioletred => 0xc71585,
  midnightblue => 0x191970,
  mintcream => 0xf5fffa,
  mistyrose => 0xffe4e1,
  moccasin => 0xffe4b5,
  navajowhite => 0xffdead,
  navy => 0x000080,
  oldlace => 0xfdf5e6,
  olive => 0x808000,
  olivedrab => 0x6b8e23,
  orange => 0xffa500,
  orangered => 0xff4500,
  orchid => 0xda70d6,
  palegoldenrod => 0xeee8aa,
  palegreen => 0x98fb98,
  paleturquoise => 0xafeeee,
  palevioletred => 0xdb7093,
  papayawhip => 0xffefd5,
  peachpuff => 0xffdab9,
  peru => 0xcd853f,
  pink => 0xffc0cb,
  plum => 0xdda0dd,
  powderblue => 0xb0e0e6,
  purple => 0x800080,
  red => 0xff0000,
  rosybrown => 0xbc8f8f,
  royalblue => 0x4169e1,
  saddlebrown => 0x8b4513,
  salmon => 0xfa8072,
  sandybrown => 0xf4a460,
  seagreen => 0x2e8b57,
  seashell => 0xfff5ee,
  sienna => 0xa0522d,
  silver => 0xc0c0c0,
  skyblue => 0x87ceeb,
  slateblue => 0x6a5acd,
  slategray => 0x708090,
  slategrey => 0x708090,
  snow => 0xfffafa,
  springgreen => 0x00ff7f,
  steelblue => 0x4682b4,
  tan => 0xd2b48c,
  teal => 0x008080,
  thistle => 0xd8bfd8,
  tomato => 0xff6347,
  turquoise => 0x40e0d0,
  violet => 0xee82ee,
  wheat => 0xf5deb3,
  white => 0xffffff,
  whitesmoke => 0xf5f5f5,
  yellow => 0xffff00,
  yellowgreen => 0x9acd32,
);

sub name_to_rgb_old {
  my $color = lc $_[0];

  # note: Mozilla strips leading and trailing whitespace at this point,
  # but IE does not

  # named colors
  my $hex = $html_color{$color};
  if (defined $hex) {
    return sprintf("#%06x", $hex);
  }

  # Flex Hex: John Graham-Cumming, http://www.jgc.org/pdf/lisa2004.pdf
  # strip optional # character
  $color =~ s/^#//;
  # pad right-hand-side to a multiple of three
  $color .= "0" x (3 - (length($color) % 3)) if (length($color) % 3);
  # split into triplets
  my $length = length($color) / 3;
  my @colors = ($color =~ /(.{$length})(.{$length})(.{$length})/);
  # truncate each color to a DWORD, take MSB, left pad nibbles
  foreach (@colors) { s/.*(.{8})$/$1/; s/(..).*/$1/; s/^(.)$/0$1/ };
  # the color
  $color = join("", @colors);
  # replace non-hex characters with 0
  $color =~ tr/0-9a-f/0/c;

  return "#" . $color;
}

sub name_to_rgb {
  my $color = lc $_[0];
  my $before = $color;

  # strip leading and ending whitespace
  $color =~ s/^\s*//;
  $color =~ s/\s*$//;

  # named colors
  my $hex = $html_color{$color};
  if (defined $hex) {
    return sprintf("#%06x", $hex);
  }

  # IF NOT A NAME, IT SHOULD BE A HEX COLOR, HEX SHORTHAND or rgb values
  if ($color =~ m/^[#a-f0-9]*$|rgb\([\d%, ]*\)/i) {

    #Convert the RGB values to hex values so we can fall through on the programming

    #RGB PERCENTS TO HEX
    if ($color =~ m/rgb\((\d+)%,\s*(\d+)%,\s*(\d+)%\s*\)/i) {
      $color = "#".dec2hex(int($1/100*255)).dec2hex(int($2/100*255)).dec2hex(int($3/100*255));
    }

    #RGB DEC TO HEX
    if ($color =~ m/rgb\((\d+),\s*(\d+),\s*(\d+)\s*\)/i) {
      $color = "#".dec2hex($1).dec2hex($2).dec2hex($3);
    }

    #PARSE THE HEX
    if ($color =~ m/^#/) {
      # strip to hex only
      $color =~ s/[^a-f0-9]//ig;

      # strip to 6 if greater than 6
      if (length($color) > 6) {
        $color=substr($color,0,6);
      }

      # strip to 3 if length < 6)
      if (length($color) > 3 && length($color) < 6) {
        $color=substr($color,0,3);
      }

      # pad right-hand-side to a multiple of three
      $color .= "0" x (3 - (length($color) % 3)) if (length($color) % 3);

      #DUPLICATE SHORTHAND HEX
      if (length($color) == 3) {
        $color =~ m/(.)(.)(.)/;
        $color = "$1$1$2$2$3$3";
      }

    } else {
      return "invalid";
    } 

  } else {
    #INVALID 

    #??RETURN BLACK SINCE WE DO NOT KNOW HOW THE MUA / BROWSER WILL PARSE
    #$color = "000000";

    return "invalid";
  }

  #print "DEBUG: before/after name_to_rgb new version: $before/$color\n";

  return "#" . $color;
}

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
    if ($base_path =~ m|/|) {
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
  if ($t{authority}) {
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
