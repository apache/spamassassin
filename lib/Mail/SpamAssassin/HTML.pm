# $Id: HTML.pm,v 1.101 2003/10/15 08:08:05 quinlan Exp $

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

# HTML decoding TODOs
# - add URIs to list for faster URI testing

use strict;
use bytes;

package Mail::SpamAssassin::HTML;

require Exporter;
my @ISA = qw(Exporter);
my @EXPORT = qw($re_start $re_loose $re_strict get_results);
my @EXPORT_OK = qw();

use HTML::Parser 3.24 ();
use vars qw($re_start $re_loose $re_strict $re_other);

# elements that trigger HTML rendering in text/plain in some mail clients
# (repeats ones listed in $re_strict)
$re_start = 'body|head|html|img|pre|table|title';

# elements defined by the HTML 4.01 and XHTML 1.0 DTDs (do not change them!)
$re_loose = 'applet|basefont|center|dir|font|frame|frameset|iframe|isindex|menu|noframes|s|strike|u';
$re_strict = 'a|abbr|acronym|address|area|b|base|bdo|big|blockquote|body|br|button|caption|cite|code|col|colgroup|dd|del|dfn|div|dl|dt|em|fieldset|form|h1|h2|h3|h4|h5|h6|head|hr|html|i|img|input|ins|kbd|label|legend|li|link|map|meta|noscript|object|ol|optgroup|option|p|param|pre|q|samp|script|select|small|span|strong|style|sub|sup|table|tbody|td|textarea|tfoot|th|thead|title|tr|tt|ul|var';

# loose list of HTML events
my $events = 'on(?:activate|afterupdate|beforeactivate|beforecopy|beforecut|beforedeactivate|beforeeditfocus|beforepaste|beforeupdate|blur|change|click|contextmenu|controlselect|copy|cut|dblclick|deactivate|errorupdate|focus|focusin|focusout|help|keydown|keypress|keyup|load|losecapture|mousedown|mouseenter|mouseleave|mousemove|mouseout|mouseover|mouseup|mousewheel|move|moveend|movestart|paste|propertychange|readystatechange|reset|resize|resizeend|resizestart|select|submit|timeerror|unload)';

# other non-standard tags
$re_other = 'o:\w+/?|x-sigsep|x-tab';

# style attributes
my %ok_attribute = (
		 text => [qw(body)],
		 color => [qw(basefont font)],
		 bgcolor => [qw(body table tr td th marquee)],
		 face => [qw(basefont font)],
		 size => [qw(basefont font)],
		 link => [qw(body)],
		 alink => [qw(body)],
		 vlink => [qw(body)],
		 background => [qw(body marquee)],
		 );

my %tested_colors;

sub new {
  my $this = shift;
  my $class = ref($this) || $this;
  my $self = {};
  bless($self, $class);

  $self->html_init();

  return $self;
}

sub html_init {
  my ($self) = @_;

  undef $self->{text_style};
  my %default = (tag => "default",
		 fgcolor => "#000000",
		 bgcolor => "#ffffff",
		 size => 3);
  push @{ $self->{text_style} }, \%default;
}

sub get_results {
  my ($self) = @_;

  return $self->{html};
}

sub html_render {
  my ($self, $text) = @_;

  # clean this up later
  for my $key (keys %{ $self->{html} }) {
    delete $self->{html}{$key};
  }

  $self->{html}{ratio} = 0;
  $self->{html}{image_area} = 0;
  $self->{html}{shouting} = 0;
  $self->{html}{max_shouting} = 0;
  $self->{html}{total_comment_ratio} = 0;
  $self->{html}{title_index} = -1;

  $self->{html_text} = [];
  $self->{html_last_tag} = 0;

  # NOTE: We *only* need to fix the rendering when we verify that it
  # differs from what people see in their MUA.  Testing is best done with
  # the most common MUAs and browsers, if you catch my drift.

  # NOTE: HTML::Parser can cope with: <?xml pis>, <? with space>, so we
  # don't need to fix them here.

  # bug #1551: HTML declarations, like <!foo>, are being used by spammers
  # for obfuscation, and they aren't stripped out by HTML::Parser prior to
  # version 3.28.  We have to modify these out *before* the parser is
  # invoked, because otherwise a spammer could do "&lt;! body of message
  # &gt;", which would get turned into "<! body of message >" by the
  # parser, and then the whole body message would be stripped.

  # convert <!foo> to <!--foo-->
  if ($HTML::Parser::VERSION < 3.28) {
    $text =~ s/<!((?!--|doctype)[^>]*)>/<!--$1-->/gsi;
  }

  # remove empty close tags: </>, </ >, </ foo>
  if ($HTML::Parser::VERSION < 3.29) {
    $text =~ s/<\/(?:\s.*?)?>//gs;
  }

  # HTML::Parser 3.31, at least, converts &nbsp; into a question mark "?" for some reason.
  # Let's convert them to spaces.
  $text =~ s/&nbsp;/ /g;

  my $hp = HTML::Parser->new(
		api_version => 3,
		handlers => [
		  start_document => [sub { $self->html_init(@_) }],
		  start => [sub { $self->html_tag(@_) }, "tagname,attr,'+1'"],
		  end => [sub { $self->html_tag(@_) }, "tagname,attr,'-1'"],
		  text => [sub { $self->html_text(@_) }, "dtext"],
		  comment => [sub { $self->html_comment(@_) }, "text"],
		  declaration => [sub { $self->html_declaration(@_) }, "text"],
		],
		marked_sections => 1);

  # ALWAYS pack it into byte-representation, even if we're using 'use bytes',
  # since the HTML::Parser object may use Unicode internally.
  # (bug 1417, maybe)
  $hp->parse(pack ('C0A*', $text));
  $hp->eof;

  delete $self->{html_last_tag};

  return $self->{html_text};
}

sub html_tag {
  my ($self, $tag, $attr, $num) = @_;

  if ($tag =~ /^(?:$re_strict|$re_loose|$re_other)$/io) {
    $self->{html}{elements}++;
    $self->{html}{elements_seen}++ if !exists $self->{html}{"inside_$tag"};
  }
  $self->{html}{tags}++;
  $self->{html}{tags_seen}++ if !exists $self->{html}{"inside_$tag"};

  $self->{html}{"inside_$tag"} += $num;
  $self->{html}{"inside_$tag"} = 0 if $self->{html}{"inside_$tag"} < 0;

  # TODO: cover other changes
  if ($tag =~ /^(?:body|font|table|tr|th|td|big|small)$/) {
    $self->text_style($tag, $attr, $num);
  }

  if ($num == 1) {
    $self->html_format($tag, $attr, $num);
    $self->html_uri($tag, $attr, $num);
    $self->html_tests($tag, $attr, $num);

    $self->{html_last_tag} = $tag;
  }

  if ($tag =~ /^(?:b|i|u|strong|em|big|center|h\d)$/) {
    $self->{html}{shouting} += $num;

    if ($self->{html}{shouting} > $self->{html}{max_shouting}) {
      $self->{html}{max_shouting} = $self->{html}{shouting};
    }
  }
}

sub html_format {
  my ($self, $tag, $attr, $num) = @_;

  # ordered by frequency of tag groups
  if ($tag eq "br") {
    push @{$self->{html_text}}, "\n";
  }
  elsif ($tag eq "li" || $tag eq "td" || $tag eq "dd") {
    push @{$self->{html_text}}, " ";
  }
  elsif ($tag =~ /^(?:p|hr|blockquote|pre)$/) {
    push @{$self->{html_text}}, "\n\n";
  }
}

use constant URI_STRICT => 0;

# resolving relative URIs as defined in RFC 2396 (steps from section 5.2)
# using draft http://www.gbiv.com/protocols/uri/rev-2002/rfc2396bis.html
sub parse_uri {
  my ($u) = @_;
  my %u;
  ($u{scheme}, $u{authority}, $u{path}, $u{query}, $u{fragment}) =
    $u =~ m|^(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|;
  return %u;
}

sub remove_dot_segments {
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

sub merge_uri {
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

  my %r = parse_uri($r);	# parsed relative URI
  my %base = parse_uri($base);	# parsed base URI
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
    $t{path} = remove_dot_segments($r{path});
    $t{query} = $r{query};
  }
  else {
    if (defined $r{authority}) {
      $t{authority} = $r{authority};
      $t{path} = remove_dot_segments($r{path});
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
	  $t{path} = remove_dot_segments($r{path});
	}
	else {
	  $t{path} = merge_uri($base{authority}, $base{path}, $r{path});
	  $t{path} = remove_dot_segments($t{path});
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
  if ($t{query}) {
    $result .= "?" . $t{query};
  }
  if ($t{fragment}) {
    $result .= "#" . $t{fragment};
  }
  return $result;
}

sub push_uri {
  my ($self, $uri) = @_;

  my $target = target_uri($self->{html}{base_href} || "", $uri || "");
  push @{$self->{html}{uri}}, $target if $target;
}

sub html_uri {
  my ($self, $tag, $attr, $num) = @_;
  my $uri;

  # ordered by frequency of tag groups
  if ($tag =~ /^(?:body|table|tr|td)$/) {
    $self->push_uri($attr->{background});
  }
  elsif ($tag =~ /^(?:a|area|link)$/) {
    $self->push_uri($attr->{href});
  }
  elsif ($tag =~ /^(?:img|frame|iframe|embed|script)$/) {
    $self->push_uri($attr->{src});
  }
  elsif ($tag eq "form") {
    $self->push_uri($attr->{action});
  }
  elsif ($tag eq "base") {
    if ($uri = $attr->{href}) {
      # use <BASE HREF="URI"> to turn relative links into absolute links

      # even if it is a base URI, handle like a normal URI as well
      push @{$self->{html}{uri}}, $uri;

      # a base URI will be ignored by browsers unless it is an absolute
      # URI of a standard protocol
      if ($uri =~ m@^(?:https?|ftp)://@i) {
	# remove trailing filename, if any; base URIs can have the
	# form of "http://foo.com/index.html"
	$uri =~ s@^([a-z]+://[^/]+/.*?)[^/\.]+\.[^/\.]{2,4}$@$1@i;
	# Make sure it ends in a slash
	$uri .= "/" unless $uri =~ m@/$@;
	$self->{html}{base_href} = $uri;
      }
    }
  }
}

# input values from 0 to 255
sub rgb_to_hsv {
  my ($r, $g, $b) = @_;
  my ($h, $s, $v, $max, $min);

  if ($r > $g) {
    $max = $r; $min = $g;
  }
  else {
    $min = $r; $max = $g;
  }
  $max = $b if $b > $max;
  $min = $b if $b < $min;
  $v = $max;
  $s = $max ? ($max - $min) / $max : 0;
  if ($s == 0) {
    $h = undef;
  }
  else {
    my $cr = ($max - $r) / ($max - $min);
    my $cg = ($max - $g) / ($max - $min);
    my $cb = ($max - $b) / ($max - $min);
    if ($r == $max) {
      $h = $cb - $cg;
    }
    elsif ($g == $max) {
      $h = 2 + $cr - $cb;
    }
    elsif ($b == $max) {
      $h = 4 + $cg - $cr;
    }
    $h *= 60;
    $h += 360 if $h < 0;
  }
  return ($h, $s, $v);
}

# HTML 4 defined 16 colors
my %html_color = (
  aqua		=> '#00ffff',
  black		=> '#000000',
  blue		=> '#0000ff',
  fuchsia	=> '#ff00ff',
  gray		=> '#808080',
  green		=> '#008000',
  lime		=> '#00ff00',
  maroon	=> '#800000',
  navy		=> '#000080',
  olive		=> '#808000',
  purple	=> '#800080',
  red		=> '#ff0000',
  silver	=> '#c0c0c0',
  teal		=> '#008080',
  white		=> '#ffffff',
  yellow	=> '#ffff00',
);

# popular X11 colors specified in CSS3 color module
my %name_color = (
  aliceblue	=> '#f0f8ff',
  cyan		=> '#00ffff',
  darkblue	=> '#00008b',
  darkcyan	=> '#008b8b',
  darkgray	=> '#a9a9a9',
  darkgreen	=> '#006400',
  darkred	=> '#8b0000',
  firebrick	=> '#b22222',
  gold		=> '#ffd700',
  lightslategray=> '#778899',
  magenta	=> '#ff00ff',
  orange	=> '#ffa500',
  pink		=> '#ffc0cb',
  whitesmoke	=> '#f5f5f5',
);

sub name_to_rgb {
  return $html_color{$_[0]} || $name_color{$_[0]} || $_[0];
}

# this might not be quite right, may need to pay attention to table nesting
sub close_tag_tr {
  my ($self) = @_;

  # don't close if never opened
  return if !grep { $_->{tag} eq "tr" } @{ $self->{text_style} };

  my $tag;
  while (@{ $self->{text_style} } && ($tag = $self->{text_style}[-1]->{tag})) {
    if ($tag =~ /^(?:font|td|tr)$/) {
      pop @{ $self->{text_style} };
    }
    else {
      last;
    }
  }
}

# this might not be quite right, may need to pay attention to table nesting
sub close_tag_td {
  my ($self) = @_;

  # don't close if never opened
  return if !grep { $_->{tag} eq "td" } @{ $self->{text_style} };

  my $tag;
  while (@{ $self->{text_style} } && ($tag = $self->{text_style}[-1]->{tag})) {
    if ($tag =~ /^(?:font|td)$/) {
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

# body, font, table, tr, th, td, big, small
# TODO: implement <basefont> support
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
    $self->close_tag_tr() if $tag eq "tr";
    $self->close_tag_td() if $tag eq "td";

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
      next unless (grep { $_ eq $tag } @{ $ok_attribute{$name} });
      if ($name =~ /^(?:text|color)$/) {
	# two different names for text color
	$new{fgcolor} = name_to_rgb(lc($attr->{$name}));
	$self->html_font_color_tests($attr->{$name});
      }
      elsif ($name eq "size" && $attr->{size} =~ /^\s*([+-]\d+)/) {
	# relative font size
	$new{size} += $1;
      }
      else {
	# overwrite
	if ($name eq "bgcolor") {
	  $attr->{bgcolor} = name_to_rgb(lc($attr->{bgcolor}));
	  # one test
	  if ($tag eq "body" && $attr->{bgcolor} !~ /^\#?ffffff$/) {
	    $self->{html}{bgcolor_nonwhite} = 1;
	  }
	}
	if ($name eq "size" && $attr->{size} !~ /^\s*([+-])(\d+)/) {
	  # attribute is malformed
	}
	else {
	  # attribute is probably okay
	  $new{$name} = $attr->{$name};
	}
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

sub html_font_color_tests {
  my ($self, $color) = @_;

  my $bg = $self->{text_style}[-1]->{fgcolor};
  my $fg = lc($color);

  if ($fg =~ /^\#?[0-9a-f]{6}$/ && $fg !~ /^\#?(?:00|33|66|80|99|cc|ff){3}$/) {
    $self->{html}{font_color_unsafe} = 1;
  }
  if ($fg !~ /^\#?[0-9a-f]{6}$/ && !exists $html_color{$fg}) {
    $self->{html}{font_color_name} = 1;
  }
  if ($fg =~ /^\#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/) {
    my ($h, $s, $v) = rgb_to_hsv(hex($1), hex($2), hex($3));
    if (!defined($h)) {
      $self->{html}{font_gray} = 1 unless ($v == 0 || $v == 255);
    }
    elsif ($h < 30 || $h >= 330) {
      $self->{html}{font_red} = 1;
    }
    elsif ($h < 90) {
      $self->{html}{font_yellow} = 1;
    }
    elsif ($h < 150) {
      $self->{html}{font_green} = 1;
    }
    elsif ($h < 210) {
      $self->{html}{font_cyan} = 1;
    }
    elsif ($h < 270) {
      $self->{html}{font_blue} = 1;
    }
    elsif ($h < 330) {
      $self->{html}{font_magenta} = 1;
    }
  }
  else {
    $self->{html}{font_color_unknown} = 1;
  }
}

sub html_font_invisible {
  my ($self, $text) = @_;

  my $fg = $self->{text_style}[-1]->{fgcolor};
  my $bg = $self->{text_style}[-1]->{bgcolor};

  # invisibility
  if (substr($fg,-6) eq substr($bg,-6)) {
    $self->{html}{font_invisible} = 1;
    return 0;
  }
  # near-invisibility
  elsif ($fg =~ /^\#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/) {
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
	$self->{html}{"font_near_invisible"} = 1;
      }
    }
  }
  return 1;
}

sub html_tests {
  my ($self, $tag, $attr, $num) = @_;

  if ($tag eq "table" && exists $attr->{border} && $attr->{border} =~ /(\d+)/)
  {
    $self->{html}{thick_border} = 1 if $1 > 1;
  }
  if ($tag eq "script") {
    $self->{html}{javascript} = 1;
  }
  if ($tag =~ /^(?:a|body|div|input|form|td|layer|area|img)$/i) {
    for (keys %$attr) {
      if (/\b(?:$events)\b/io)
      {
	$self->{html}{html_event} = 1;
      }
      if (/\bon(?:blur|contextmenu|focus|load|resize|submit|unload)\b/i &&
	  $attr->{$_})
      {
	$self->{html}{html_event_unsafe} = 1;
        if ($attr->{$_} =~ /\.open\s*\(/) { $self->{html}{window_open} = 1; }
        if ($attr->{$_} =~ /\.blur\s*\(/) { $self->{html}{window_blur} = 1; }
        if ($attr->{$_} =~ /\.focus\s*\(/) { $self->{html}{window_focus} = 1; }
      }
    }
  }
  if ($tag eq "font" && exists $attr->{size}) {
    my $size = $attr->{size};
    $self->{html}{tiny_font} = 1 if (($size =~ /^\s*(\d+)/ && $1 < 1) ||
				     ($size =~ /\-(\d+)/ && $1 >= 3));
    $self->{html}{big_font} = 1 if (($size =~ /^\s*(\d+)/ && $1 > 3) ||
				    ($size =~ /\+(\d+)/ && $1 >= 1));
  }
  if ($tag eq "font" && exists $attr->{face}) {
    #print STDERR "FONT " . $attr->{face} . "\n";
    if ($attr->{face} =~ /[A-Z]{3}/ && $attr->{face} !~ /M[ST][A-Z]|ITC/) {
      $self->{html}{font_face_caps} = 1;
    }
    if ($attr->{face} !~ /^[a-z][a-z -]*[a-z](?:,\s*[a-z][a-z -]*[a-z])*$/i) {
      $self->{html}{font_face_bad} = 1;
    }
    for (split(/,/, lc($attr->{face}))) {
      $self->{html}{font_face_odd} = 1 if ! /^\s*(?:arial|arial black|courier new|geneva|helvetica|ms sans serif|sans serif|sans-serif|sans-serif;|serif|sunsans-regular|swiss|tahoma|times|times new roman|trebuchet|trebuchet ms|verdana)\s*$/i;
    }
  }
  if (exists($attr->{style})) {
    if ($attr->{style} =~ /font(?:-size)?:\s*(\d+(?:\.\d*)?|\.\d+)(p[tx])/i) {
      $self->examine_text_style ($1, $2);
    }
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
    if ($width > 0 && $height > 0) {
      $area = $width * $height;
      $self->{html}{image_area} += $area;
    }
    # this is intended to match any width and height if they're specified
    if (exists $attr->{src} &&
	$attr->{src} =~ /\.(?:pl|cgi|php|asp|jsp|cfm)\b/i)
    {
      $self->{html}{web_bugs} = 1;
    }
  }
  if ($tag eq "form" && exists $attr->{action}) {
    $self->{html}{form_action_mailto} = 1 if $attr->{action} =~ /mailto:/i
  }
  if ($tag =~ /^i?frame$/) {
    $self->{html}{relaying_frame} = 1;
  }
  if ($tag =~ /^(?:object|embed)$/) {
    $self->{html}{embeds} = 1;
  }
  if ($tag eq "title") {
    $self->{html}{title_index}++;
    $self->{html}{title_text} = "" if ($self->{html}{title_index} == 0);

    # begin test code
    $self->{html}{t_title}->[$self->{html}{title_index}] = "";
    # end test code

    # begin test code
    if (exists $self->{html}{"inside_body"} &&
	$self->{html}{"inside_body"} > 0)
    {
      $self->{html}{t_title_misplaced_1}++;
    }
    if (!(exists $self->{html}{"inside_head"} &&
	  $self->{html}{"inside_head"} > 0))
    {
      $self->{html}{t_title_misplaced_2}++;
    }
    if (exists $self->{html}{"inside_body"} &&
	$self->{html}{"inside_body"} > 0 &&
	!(exists $self->{html}{"inside_head"} &&
	  $self->{html}{"inside_head"} > 0))
    {
      $self->{html}{t_title_misplaced_3}++;
    }
    if ((exists $self->{html}{"inside_body"} &&
	$self->{html}{"inside_body"} > 0) ||
	!(exists $self->{html}{"inside_head"} &&
	  $self->{html}{"inside_head"} > 0))
    {
      $self->{html}{t_title_misplaced_4}++;
    }
    if ($self->{html}{title_index} > 0)
    {
      $self->{html}{t_title_extra}++;
    }
    # end test code
  }
  if ($tag eq "meta" &&
      exists $attr->{'http-equiv'} &&
      exists $attr->{content} &&
      $attr->{'http-equiv'} =~ /Content-Type/i &&
      $attr->{content} =~ /\bcharset\s*=\s*["']?([^"']+)/i)
  {
    $self->{html}{charsets} .= exists $self->{html}{charsets} ? " $1" : $1;
  }

  $self->{html}{anchor_text} ||= "" if ($tag eq "a");
}

sub examine_text_style {
  my ($self, $size, $type) = @_;
  $type = lc $type;
  $self->{html}{tiny_font} = 1 if ($type eq "pt" && $size < 4);
  $self->{html}{tiny_font} = 1 if ($type eq "pt" && $size < 4);
  $self->{html}{big_font} = 1 if ($type eq "pt" && $size > 14);
  $self->{html}{big_font} = 1 if ($type eq "px" && $size > 18);
}

sub html_text {
  my ($self, $text) = @_;

  if (exists $self->{html}{"inside_a"} && $self->{html}{"inside_a"} > 0) {
    $self->{html}{anchor_text} .= " $text";
  }

  if (exists $self->{html}{"inside_script"} && $self->{html}{"inside_script"} > 0)
  {
    if ($text =~ /\b(?:$events)\b/io)
    {
      $self->{html}{html_event} = 1;
    }
    if ($text =~ /\bon(?:blur|contextmenu|focus|load|resize|submit|unload)\b/i)
    {
      $self->{html}{html_event_unsafe} = 1;
    }
    if ($text =~ /\.open\s*\(/) { $self->{html}{window_open} = 1; }
    if ($text =~ /\.blur\s*\(/) { $self->{html}{window_blur} = 1; }
    if ($text =~ /\.focus\s*\(/) { $self->{html}{window_focus} = 1; }
    return;
  }

  if (exists $self->{html}{"inside_style"} && $self->{html}{"inside_style"} > 0) {
    if ($text =~ /font(?:-size)?:\s*(\d+(?:\.\d*)?|\.\d+)(p[tx])/i) {
      $self->examine_text_style ($1, $2);
    }
    return;
  }

  if (exists $self->{html}{"inside_title"} && $self->{html}{"inside_title"} > 0)
  {
    $self->{html}{title_text} .= $text if ($self->{html}{title_index} == 0);
    $self->{html}{t_title}->[$self->{html}{title_index}] .= $text;
  }

  $self->html_font_invisible($text) if $text =~ /[^ \t\n\r\f\x0b\xa0]/;

  $text =~ s/^\n//s if $self->{html_last_tag} eq "br";

  if (defined $self->{html_text}[-1]) {
    # ideas discarded since they would be easy to evade:
    # 1. using \w instead of \S
    # 2. exempting certain tags
    if ($self->{html_text}[-1] =~ /\S$/s && $text =~ /^\S/s) {
      $self->{html}{obfuscation}++;
    }
  }

  push @{$self->{html_text}}, $text;
}

sub html_comment {
  my ($self, $text) = @_;

  $self->{html}{comment_text} .= "$text\n";
  $self->{html}{total_comment_length} += length($text) + 7; # "<!--" + "-->"

  if ($self->{html_last_tag} eq "div" &&
      $text =~ /Converted from text\/plain format/)
  {
    $self->{html}{div_converted} = 1;
  }
  if (exists $self->{html}{"inside_script"} && $self->{html}{"inside_script"} > 0)
  {
    if ($text =~ /\b(?:$events)\b/io)
    {
      $self->{html}{html_event} = 1;
    }
    if ($text =~ /\bon(?:blur|contextmenu|focus|load|resize|submit|unload)\b/i)
    {
      $self->{html}{html_event_unsafe} = 1;
    }
    if ($text =~ /\.open\s*\(/) { $self->{html}{window_open} = 1; }
    if ($text =~ /\.blur\s*\(/) { $self->{html}{window_blur} = 1; }
    if ($text =~ /\.focus\s*\(/) { $self->{html}{window_focus} = 1; }
    return;
  }

  if (exists $self->{html}{"inside_style"} && $self->{html}{"inside_style"} > 0) {
    if ($text =~ /font(?:-size)?:\s*(\d+(?:\.\d*)?|\.\d+)(p[tx])/i) {
      $self->examine_text_style ($1, $2);
    }
  }

  if (exists $self->{html}{shouting} && $self->{html}{shouting} > 1) {
    $self->{html}{comment_shouting} = 1;
  }
}

sub html_declaration {
  my ($self, $text) = @_;

  if ($text =~ /^<!doctype/i) {
    my $tag = "!doctype";

    $self->{html}{elements}++;
    $self->{html}{tags}++;
    $self->{html}{"inside_$tag"} = 0;
  }
}

1;
__END__
