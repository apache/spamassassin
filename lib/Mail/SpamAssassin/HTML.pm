# $Id: HTML.pm,v 1.3.2.2 2002/08/22 10:41:26 matt_sergeant Exp $

package Mail::SpamAssassin::HTML;
1;

package Mail::SpamAssassin::PerMsgStatus;
use HTML::Parser 3.00 ();

# HTML decoding TODOs
# - add URIs to list for faster URI testing

sub html_tag {
  my ($self, $tag, $attr, $num) = @_;
  
  $self->{html_inside}{$tag} += $num;
  
  if ($num == 1) {
    $self->html_format($tag, $attr, $num);
    $self->html_uri($tag, $attr, $num);
    $self->html_tests($tag, $attr, $num);

    $self->{html_last_tag} = $tag;
  }
}

sub html_format {
  my ($self, $tag, $attr, $num) = @_;

  if ($tag eq "p" || $tag eq "hr") {
    push @{$self->{html_text}}, "\n\n";
  }
  elsif ($tag eq "br") {
    push @{$self->{html_text}}, "\n";
  }
}

sub html_uri {
  my ($self, $tag, $attr, $num) = @_;
  my $uri;

  if ($tag =~ /^(?:a|area|link)$/) {
    push @{$self->{html_text}}, "URI:$uri " if $uri = $attr->{href};
  }
  elsif ($tag =~ /^(?:img|frame|iframe|embed|script)$/) {
    push @{$self->{html_text}}, "URI:$uri " if $uri = $attr->{src};
  }
  elsif ($tag =~ /^(?:body|table|tr|td)$/) {
    push @{$self->{html_text}}, "URI:$uri " if $uri = $attr->{background};
  }
  elsif ($tag eq "form") {
    push @{$self->{html_text}}, "URI:$uri " if $uri = $attr->{action};
  }
  elsif ($tag eq "base") {
    if ($uri = $attr->{href}) {
      # use <BASE HREF="URI"> to turn relative links into absolute links

      # even if it is a base URI, handle like a normal URI as well
      push @{$self->{html_text}}, "URI:$uri ";

      # a base URI will be ignored by browsers unless it is an absolute
      # URI of a standard protocol
      if ($uri =~ m@^(?:ftp|https?)://@i) {
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

# the most common HTML colors
my %name_to_rgb = (
  red           => '#ff0000',
  black         => '#000000',
  blue          => '#0000ff',
  white         => '#ffffff',
  navy          => '#000080',
  green         => '#008000',
  orange        => '#ffa500',
  yellow        => '#ffff00',
  fuchsia       => '#ff00ff',
  lime          => '#00ff00',
  maroon        => '#800000',
  darkblue      => '#00008b',
  gray          => '#808080',
  purple        => '#800080',
  magenta       => '#ff00ff',
  pink          => '#ffc0cb',
);

sub name_to_rgb {
  return $name_to_rgb{$_[0]} || $_[0];
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
  if ($tag =~ /^(?:body|frame)$/) {
    for (keys %$attr) {
      if (/^on(?:Load|UnLoad|BeforeUnload)$/i)
      {
	$self->{html}{javascript_very_unsafe} = 1;
      }
    }
  }
  if ($tag eq "body" && exists $attr->{bgcolor}) {
    $self->{html}{bgcolor} = lc($attr->{bgcolor});
    $self->{html}{bgcolor} = name_to_rgb($self->{html}{bgcolor});
    $self->{html}{bgcolor_nonwhite} = 1 if $self->{html}{bgcolor} !~ /^\#?ffffff$/;
  }
  if ($tag eq "font" && exists $attr->{size}) {
    $self->{html}{big_font} = 1 if (($attr->{size} =~ /^\s*(\d+)/ && $1 >= 3) ||
			    ($attr->{size} =~ /\+(\d+)/ && $1 > 1));
  }
  if ($tag eq "font" && exists $attr->{color}) {
    my $c = lc($attr->{color});
    $self->{html}{font_color_nohash} = 1 if $c =~ /^[0-9a-f]{6}$/;
    $self->{html}{font_color_unsafe} = 1 if ($c =~ /^\#?[0-9a-f]{6}$/ &&
				     $c !~ /^\#?(?:00|33|66|80|99|cc|ff){3}$/);
    $self->{html}{font_color_name} = 1 if ($c !~ /^\#?[0-9a-f]{6}$/ &&
				   $c !~ /^(?:navy|gray|red|white)$/);
    $c = name_to_rgb($c);
    $self->{html}{font_invisible} = 1 if (exists $self->{html}{bgcolor} &&
                                substr($c,-6) eq substr($self->{html}{bgcolor},-6));
    if ($c =~ /^\#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/) {
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
  if ($tag eq "font" && exists $attr->{face}) {
    $self->{html}{font_face_caps} = 1 if $attr->{face} =~ /[A-Z]{3}/;
    if ($attr->{face} !~ /^[a-z][a-z -]*[a-z](?:,\s*[a-z][a-z -]*[a-z])*$/i) {
      $self->{html}{font_face_bad} = 1;
    }
    for (split(/,/, lc($attr->{face}))) {
      $self->{html}{font_face_odd} = 1 if ! /^\s*(?:arial|comic sans ms|courier new|geneva|helvetica|ms mincho|sans-serif|serif|tahoma|times new roman|verdana)\s*$/i;
    }
  }
  if (($tag eq "img" && exists $attr->{src} &&
       $attr->{src} =~ /(?:\?|[a-f\d]{12,})/i) ||
      ($tag =~ /^(?:body|table|tr|td)$/ && exists $attr->{background} &&
       $attr->{background} =~ /(?:\?|[a-f\d]{12,})/i))
  {
    $self->{html}{web_bugs} = 1;
  }
  if ($tag =~ /^i?frame$/) {
    $self->{html}{relaying_frame} = 1;
  }
  if ($tag =~ /^(?:object|embed)$/) {
    $self->{html}{embeds} = 1;
  }
}

sub html_text {
  my ($self, $text) = @_;

  return if (exists $self->{html_inside}{script} && $self->{html_inside}{script} > 0);
  return if (exists $self->{html_inside}{style} && $self->{html_inside}{style} > 0);
  $text =~ s/\n// if $self->{html_last_tag} eq "br";
  push @{$self->{html_text}}, $text;
}

sub html_comment {
  my ($self, $text) = @_;

  $self->{html}{comment_8bit} = 1 if $text =~ /[\x80-\xff]{3,}/;
  $self->{html}{comment_saved_url} = 1 if $text =~ /<!-- saved from url=\(\d{4}\)/;
  $self->{html}{comment_unique_id} = 1 if $text =~ /<!--\s*(?:[\d.]+|[a-f\d]{5,}|\S{10,})\s*-->/i;
}

###########################################################################
# HTML parser tests
###########################################################################

# A possibility for spotting heavy HTML spam and image-only spam
# Submitted by Michael Moncur 7/26/2002, see bug #608
sub html_percentage {
  my ($self, undef, $min, $max) = @_;

  my $html_percent = $self->{html}{ratio} * 100;
  return ($html_percent > $min && $html_percent <= $max);
}

sub html_test {
  my ($self, undef, $test) = @_;
  return $self->{html}{$test};
}


1;
__END__
