# $Id: HTML.pm,v 1.20 2002/10/04 23:44:10 felicity Exp $

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
        if ($attr->{$_} =~ /\.open\s*\(/) { $self->{html}{window_open} = 1; }
        if ($attr->{$_} =~ /\.blur\s*\(/) { $self->{html}{window_blur} = 1; }
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

  if ($tag eq "img") {
      $self->{html}{num_imgs}++;

      $self->{html}{consec_imgs}++;

      if ($self->{html}{consec_imgs} > $self->{html}{max_consec_imgs}) {
          $self->{html}{max_consec_imgs} = $self->{html}{consec_imgs};
      }
  }

  if ($tag eq "img" && exists $attr->{width} && $attr->{width} =~ /^\d+$/ && exists $attr->{height} && $attr->{height}
  =~ /^\d+$/ ) {
      my $area = $attr->{width} * $attr->{height};
      $self->{html}{total_image_area} += $area;

      if (($attr->{width} > 0) && ($attr->{height} > 0)) {
          my $ratio = ($attr->{width} + 0.0) / ($attr->{height} + 0.0);

          $self->{html}{min_img_ratio} = $ratio
            if ($ratio < $self->{html}{min_img_ratio});
          $self->{html}{max_img_ratio} = $ratio
            if ($ratio > $self->{html}{max_img_ratio});
      }
  }

  if ($tag =~ /^i?frame$/) {
    $self->{html}{relaying_frame} = 1;
  }
  if ($tag =~ /^(?:object|embed)$/) {
    $self->{html}{embeds} = 1;
  }
  if ($tag eq "title" &&
      !(exists $self->{html_inside}{body} && $self->{html_inside}{body} > 0))
  {
    $self->{html}{title_text} = "";
  }
}

sub html_text {
  my ($self, $text) = @_;

  if ($text =~ /\S/) {
      # Measuring consecutive image tags with no intervening text
      $self->{html}{consec_imgs} = 0;
  }

  if (exists $self->{html_inside}{script} && $self->{html_inside}{script} > 0)
  {
    if ($text =~ /\.open\s*\(/) { $self->{html}{window_open} = 1; }
    if ($text =~ /\.blur\s*\(/) { $self->{html}{window_blur} = 1; }
    return;
  }
  return if (exists $self->{html_inside}{style} && $self->{html_inside}{style} > 0);
  if (!(exists $self->{html_inside}{body} && $self->{html_inside}{body} > 0) &&
        exists $self->{html_inside}{title} && $self->{html_inside}{title} > 0)
  {
    $self->{html}{title_text} .= $text;
  }
  $text =~ s/\n// if $self->{html_last_tag} eq "br";
  push @{$self->{html_text}}, $text;
}

sub html_comment {
  my ($self, $text) = @_;

  $self->{html}{comment_8bit} = 1 if $text =~ /[\x80-\xff]{3,}/;
  $self->{html}{comment_email} = 1 if $text =~ /\S+\@\S+/;
  $self->{html}{comment_saved_url} = 1 if $text =~ /<!-- saved from url=\(\d{4}\)/;
  $self->{html}{comment_sky} = 1 if $text =~ /SKY-(?:Email-Address|Database|Mailing|List)/;
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

sub html_tag_balance {
  my ($self, undef, $tag, $expr) = @_;
  return exists $self->{html_inside}{$tag} && eval "$self->{html_inside}{$tag} $expr";
}

sub html_tag_exists {
  my ($self, undef, $tag) = @_;
  return exists $self->{html_inside}{$tag};
}

sub html_test {
  my ($self, undef, $test) = @_;
  return $self->{html}{$test};
}

sub html_eval {
  my ($self, undef, $test, $expr) = @_;
  return exists $self->{html}{$test} && eval "qq{\Q$self->{html}{$test}\E} $expr";
}

sub html_image_area {
    my ($self, undef, $min, $max) = @_;

    $max ||= "inf";

    my $image_area = $self->{html}{total_image_area};
    return ($image_area > $min && $image_area <= $max);
} # html_image_area()


sub html_num_imgs {
    my ($self, undef, $min, $max) = @_;

    $max ||= "inf";

    my $num_imgs = $self->{html}{num_imgs};
    return ($num_imgs > $min && $num_imgs <= $max);
} # html_num_imgs()

sub html_max_consec_imgs {
    my ($self, undef, $min, $max) = @_;

    $max ||= "inf";

    my $consec = $self->{html}{max_consec_imgs};
    return ($consec > $min && $consec <= $max);
} # html_max_consec_imgs()

sub html_min_img_ratio {
    my ($self, undef, $min, $max) = @_;

    $max ||= "inf";

    my $ratio = $self->{html}{min_img_ratio};
    return ($ratio > $min && $ratio <= $max);
} # html_min_img_ratio()

sub html_max_img_ratio {
    my ($self, undef, $min, $max) = @_;

    $max ||= "inf";

    my $ratio = $self->{html}{max_img_ratio};
    return ($ratio > $min && $ratio <= $max);
} # html_max_img_ratio()


1;
__END__
