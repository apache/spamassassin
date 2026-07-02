package Mail::SpamAssassin::PDF::Context::Info;
use strict;
use warnings FATAL => 'all';
use Mail::SpamAssassin::PDF::Context;
use Encode qw(decode);

our @ISA = qw(Mail::SpamAssassin::PDF::Context);

sub new {
    my $class = shift;
    my $self = $class->SUPER::new(@_);
    $self->{info} = {
        ImageCount => 0,
        PageCount  => 0,
        PageArea   => 0,
        ImageArea  => 0,
        ClickArea  => 0,
        LinkCount  => 0,
        OpenAction => 0,
        JavaScript => 0,
        uris       => {}
    };

    # Descriptors of XObject images seen during draw_image, for callers that want
    # to extract the image bytes later (e.g. emit them as sub-parts).  Stored on
    # the context object, NOT in {info}, so get_info() output is unchanged.
    $self->{image_candidates} = [];

    $self;
}

sub get_info {
    my $self = shift;
    return $self->{info};
}

sub get_image_candidates {
    my $self = shift;
    return $self->{image_candidates};
}

# Maximum number of image descriptors to retain (bounds memory on image-heavy PDFs)
my $MAX_IMAGE_CANDIDATES = 64;

sub page_begin {
    my ($self, $page) = @_;

    $self->{info}->{PageCount}++;

    return 0 unless $page->{page_number} == 1;

    # Calculate page area in user space
    $self->{info}->{PageArea} +=
        ($page->{'/MediaBox'}->[2] - $page->{'/MediaBox'}->[0]) *
        ($page->{'/MediaBox'}->[3] - $page->{'/MediaBox'}->[1]);

    return 1;
}

sub draw_image {
    my ($self,$image,$page) = @_;

    $self->{info}->{ImageCount}++;

    # Calculate image area in user space
    my $ctm = $self->{gs}->{ctm};
    if ( $ctm->[1] == 0 && $ctm->[2] == 0 ) {
        $self->{info}->{ImageArea} += $ctm->[0] * $ctm->[3];
    } else {
        # Image is rotated, skewed, etc. More complicated
        # The following should be accurate for rotated images but just an approximation for other transformations
        my ($x1,$y1,$x2,$y2) = $self->transform(0,0,1,1);
        $self->{info}->{ImageArea} += abs($x2-$x1) * abs($y2-$y1);
    }

    # Record a lightweight descriptor so the image bytes can be extracted later.
    # Inline images have no stream offset (their data is skipped by the parser),
    # so they are excluded here.
    if ( defined($image->{_stream_offset})
         && @{$self->{image_candidates}} < $MAX_IMAGE_CANDIDATES ) {
        push(@{$self->{image_candidates}}, {
            dict       => $image,
            width      => $image->{'/Width'},
            height     => $image->{'/Height'},
            colorspace => $image->{'/ColorSpace'},
            bpc        => $image->{'/BitsPerComponent'},
            filters    => $image->{'/Filter'},
        });
    }

}

sub uri {
    my ($self,$location,$rect,$page) = @_;

    $self->{info}->{uris}->{$location} = 1;
    $self->{info}->{LinkCount}++;

    if ( defined($rect) ) {
        my ($x1,$y1,$x2,$y2) = @{$rect};
        if ( defined($page->{'/MediaBox'}) ) {
            # clip rectangle to media box
            $x1 = _max($page->{'/MediaBox'}->[0],_min($page->{'/MediaBox'}->[2],$x1));
            $x2 = _max($page->{'/MediaBox'}->[0],_min($page->{'/MediaBox'}->[2],$x2));
            $y1 = _max($page->{'/MediaBox'}->[1],_min($page->{'/MediaBox'}->[3],$y1));
            $y2 = _max($page->{'/MediaBox'}->[1],_min($page->{'/MediaBox'}->[3],$y2));
        }
        $self->{info}->{ClickArea} += abs(($x2-$x1) * ($y2-$y1));
    }
}

sub javascript {
    my ($self, $js) = @_;

    $self->{info}->{JavaScript} = 1;
}

sub open_action {
    my ($self, $action) = @_;

    $self->{info}->{OpenAction} = 1;
}

sub parse_end {
    my ($self,$parser) = @_;

    $self->{info}->{Encrypted} = $parser->is_encrypted();
    $self->{info}->{Protected} = $parser->is_protected();
    $self->{info}->{Version} = $parser->{version};

    return if $parser->is_protected();

    $self->{info}->{ImageArea} = _round($self->{info}->{ImageArea},0);
    $self->{info}->{PageArea} = _round($self->{info}->{PageArea},0);
    $self->{info}->{ClickArea} = _round($self->{info}->{ClickArea},0);

    if ( $self->{info}->{PageArea} > 0 ) {
        $self->{info}->{ImageRatio} = _min(100,_round($self->{info}->{ImageArea} / $self->{info}->{PageArea} * 100,2));
        $self->{info}->{ClickRatio} = _min(100,_round($self->{info}->{ClickArea} / $self->{info}->{PageArea} * 100,2));
    } else {
        $self->{info}->{ImageRatio} = 0;
        $self->{info}->{ClickRatio} = 0;
    }

    for (keys %{$parser->{trailer}->{'/Info'}}) {
        my $key = $_;
        $key =~ s/^\///; # Trim leading slash
        $self->{info}->{$key} = $parser->{trailer}->{'/Info'}->{$_};
    }

}

sub _round {
    my ($num,$prec) = @_;
    sprintf("%.${prec}f",$num);
}

sub _min {
    my ($x,$y) = @_;
    $x < $y ? $x : $y;
}

sub _max {
    my ($x,$y) = @_;
    $x > $y ? $x : $y;
}

1;