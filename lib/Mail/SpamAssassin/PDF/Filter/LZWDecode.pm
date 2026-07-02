package Mail::SpamAssassin::PDF::Filter::LZWDecode;
use strict;
use warnings FATAL => 'all';
use Carp;
use POSIX;

# Code taken from PDF::Builder::Basic::PDF::Filter::LZWDecode

sub new {
    my ($class, $decode_parms) = @_;
    $decode_parms //= {};
    my $self = {
        'DecodeParms' => $decode_parms
    };
    bless $self, $class;
    $self->_reset_code();
    return $self;
}

sub decode {
    my ($self, $data) = @_;
    my ($code, $result);
    my $partial_code = $self->{'partial_code'};
    my $partial_bits = $self->{'partial_bits'};
    my $early_change = $self->{'DecodeParms'}->{'EarlyChange'} // 1;

    $self->{'table'} = [ map { chr } 0 .. $self->{'clear_table'} - 1 ];
    while ($data ne q{}) {
        ($code, $partial_code, $partial_bits) =
            $self->read_dat(\$data, $partial_code, $partial_bits,
                $self->{'code_length'});
        last unless defined $code;
        unless ($early_change) {
            if ($self->{'next_code'} == (1 << $self->{'code_length'})
                and $self->{'code_length'} < 12) {
                $self->{'code_length'}++;
            }
        }
        if      ($code == $self->{'clear_table'}) {
            $self->{'code_length'} = $self->{'initial_code_length'};
            $self->{'next_code'}   = $self->{'eod_marker'} + 1;
            next;
        } elsif ($code == $self->{'eod_marker'}) {
            last;
        } elsif ($code > $self->{'eod_marker'}) {
            $self->{'table'}[$self->{'next_code'}] = $self->{'table'}[$code];
            $self->{'table'}[$self->{'next_code'}] .=
                substr($self->{'table'}[$code + 1], 0, 1);
            $result .= $self->{'table'}[$self->{'next_code'}];
            $self->{'next_code'}++;
        } else {
            $self->{'table'}[$self->{'next_code'}] = $self->{'table'}[$code];
            $result .= $self->{'table'}[$self->{'next_code'}];
            $self->{'next_code'}++;
        }
        if ($early_change) {
            if ($self->{'next_code'} == (1 << $self->{'code_length'})
                and $self->{'code_length'} < 12) {
                $self->{'code_length'}++;
            }
        }
    }
    $self->{'partial_code'} = $partial_code;
    $self->{'partial_bits'} = $partial_bits;
    if ($self->_predictor_type() == 2) {
        return $self->_depredict($result);
    }
    return $result;
}

sub _reset_code {
    my $self = shift;

    $self->{'initial_code_length'} = 9;
    $self->{'max_code_length'}     = 12;
    $self->{'code_length'}         = $self->{'initial_code_length'};
    $self->{'clear_table'}         = 256;
    $self->{'eod_marker'}          = $self->{'clear_table'} + 1;
    $self->{'next_code'}           = $self->{'eod_marker'} + 1;
    $self->{'next_increase'}       = 2**$self->{'code_length'};
    $self->{'at_max_code'}         = 0;
    $self->{'table'} = { map { chr $_ => $_ } 0 .. $self->{'clear_table'} - 1 };
    return;
}

sub _new_code {
    my ($self, $word) = @_;

    if ($self->{'at_max_code'} == 0) {
        $self->{'table'}{$word} = $self->{'next_code'};
        $self->{'next_code'} += 1;
    }

    if ($self->{'next_code'} >= $self->{'next_increase'}) {
        if ($self->{'code_length'} < $self->{'max_code_length'}) {
            $self->{'code_length'}   += 1;
            $self->{'next_increase'} *= 2;
        } else {
            $self->{'at_max_code'} = 1;
        }
    }
    return;
}

sub read_dat {
    my ($self, $data_ref, $partial_code, $partial_bits, $code_length) = @_;
    if (not defined $partial_bits) { $partial_bits = 0; }
    if (not defined $partial_code) { $partial_code = 0; }
    while ($partial_bits < $code_length) {
        return (undef, $partial_code, $partial_bits) unless length($$data_ref);
        $partial_code = ($partial_code << 8) + unpack('C', $$data_ref);
        substr($$data_ref, 0, 1, q{});
        $partial_bits += 8;
    }
    my $code = $partial_code >> ($partial_bits - $code_length);
    $partial_code &= (1 << ($partial_bits - $code_length)) - 1;
    $partial_bits -= $code_length;
    return ($code, $partial_code, $partial_bits);
}

sub _predictor_type {
    my ($self) = @_;
    my $predictor = $self->{'DecodeParms'}->{'Predictor'} // 1;
    if ($predictor == 1 or $predictor == 2) {
        return $predictor;
    } elsif ($predictor == 3) {
        croak 'Floating point TIFF predictor not yet supported';
    } else {
        croak "Invalid predictor: $predictor";
    }
}

sub _depredict {
    my ($self, $data) = @_;
    my $param = $self->{'DecodeParms'} // {};
    my $alpha = $param->{'Alpha'} // 0;
    my $bpc = $param->{'BitsPerComponent'} // 8;
    my $colors  = $param->{'Colors'}  // 1;
    my $columns = $param->{'Columns'} // 1;
    my $rows    = $param->{'Rows'} // 0;

    my $comp = $colors + $alpha;
    my $bpp  = ceil($bpc * $comp / 8);
    my $max  = 256;
    if ($bpc == 8) {
        my @data = unpack('C*', $data);
        for my $j (0 .. $rows - 1) {
            my $count = $bpp * ($j * $columns + 1);
            for my $i ($bpp .. $columns * $bpp - 1) {
                $data[$count] =
                    ($data[$count] + $data[$count - $bpp]) % $max;
                $count++;
            }
        }
        $data = pack('C*', @data);
        return $data;
    }
    return $data;
}

1;