package Mail::SpamAssassin::PDF::Filter::ASCII85Decode;
use strict;
use warnings FATAL => 'all';

# Convert::Ascii85 is an optional dependency: it is only needed to decode
# ASCII85-filtered streams.  Load it lazily so a PDF that uses no ASCII85 (the
# vast majority) parses fine without it; decode() dies with a clear message if
# the module is genuinely needed but missing, which the caller treats as an
# undecodable stream.
use constant HAS_CONVERT_ASCII85 => eval { require Convert::Ascii85; 1 };

sub new {
    my ($class) = @_;
    bless {}, $class;
}

sub decode {
    my ($self, $data) = @_;
    die "Convert::Ascii85 module not available\n" unless HAS_CONVERT_ASCII85;
    Convert::Ascii85::decode($data);
}

1;