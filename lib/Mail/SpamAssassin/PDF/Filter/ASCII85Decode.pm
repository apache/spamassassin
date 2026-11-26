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
    my ($self, $data, $limit) = @_;
    die "Convert::Ascii85 module not available\n" unless HAS_CONVERT_ASCII85;

    # Convert::Ascii85 makes a list of all the groups in its input, so give it
    # whole groups of five characters, 64 KB of input at a time, returning
    # early once the output is over $limit bytes
    my ($out, $groups) = ('', '');
    for( my $pos=0; $pos<length($data); $pos+=65536 ) {
        my $in = substr($data,$pos,65536);
        $in =~ tr[ \t\r\n\f][]d;
        $in =~ s/z/!!!!!/g;
        $in =~ s/y/+<VdL/g;
        $groups .= $in;
        $out .= Convert::Ascii85::decode(substr($groups,0,length($groups) - length($groups) % 5,''));
        return $out if defined($limit) && length($out) > $limit;
    }
    return $out . Convert::Ascii85::decode($groups);
}

1;