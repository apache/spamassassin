package Mail::SpamAssassin::PDF::Filter::FlateDecode;
use strict;
use warnings FATAL => 'all';
# use Compress::Zlib;
use Compress::Raw::Zlib qw(Z_OK Z_STREAM_END);

sub new {
    my ($class,$params) = @_;

    my $self = {};

    if ( defined($params) && $params ne 'null' ) {
        $self->{predictor} = $params->{'/Predictor'};
        $self->{columns} = $params->{'/Columns'};
    }

    bless $self, $class;
}

sub decode {
    my ($self,$data,$limit) = @_;

    # inflate 1 KB of input at a time (at most about 1 MB of output), returning
    # early once the output is over $limit bytes
    my $i = new Compress::Raw::Zlib::Inflate( -AppendOutput => 1 );
    my $uncompressed = '';
    my $status = Z_OK;
    for( my $pos=0; $status == Z_OK && $pos<length($data); $pos+=1024 ) {
        my $in = substr($data,$pos,1024);
        $status = $i->inflate($in,$uncompressed);
        return $uncompressed if defined($limit) && length($uncompressed) > $limit;
    }
    unless ( $status == Z_OK || $status == Z_STREAM_END ) {
        die "Error inflating data: " . $i->msg;
    }
    $data = $uncompressed;
    return $data unless defined($self->{predictor});

    my $out;
    if ( $self->{predictor} == 1 ) {
        return $data;
    } elsif ( $self->{predictor} == 2 ) {
        die "TIFF Predictor not implemented";
    } elsif ( $self->{predictor} >= 10 ) {

        # PNG Predictor https://www.rfc-editor.org/rfc/rfc2083#section-6
        my $columns = $self->{columns} + 1;
        my $length = length($data);

        die "Invalid Columns $self->{columns}" if $columns < 1;

        my $prior;
        for( my $i=0; $i<$length; $i+=$columns ) {
            my $alg = ord(substr($data,$i,1));
            die "PNG algorithm $alg not implemented" unless $alg == 2;

            # PNG "Up" Predictor, 4096 bytes of the row at a time
            my $row = substr($data,$i+1,$columns-1);
            $prior //= "\0" x length($row);
            my $up = '';
            for( my $j=0; $j<length($row); $j+=4096 ) {
                my @row = unpack('C*',substr($row,$j,4096));
                my @prior = unpack('C*',substr($prior,$j,4096));
                $up .= pack('C*',map { ($row[$_]+$prior[$_]) & 0xff } 0..$#row);
            }

            $out .= $up;
            $prior = $up;
        }

    } else {
        die "Unknown predictor $self->{predictor}";
    }

    return $out;

}

1;