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
    my ($self,$data) = @_;

    my $i = new Compress::Raw::Zlib::Inflate( -ConsumeInput => 0 );
    my $uncompressed = '';
    my $status = $i->inflate($data,$uncompressed);
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

        my @prior = (0) x ($columns-1);
        for( my $i=0; $i<$length; $i+=$columns ) {
            my @out;
            my ($alg,@row) = unpack("x$i C$columns",$data);

            if ( $alg == 2 ) {
                # PNG "Up" Predictor
                push(@out,($row[$_]+$prior[$_]) & 0xff) for (0..$#row)
            } else {
                die "PNG algorithm $alg not implemented";
            }

            $out .= pack('C*',@out);
            # printf "i=$i prior=%s row=%s out=%s\n",join(',',@prior),join(',',@row),join(',',@out);

            @prior = @out;
        }

    } else {
        die "Unknown predictor $self->{predictor}";
    }

    return $out;

}

1;