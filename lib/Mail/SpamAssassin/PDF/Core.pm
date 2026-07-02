package Mail::SpamAssassin::PDF::Core;
use strict;
use warnings FATAL => 'all';
use Carp;

=head1 NAME

Mail::SpamAssassin::PDF::Core - Core PDF parsing functions

=head1 DESCRIPTION

This module contains the core PDF parsing functions.  It is not intended to be
used directly, but rather to be used by other modules in this distribution.

=head1 METHODS

=over

=cut

use constant CHAR_SPACE             => 0;
use constant CHAR_DELIM1           => 1;
use constant CHAR_DELIM2           => 2;
use constant CHAR_REGULAR           => 3;

use constant TYPE_NUM     => 0;
use constant TYPE_OP      => 1;
use constant TYPE_STRING  => 2;
use constant TYPE_NAME    => 3;
use constant TYPE_REF     => 4;
use constant TYPE_ARRAY   => 5;
use constant TYPE_DICT    => 6;
use constant TYPE_STREAM  => 7;
use constant TYPE_COMMENT => 8;
use constant TYPE_BOOL    => 9;
use constant TYPE_NULL    => 10;

my %specials = (
    'n' => "\n",
    'r' => "\r",
    't' => "\t",
    'b' => "\b",
    'f' => "\f",
);

my %class_map;
$class_map{chr($_)} = CHAR_REGULAR  for 0x21..0xFF;
$class_map{$_} = CHAR_SPACE         for split //, " \n\r\t\f\x{00}";
$class_map{$_} = CHAR_DELIM1        for split //, '[]()%/';
$class_map{$_} = CHAR_DELIM2        for split //, '<>';

=item new($fh)

Creates a new instance of the object.  $fh is an open file handle to the PDF file or a reference to a scalar containing
the contents of the PDF file.

=cut

sub new {
    my $class = shift;
    my $self = bless {},$class;
    $self->_init(@_);

    # Look for PDF header
    #
    # According to the standard, this should be the first 5 bytes of the file, but some PDFs have extraneous data
    # at the beginning. Acrobat Reader seems to be able to handle this, so we will too.
    my $fh = $self->{fh};
    { local $/ = "%PDF-"; readline($fh); }
    croak("PDF header not found") if eof($fh);

    $self->{starting_offset} = tell($fh) - 5;
    $self->{version} = $self->get_number();
    croak("Invalid version number") unless defined($self->{version});

    return $self;
}

=item clone($fh)

Returns a new instance of the object with the same state as the original, but
using the new file handle. This is useful for parsing objects within objects.

=cut

sub clone {
    my $self = shift;
    my $copy = bless { %$self }, ref $self;
    $copy->_init(@_);
    # Disable encryption for cloned objects. The parent object is already decrypted.
    undef $copy->{crypt};
    return $copy;
}

=item pos($offset)

Sets the file pointer to the specified offset.  If no offset is specified, returns the current offset.

=cut

sub pos {
    my ($self,$offset) = @_;
    defined($offset)
        ? seek($self->{fh},$offset+$self->{starting_offset},0)
        : tell($self->{fh}) - $self->{starting_offset};
}

=item get_number

Reads a number from the file.  A number can be an integer or a real number. Returns undef if no number is found.

=cut

sub get_number {
    my ($self) = @_;
    my $fh = $self->{fh};

    my $offset = $self->pos();
    my $num = $self->get_token();
    return unless defined($num);

    if ( $num !~ /^[0-9+.-]+$/ ) {
        # not a number
        $self->pos($offset);
        return;
    }

    $num += 0;
    return wantarray ? ($num,TYPE_NUM) : $num;
}

=item assert_number($num)

Get the next token from the file and croak if it isn't a number.  If $num is specified, croak if the number doesn't
match $num.

=cut

sub assert_number {
    my ($self,$num) = @_;
    my $fh = $self->{fh};

    my $offset = $self->pos();
    my $token = $self->get_token();
    if (!defined($token) ) {
        # EOF
        croak "Expected number, got EOF";
    }

    if ($token !~ /^[0-9+.-]+$/ ) {
        # not a number
        $self->pos($offset);
        croak "Expected number, got '$token' at offset $offset";
    }

    $token += 0;
    if ( defined($num) && $token != $num ) {
        # not the expected number
        $self->pos($offset);
        croak "Expected number '$num', got '$token' at offset $offset";
    }

}

=item assert_token($literal)

Get the next token from the file and croak if it doesn't match the specified literal.

=cut

sub assert_token {
    my ($self,$literal) = @_;
    my $fh = $self->{fh};

    my $offset = $self->pos();
    my $token = $self->get_token();
    if (!defined($token) ) {
        croak "Expected '$literal', got EOF";
    }
    if ($token ne $literal) {
        $self->pos($offset);
        croak "Expected '$literal', got '$token' at offset $offset";
    }
    1;
}

=item get_token

Get the next token from the file as a string of characters. Will skip leading spaces and comments. Returns undef if
there are no more tokens. Will croak if an invalid character is encountered or if the token is too long.

=cut

sub get_token {
    my ($self) = @_;
    my $fh = $self->{fh};

    # Max token length. This is to prevent reading the entire file into memory if the file is corrupt or if the
    # file pointer is not set correctly.
    my $limit = 256;

    my $token;
    while (defined(my $ch = getc($fh))) {
        my $class = $class_map{$ch};
        unless (defined($class)) {
            seek($fh, -1, 1);
            croak "Invalid character '$ch' at offset " . tell($fh);
        }
        if ( $class == CHAR_SPACE ) {
            if ( defined($token) ) {
                last;
            } else {
                # skip leading whitespace
                next;
            }
        }
        if ( $class == CHAR_DELIM1 ) {
            if ( defined($token) ) {
                seek($fh, -1, 1);
                last;
            } else {
                return $ch;
            }
        }
        if ( $class == CHAR_DELIM2 ) {
            if (defined($token)) {
                seek($fh, -1, 1);
                last;
            } else {
                my $ch2 = getc($fh);
                if (defined($ch2) && $ch2 eq $ch) {
                    return $ch . $ch2;
                } else {
                    seek($fh, -1, 1);
                    return $ch;
                }
            }
        }
        $token .= $ch;
        die "Invalid token length at offset ".tell($fh) if $limit-- == 0;
    }

    return $token;
}

=item get_primitive

Reads a primitive object from the file.  A primitive object can be a number, string, name, array, dictionary,
or reference.

=cut

sub get_primitive {
    my ($self) = @_;
    my $fh = $self->{fh};

NEXT_TOKEN:
    my $token = $self->get_token();
    return unless defined($token);
    if ( $token eq '/' ) {
        return $self->_get_name();
    }
    if ( $token eq '<' ) {
        return $self->_get_hex_string();
    }
    if ( $token eq '(' ) {
        return $self->_get_string();
    }
    if ( $token eq '[' ) {
        return $self->_get_array();
    }
    if ( $token eq '<<' ) {
        return $self->_get_dict();
    }
    if ( $token eq '%' ) {
        # skip comments
        $self->get_line();
        goto NEXT_TOKEN;
    }
    if ( $token =~ /^[0-9]+$/ ) {
        my $offset = $self->pos();
        my $t2 = $self->get_token();
        if ( defined($t2) && $t2 =~ /^[0-9]+$/ ) {
            my $t3 = $self->get_token();
            if ( defined($t3) && $t3 eq 'R') {
                $token = $token . ' ' . $t2 . ' ' . $t3;
                return wantarray ? ($token,TYPE_REF) : $token;
            }
        }
        $self->pos($offset);
        return wantarray ? ($token,TYPE_NUM) : $token;
    }
    if ( $token =~ /^[0-9.+-]+$/ ) {
        return wantarray ? ($token,TYPE_NUM) : $token;
    }
    if ( $token =~ /^true|false$/ ) {
        return wantarray ? ($token,TYPE_BOOL) : $token;
    }
    if ( $token =~ /^null$/ ) {
        return wantarray ? ($token,TYPE_NULL) : $token;
    }

    return wantarray ? ($token,TYPE_OP) : $token;


}

=item get_line

Reads a line from the file.  A line is a sequence of characters terminated by a line feed, a carriage return, or
a carriage return/line feed combo. The returned string will include the newline character(s).  The file pointer is left
at the first character after the line.

=cut

sub get_line {
    my ($self) = @_;
    my $fh = $self->{fh};
    my $line;
    my $limit = 1024;
    while (defined(my $ch = getc($fh)) && $limit--) {
        $line .= $ch;
        if ($ch eq "\n") {
            last;
        } elsif ($ch eq "\r") {
            my $ch2 = getc($fh);
            if (defined($ch2) && $ch2 eq "\n") {
                $line .= $ch2;
                last;
            } else {
                seek($fh, -1, 1);
                return $line;
            }
        }
    }

    return $line;
}

sub get_version {
    my ($self) = @_;
    return $self->{version};
}

=item get_startxref

Reads the startxref value from the end of the file. Will croak if the startxref value is not found or is invalid.

=cut

sub get_startxref {
    my ($self) = @_;
    my $fh = $self->{fh};

    # read backwards from the end of the file looking for 'startxref'
    my $tok = '';
    my $pos = -1;
    my $limit = 65536;
    while ($limit--) {
        seek($fh,$pos--,2);
        my $ch = getc($fh);
        last unless defined($ch);
        if ( $ch =~ /\s/ ) {
            if ( $tok eq 'startxref' ) {
                seek($fh, 9, 1);
                last;
            }
            $tok = '';
            next;
        }
        $tok = $ch . $tok;
    }

    croak "startxref marker not found" unless $tok eq 'startxref';

    my $xref = $self->get_number();
    croak "Invalid startxref" unless defined($xref);

    eval {
        $self->assert_token('%');
        $self->assert_token('%');
        $self->assert_token('EOF');
        1;
    } or do {
        croak "EOF marker not found";
    };

    return $xref;

}

=item get_string

Reads a string from the file.  A string is a sequence of characters enclosed in parentheses.

=cut


sub get_string {
    my ($self) = @_;
    $self->assert_token('(');
    return $self->_get_string();
}

=item get_hex_string

Reads a hex string from the file.  A hex string is a sequence of hexadecimal digits enclosed in angle brackets with
optional whitespace between the digits. If there is an odd number of hex digits, a zero is appended to the string. The
string is then converted to binary and decrypted if necessary. If the string begins with a byte order mark (BOM), it
is converted to UTF-8.

=cut

sub get_hex_string {
    my ($self) = @_;
    $self->assert_token('<');
    return $self->_get_hex_string();
}

=item get_array

Reads an array from the file.  An array is a sequence of objects enclosed in square brackets.

=cut

sub get_array {
    my ($self) = @_;
    $self->assert_token('[');
    return $self->_get_array();
}

=item get_dict

Reads a dictionary from the file.  A dictionary is a sequence of key/value pairs enclosed in double angle brackets.

=cut

sub get_dict {
    my ($self) = @_;
    $self->assert_token('<<');
    return $self->_get_dict();
}

=item get_name

Reads a name from the file.  A name is a sequence of characters beginning with a slash. A name can contain any
character except whitespace and the characters ()<>[]{}/%. Any character except null (character code 0) may be included
in a name by writing its 2-digit hexadecimal code, preceded by the number sign character (#)

=cut

sub get_name {
    my ($self) = @_;
    $self->assert_token('/');
    return $self->_get_name();
}

########################################################################
# Internal methods
########################################################################

sub _init {
    my $self = shift;
    if (ref($_[0]) eq 'SCALAR') {
        # scalar ref, open it as a file
        open(my $fh, '<', $_[0]) or croak "Error opening scalar as file handle: $!";
        binmode($fh);
        $self->{fh} = $fh;
    } elsif (ref($_[0]) eq 'GLOB') {
        $self->{fh} = $_[0];
    } elsif (ref($_[0]) eq '' ) {
        # filename
        open(my $fh, '<', $_[0]) or croak "Error opening file $_[0]: $!";
        binmode($fh);
        $self->{fh} = $fh;
    } else {
        croak "Invalid file handle";
    }
    $self->{pos} = 0;
    $self->{starting_offset} = 0;
}

sub _get_string {
    my ($self) = @_;
    my $fh = $self->{fh};

    my $depth = 1;
    my $str = '';
    my $esc = 0;
    while ($depth > 0) {
        my $ch = getc($fh);
        if ( !defined($ch) ) {
            croak "Unterminated string at offset ".tell($fh);
        }
        if ($esc) {
            if ( defined($specials{$ch}) ) {
                $str .= $specials{$ch};
            } elsif ($ch =~ /[0-7]/) {
                my $oct = $ch;
                $ch = getc($fh);
                if ( $ch =~ /[0-7]/ ) {
                    $oct .= $ch;
                    $ch = getc($fh);
                    if ( $ch =~ /[0-7]/ ) {
                        $oct .= $ch;
                    } else {
                        seek($fh, -1, 1);
                    }
                } else {
                    seek($fh, -1, 1);
                }
                $str .= chr(oct($oct));
            } else {
                $str .= $ch;
            }
            $esc = 0;
        } elsif ($ch eq '\\') {
            $esc = 1;
        } elsif ($ch eq '(') {
            $str .= $ch;
            $depth++;
        } elsif ($ch eq ')') {
            $depth--;
            $str .= $ch if $depth > 0;
        } else {
            $str .= $ch;
        }

    }

    # decrypt
    if ( defined($self->{crypt}) ) {
        $str = $self->{crypt}->decrypt($str);
    }

    return wantarray ? ($str,TYPE_STRING) : $str;
}

sub _get_hex_string {
    my ($self) = @_;
    my $fh = $self->{fh};

    my $hex = '';
    while ( defined(my $ch = getc($fh)) ) {
        last if $ch eq '>';
        next if $ch =~ /\s/; # skip whitespace
        croak "Invalid hex string at offset " . tell($fh) unless $ch =~ /[0-9a-fA-F]/;
        $hex .= $ch;
    }
    # pad with a zero if the length is odd
    $hex .= '0' if length($hex) % 2;
    my $str = pack("H*",$hex);

    # decrypt
    if ( defined($self->{crypt}) ) {
        $str = $self->{crypt}->decrypt($str);
    }

    return  wantarray ? ($str,TYPE_STRING) : $str;
}

=item _get_array

Reads an array from the file.  An array is a sequence of objects enclosed in square brackets.  The file pointer is left
at the first character after the array.

=cut

sub _get_array {
    my ($self) = @_;
    my @array;

    while () {
        local $_ = $self->get_primitive();
        croak "Unexpected end of file" unless defined($_);
        last if $_ eq ']';
        push(@array,$_);
    }

    return wantarray ? (\@array,TYPE_ARRAY) : \@array;
}

sub _get_dict {
    my ($self) = @_;
    my $fh = $self->{fh};
    my @array;

    while () {
        local $_ = $self->get_primitive();
        croak "Unexpected end of file" unless defined($_);
        last if $_ eq '>>';
        push(@array,$_);
    }

    my %dict = @array;

    # From the docs: "The keyword stream that follows the stream dictionary shall be followed by an end-of-line marker
    #   consisting of either a CARRIAGE RETURN and a LINE FEED or just a LINE FEED, and not by a CARRIAGE
    #   RETURN alone."
    # Unfortunately this isn't always true in real life so we have to allow:
    #   stream\r\n
    #   stream\n
    #   stream\r
    # get_line() will handle all of these cases for us

    if ( exists($dict{'/Length'})) {
        # check for stream data following the dictionary
        my $offset = $self->pos();
        while (defined(my $line = $self->get_line())) {
            next if $line =~ /^\s*$/; # skip blank lines
            if ($line =~ /^\s*stream\b/) {
                $dict{_stream_offset} = $self->pos();
                return wantarray ? (\%dict, TYPE_STREAM) : \%dict;
            }
            last;
        }
        # not a stream dictionary
        $self->pos($offset);
    }

    return wantarray ? (\%dict,TYPE_DICT) : \%dict;

}

sub _get_name {
    my ($self) = @_;
    my $fh = $self->{fh};

    my $name = '/';
    while ( defined(my $ch = getc($fh)) ) {
        my $class = $class_map{$ch};
        unless (defined($class)) {
            seek($fh, -1, 1);
            croak "Invalid character '$ch' at offset " . tell($fh);
        }
        last if $class == CHAR_SPACE;
        if ( $class != CHAR_REGULAR ) {
            seek($fh, -1, 1);
            last;
        }
        $name .= $ch;
    }
    $name =~ s/#([0-9a-fA-F]{2})/chr(hex($1))/ge;

    return wantarray ? ($name,TYPE_NAME) : $name;

}


=back

=cut

1;