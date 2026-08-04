=head1 NAME

Mail::SpamAssassin::PDF::Parser - Parse PDF documents

=head1 SYNOPSIS

    use Mail::SpamAssassin::PDF::Parser;
    my $parser = Mail::SpamAssassin::PDF::Parser->new(timeout => 5);
    $parser->parse(\$data);
    print $parser->version();
    print $parser->info()->{Author};
    print $parser->is_encrypted();
    print $parser->is_protected();

=over

=cut

package Mail::SpamAssassin::PDF::Parser;
use strict;
use warnings FATAL => 'all';
use Mail::SpamAssassin::PDF::Core;
use Mail::SpamAssassin::PDF::Context::Info;
use Mail::SpamAssassin::PDF::Filter::FlateDecode;
use Mail::SpamAssassin::PDF::Filter::LZWDecode;
use Mail::SpamAssassin::PDF::Filter::ASCII85Decode;
use Mail::SpamAssassin::PDF::Filter::Decrypt;
use Encode qw(from_to);
use Carp;

my $debug;  # debugging level

my %abbreviations = (
    '/BPC'  => '/BitsPerComponent',
    '/CS'   => '/ColorSpace',
    '/D'    => '/Decode',
    '/DP'   => '/DecodeParms',
    '/F'    => '/Filter',
    '/H'    => '/Height',
    '/IM'   => '/ImageMask',
    '/I'    => '/Interpolate',
    '/W'    => '/Width',
    '/G'    => '/DeviceGray',
    '/RGB'  => '/DeviceRGB',
    '/CMYK' => '/DeviceCMYK',
    '/AHx'  => '/ASCIIHexDecode',
    '/A85'  => '/ASCII85Decode',
    '/LZW'  => '/LZWDecode',
    '/Fl'   => '/FlateDecode',
    '/RL'   => '/RunLengthDecode',
    '/CCF'  => '/CCITTFaxDecode',
    '/DCT'  => '/DCTDecode'
);

=item new(%opts)

Create a new parser object. Options are:

=over

=item context

A Mail::SpamAssassin::PDF::Context object. This object will be used to
handle callbacks for various PDF objects. See L<Mail::SpamAssassin::PDF::Context>
for more information.

=item timeout

Timeout in seconds. If the PDF document takes longer than this to parse,
the parser will die with an error. This is useful for preventing denial
of service attacks.

=item debug

Set the debugging level. Valid values are 'all', 'trace', 'xref', 'stream',
'tokens', 'page', 'image', 'text', 'uri'

=back

=cut

sub new {
    my ($class,%opts) = @_;

    my $self = bless {
        context      => $opts{context} || Mail::SpamAssassin::PDF::Context::Info->new(),
        timeout      => $opts{timeout},
    }, $class;

    $debug = $opts{debug};

    $self;
}

=item parse($data)

Parse a PDF document. $data can be a filename, a reference to a scalar containing the PDF data, or a file handle.

=cut

sub parse {
    my ($self,$data) = @_;

    # Initialize object
    $self->{object_cache} = {};
    $self->{stream_cache} = {};
    $self->{xref} = {};
    $self->{trailer} = {};
    $self->{pages} = [];
    $self->{is_encrypted} = 0;
    $self->{is_protected} = 0;


    $self->{core} = Mail::SpamAssassin::PDF::Core->new($data);

    # Parse header
    $self->{version} = $self->{core}->get_version();

    local $SIG{ALRM} = sub {die "__TIMEOUT__\n"};
    alarm($self->{timeout}) if (defined($self->{timeout}));

    eval {

        # Parse cross-reference table (and trailer)
        debug('trace',"Calling _parse_xref");
        $self->_parse_xref($self->{core}->get_startxref());
        debug('xref',$self->{xref});
        debug('trailer',$self->{trailer});

        # Parse encryption dictionary
        debug('trace',"Calling _parse_encrypt");
        $self->_parse_encrypt($self->{trailer}->{'/Encrypt'}) if defined($self->{trailer}->{'/Encrypt'});

        if ( !$self->{is_protected} ) {

            # Parse info object
            debug('trace',"Calling _parse_info");
            $self->{trailer}->{'/Info'} = $self->_parse_info($self->{trailer}->{'/Info'});
            debug('info',$self->{trailer}->{'/Info'});
            $self->{trailer}->{'/Root'} = $self->_get_obj($self->{trailer}->{'/Root'});
            debug('root',$self->{trailer}->{'/Root'});

            # Parse catalog
            my $root = $self->{trailer}->{'/Root'};
            if (defined($root->{'/OpenAction'}) && ref($root->{'/OpenAction'}) eq 'HASH') {
                $root->{'/OpenAction'} = $self->_dereference($root->{'/OpenAction'});
                $self->{context}->open_action($root->{'/OpenAction'}) if $self->{context}->can('open_action');
                debug('trace',"Calling _parse_action");
                $self->_parse_action($root->{'/OpenAction'});
            }
            if (defined($root->{'/AA'}) ) {
                # Additional Actions
                $self->{context}->open_action($root->{'/AA'}) if $self->{context}->can('open_action');
            }

            if ($self->{context}->can('parse_begin')) {
                debug('trace',"Calling _parse_begin");
                $self->{context}->parse_begin($self);
            }

            # Parse page tree
            debug('trace',"Calling _parse_pages");
            $root->{'/Pages'} = $self->_parse_pages($root->{'/Pages'});

        }

        if ($self->{context}->can('parse_end')) {
            debug('trace',"Calling _parse_end");
            $self->{context}->parse_end($self);
        }

        1;
    } or do {
        if ( $@ eq "__TIMEOUT__\n" ) {
            croak "Timeout limit exceeded";
        }
        alarm(0);
        die $@;
    };

    alarm(0);

}

sub version {
    shift->{version};
}

sub info {
    shift->{trailer}->{'/Info'};
}

sub is_encrypted {
    shift->{is_encrypted};
}

sub is_protected {
    shift->{is_protected};
}

###################
# Private methods
###################
sub _parse_xref {
    my ($self,$pos) = @_;
    my $core = $self->{core};

    $core->pos($pos);
    my $token = eval { $core->get_token(); } // '';
    if ( $token ne 'xref' ) {
        # not a cross-reference table. See if it's a cross-reference stream
        eval {
            die if ($token !~ /^\d+$/);
            $core->assert_number();
            $core->assert_token('obj');
            1;
        } or do {
            # not a cross-reference stream either. Try to repair the file
            return $self->_repair_xref($pos);
        };
        debug('xref','Parsing xref stream at offset '.$pos);
        my $xref = $core->get_dict();
        return $self->_parse_xref_stream($xref);
    }
    debug('xref','Parsing xref table at offset '.$pos);

    while () {
        my $start = eval { $core->get_number(); };
        last unless defined($start);
        my $count = $core->get_number();
        debug('xref',"start=$start count=$count");
        for (my ($i,$n)=($start,0);$n<$count;$i++,$n++) {
            my $offset = $core->get_number();
            my $gen = $core->get_number();
            my $type = $core->get_primitive();
            next unless $type eq 'n';
            my $key = "$i $gen R";
            $self->{xref}->{$key} = $offset unless defined($self->{xref}->{$key});
        }
    }

    $core->assert_token('trailer');

    my $trailer = $core->get_dict();
    $self->{trailer} = {
        %{$trailer},
        %{$self->{trailer}}
    };

    if ( defined($trailer->{'/Prev'}) ) {
        return $self->_parse_xref($trailer->{'/Prev'});
    }

    return 1;

}

sub _parse_xref_stream {
    my ($self,$xref) = @_;

    my $data = $self->_get_stream_data($xref);
    my $width = $xref->{'/W'}->[0] + $xref->{'/W'}->[1] + $xref->{'/W'}->[2];
    my $template = 'H'.($xref->{'/W'}->[0]*2).'H'.($xref->{'/W'}->[1]*2).'H'.($xref->{'/W'}->[2]*2);
    my @index = defined($xref->{'/Index'}) ? @{$xref->{'/Index'}} : (0,$xref->{'/Size'});
    die "Odd number of elements in index while parsing xref stream" if (scalar(@index) % 2 != 0);

    my $o = 0;
    for (my $i=0;$i<scalar(@index);$i+=2) {
        my ($start,$count) = ($index[$i],$index[$i+1]);
        for ( my ($n,$c)=($start,0); $c<$count; $n++,$c++ ) {
            my ($type,@fields) = map { hex($_) } unpack("x$o $template",$data);
            $o+=$width;
            if ( $type == 0 ) {
                next;
            } elsif ( $type == 1 ) {
                my ($offset,$gen) = @fields;
                my $key = "$n $gen R";
                $self->{xref}->{$key} = $offset unless defined($self->{xref}->{$key});
            } elsif ( $type == 2 ) {
                my ($obj,$index) = @fields;
                my $key = "$n 0 R";
                $self->{xref}->{$key} = [ "$obj 0 R", $index ]; # unless defined($self->{xref}->{$key});
            }
        }
    }

    $self->{trailer} = $xref;

    if ( defined($xref->{'/Prev'}) ) {
        $self->_parse_xref($xref->{'/Prev'});
    }

    return 1;

}

# sub _repair_xref()
#
# Try to repair a PDF file that has a corrupt xref table. This generally happens when a PDF has been transmitted
# over a network and the line endings have been converted from DOS to Unix or vice versa. This causes the offsets
# in the xref table to be incorrect. This method will scan the file from beginning to end looking for objects and
# creates the xref table manually. This seems to be how Adobe Reader handles it so we'll do the same.
#
sub _repair_xref {
    my ($self) = @_;
    my $core = $self->{core};
    my @token_buf;
    my @pos_buf;
    my @xref_stream;

    # Scan the file from the beginning looking for objects and add them to the xref table
    $core->pos(0);
    while () {
        my $pos = $core->pos();
        my $token = $core->get_token();
        last unless defined($token);
        if ( $token eq 'obj' ) {
            # found object
            my $ref = join(' ',@token_buf).' R';
            $self->{xref}->{$ref} = $pos_buf[0];
            my $obj = $core->get_primitive();
            if ( ref($obj) eq 'HASH' && defined($obj->{_stream_offset}) ) {
                # Object stream. Skip over stream data
                { local $/ = "\nendstream"; readline $core->{fh}; }

                # Calculate stream length (may be different from Length entry)
                $obj->{_stream_length} = $core->pos() - $obj->{_stream_offset} - 10;

                # Store in cache
                $obj->{_objnum} = $token_buf[0];
                $obj->{_gennum} = $token_buf[1];
                $self->{object_cache}->{$ref} = $obj;

                if ( defined($obj->{'/Type'}) && $obj->{'/Type'} eq '/XRef' ) {
                    # Found xref stream. Process these later
                    push(@xref_stream, $obj);
                }
            }
            @token_buf = ();
            @pos_buf = ();
            next;
        }
        if ( $token eq 'trailer' ) {
            # found trailer
            my $trailer = $core->get_dict();
            $self->{trailer} = {
                %{$trailer},
                %{$self->{trailer}}
            };
            last;
        }

        # keep the last two tokens and their positions in a buffer
        push(@token_buf,$token);
        push(@pos_buf,$pos);
        if (scalar(@token_buf) > 2) {
            shift @token_buf;
            shift @pos_buf;
        }
    }

    die "Trailer not found" unless defined($self->{trailer});

    # Process xref streams in reverse order
    while () {
        my $xref_stream = pop(@xref_stream);
        last unless defined($xref_stream);
        undef $xref_stream->{'/Prev'}; # prevent recursion
        $self->_parse_xref_stream($xref_stream);
    }



}

sub _parse_encrypt {
    my ($self,$encrypt) = @_;
    $encrypt = $self->_dereference($encrypt);
    return unless defined($encrypt);

    if ( $encrypt->{'/Filter'} ne '/Standard' ) {
        die "Encryption filter $encrypt->{'/Filter'} not implemented";
    }

    $self->{core}->{crypt} = Mail::SpamAssassin::PDF::Filter::Decrypt->new($encrypt,$self->{trailer}->{'/ID'}->[0]);
    if ( !defined($self->{core}->{crypt}) ) {
        $self->{is_protected} = 1;
    }
    $self->{is_encrypted} = 1;
    debug('crypt',$self->{core}->{crypt});

}

sub _parse_info {
    my ($self,$info) = @_;
    $info = $self->_dereference($info);
    return unless defined($info);

    foreach (keys %{$info}) {
        $info->{$_} = $self->_dereference($info->{$_});
        _to_utf8($info->{$_});
    }

    return $info;
}

sub _parse_pages {
    my ($self,$node,$parent_node) = @_;
    $node = $self->_dereference($node);
    return unless defined($node);

    # inherit properties
    $parent_node = {} unless defined($parent_node);
    for (qw(/MediaBox /Resources) ) {
        next unless defined($parent_node->{$_});
        $node->{$_} = $parent_node->{$_} unless defined($node->{$_});
    }

    if ( !defined($node->{'/Type'}) ) {
        # Type is required but sometimes it's missing
        $node->{'/Type'} = defined($node->{'/Kids'}) ? '/Pages' :
                           defined($node->{'/Contents'}) ? '/Page' :
                           die "Page type not found";
    }

    if ( $node->{'/Type'} eq '/Pages' ) {
        $node->{'/Kids'} = $self->_dereference($node->{'/Kids'});
        $self->_parse_pages($_, $node) for (@{$node->{'/Kids'}});
    } elsif ( $node->{'/Type'} eq '/Page' ) {
        $node->{'/MediaBox'} = $self->_dereference($node->{'/MediaBox'});
        my $process_page = 1;
        push @{$self->{pages}}, $node;
        $node->{page_number} = scalar(@{$self->{pages}});

        # call page begin handler
        $process_page = $self->{context}->page_begin($node) if $self->{context}->can('page_begin');

        # Annotations are parsed for every page, even when the context declines
        # to process the page body.  Link annotations are where URIs live, and a
        # phisher can put the link on any page; skipping them would hide the URI
        # entirely.  This is cheap -- a dict lookup per annotation -- unlike the
        # content stream rendering below.
        $self->_parse_annotations($node->{'/Annots'},$node) if (defined($node->{'/Annots'}));

        if ( $process_page ) {
            $node->{'/Resources'} = $self->_parse_resources($node->{'/Resources'}) if (defined($node->{'/Resources'}));
            $self->_parse_contents($node->{'/Contents'},$node) if (defined($node->{'/Contents'}));

            # call page end handler
            $self->{context}->page_end($node) if $self->{context}->can('page_end');
        }

    } else {
        die "Unexpected page type";
    }

    return $node;

}

sub _parse_annotations {
    my ($self,$annots,$page) = @_;
    $annots = $self->_dereference($annots);
    return unless defined($annots);

    for my $ref (@$annots) {
        my $annot = $self->_dereference($ref);
        if ( defined($annot->{'/Subtype'}) && $annot->{'/Subtype'} eq '/Link' && defined($annot->{'/A'}) ) {
            $self->_parse_action($annot->{'/A'},$annot->{'/Rect'},$page);
        }
    }

}

sub _parse_action {
    my ($self,$action,$rect,$page) = @_;
    $action = $self->_dereference($action);
    return unless defined($action);

    if ( $action->{'/S'} eq '/URI' ) {
        # /URI may be given as an indirect reference to a string object
        my $location = $self->_dereference($action->{'/URI'});
        if ( defined($location) ) {
            if ( $location !~ /^[a-z]+:/i && $location =~ /^[^\s\/?#]+\.[^\s\/?#]+/ ) {
                # Schemeless URI that looks like a hostname — most viewers
                # treat these as http://, so normalize for downstream rules.
                $location = 'http://' . $location;
            }
            if ( $location =~ /^[a-z]+:/i ) {
                $rect = $self->_dereference($rect);
                $_ = $self->_dereference($_) for (@{$rect});
                $self->{context}->uri($location,$rect,$page) if $self->{context}->can('uri');
            }
        }
    }
    if ( $action->{'/S'} eq '/JavaScript' ) {
        $self->{context}->javascript($action->{'/JS'}) if $self->{context}->can('javascript');
    }

    if ( defined($action->{'/Next'}) ) {
        # can be array or dict
        if ( ref($action->{'/Next'}) eq 'ARRAY' ) {
            $self->_parse_action($_) for @{$action->{'/Next'}};
        } else {
            $self->_parse_action($action->{'/Next'});
        }
    }

}

sub _parse_resources {
    my ($self,$resources) = @_;
    $resources = $self->_dereference($resources);
    return unless defined($resources);

    $resources->{'/XObject'} = $self->_parse_xobject($resources->{'/XObject'}) if (defined($resources->{'/XObject'}));
    return $resources;
}

sub _parse_xobject {
    my ($self,$xobject) = @_;
    $xobject = $self->_dereference($xobject);
    return unless defined($xobject);

    for my $name (keys %$xobject) {
        my $ref = $xobject->{$name};
        my $obj = $xobject->{$name} = $self->_dereference($ref);
        if ( $obj->{'/Subtype'} eq '/Image' ) {
            $obj->{'/ColorSpace'} = $self->_dereference($obj->{'/ColorSpace'});
        } elsif ( $obj->{'/Subtype'} eq '/Form' ) {
            $obj->{'/Resources'} = $self->_parse_resources($obj->{'/Resources'}) if (defined($obj->{'/Resources'}));
        }
    }
    return $xobject;
}

sub _parse_contents {
    my ($self,$contents,$page,$resources) = @_;
    return if $self->is_protected();

    $resources = $self->_dereference($resources) || $page->{'/Resources'};

    #@type Mail::SpamAssassin::PDF::Context
    my $context = $self->{context};
    my @params;

    # Build a dispatch table
    my %dispatch = (
        q  => sub { $context->save_state() },
        Q  => sub { $context->restore_state() },
        cm => sub { $context->concat_matrix(@_) },
        Do => sub {
            my $xobj = $resources->{'/XObject'}->{$_[0]};
            unless (defined($xobj)) {
                warn "XObject $_[0] not found: ";
                return;
            }
            $xobj->{_name} = $_[0];
            if ( $xobj->{'/Subtype'} eq '/Image' ) {
                $context->draw_image($xobj,$page) if $self->{context}->can('draw_image');
            } elsif ( $xobj->{'/Subtype'} eq '/Form' ) {
                $context->save_state();
                if (defined($xobj->{'/Matrix'})) {
                    my $matrix = $xobj->{'/Matrix'};
                    $matrix = $self->_dereference($matrix) if ref($matrix) ne 'ARRAY';
                    $context->concat_matrix(@{$matrix});
                }
                $self->_parse_contents($xobj, $page, $xobj->{'/Resources'});
                $context->restore_state();
            }
        }
    );

    # Contents can be one of the following:
    # 1. Reference to a content stream i.e. "35 0 R"
    # 2. An array of content stream references i.e. [ "35 0 R", "36 0 R" ]
    # 3. A reference to an array of content streams i.e. "6 0 R" which points to [ "35 0 R", "36 0 R" ]
    # Convert all of the above to an array ref:
    if (ref($contents) ne 'ARRAY') {
        # reference to something
        my $obj = $self->_get_obj($contents);
        if ( ref($obj) eq 'ARRAY' ) {
            # reference to an array (#3)
            $contents = $obj;
        } else {
            # reference to a content stream (#1)
            $contents = [ $contents ];
        }
    }

    # Concatenate content streams
    my $stream = '';
    for my $obj ( @$contents ) {
        $stream .= $self->_get_stream_data($obj) . "\n";
    }
    debug('stream',$stream);

    my $core = $self->{core}->clone(\$stream);

    # Process commands
    while () {
        my ($token,$type) = $core->get_primitive();
        last unless defined($token);
        debug('tokens',"$type: $token");
        if ( $type != Mail::SpamAssassin::PDF::Core::TYPE_OP ) {
            push(@params,$token);
            next;
        }
        if ( $token eq 'BI' ) {
            my $image = $self->_parse_inline_image($core);
            $context->draw_image($image,$page) if $self->{context}->can('draw_image');
            next;
        }
        if ( defined($dispatch{$token}) ) {
            $dispatch{$token}->(@params);
        }
        @params = ();
    }

}

sub _parse_inline_image {
    my ($self,$core) = @_;

    my @array;
    while () {
        my $token = $core->get_primitive();
        last if $token eq 'ID';
        $token = $abbreviations{$token} if defined($abbreviations{$token});
        push(@array,$token);
    }
    my %image = @array;

    # skip over image data
    local $/ = "\nEI";
    readline $core->{fh};

    return \%image;
}

sub _get_obj {
    my ($self,$ref) = @_;
    my $core = $self->{core};

    # return undef for non-existent objects
    return undef unless defined($ref) && defined($self->{xref}->{$ref});

    if ( !defined($self->{object_cache}->{$ref}) ) {
        my ($objnum,$gennum) = $ref =~ /^(\d+) (\d+) R$/;
        if (defined($core->{crypt})) {
            $core->{crypt}->set_current_object($objnum, $gennum);
        }

        my $obj;
        if ( ref($self->{xref}->{$ref}) eq 'ARRAY' ) {
            my ($stream_obj_ref,$index) = @{$self->{xref}->{$ref}};
            debug('trace',"Getting compressed object $ref from $stream_obj_ref");
            $obj = $self->_get_compressed_obj($stream_obj_ref,$index,$ref);
        } else {
            $core->pos($self->{xref}->{$ref});
            eval {
                $core->get_number();
                $core->get_number();
                $core->assert_token('obj');
                $obj = $core->get_primitive();
                1;
            } or die "Error getting object $ref: $@";
        }
        if ( ref($obj) eq 'HASH' and defined($obj->{_stream_offset}) ) {
            # stream object. Store object number for decryption later
            $obj->{_objnum} = $objnum;
            $obj->{_gennum} = $gennum;
        }
        $self->{object_cache}->{$ref} = $obj;
    }

    return $self->{object_cache}->{$ref};
}

sub _dereference {
    my ($self,$obj) = @_;
    while ( defined($obj) && !ref($obj) && $obj =~ /^\d+ \d+ R$/ ) {
        $obj = $self->_get_obj($obj);
    }
    return $obj;
}

sub _get_compressed_obj {
    my ($self,$stream_obj_ref,$index,$ref) = @_;

    $ref =~ /^(\d+)/ or die "invalid object reference";
    my $obj = $1;

    my $stream_obj = $self->_get_obj($stream_obj_ref);

    if ( !defined($stream_obj->{core}) ) {
        my $data = $self->_get_stream_data($stream_obj);
        die "Error getting stream data for object $ref" unless defined($data);
        my $core = $stream_obj->{core} = $self->{core}->clone(\$data);
        for(my $n = $stream_obj->{'/N'}; $n > 0; $n--) {
            my $key = $core->get_number();
            die "Error getting xref key for object $ref" unless defined($key);
            $stream_obj->{xref}->{$key} = $core->get_number();
        }
        $stream_obj->{pos} = $core->pos();
    }

    $stream_obj->{core}->pos($stream_obj->{pos}+$stream_obj->{xref}->{$obj});
    return $self->{object_cache}->{$ref} = $stream_obj->{core}->get_primitive();
}

sub _get_stream_data {
    my ($self,$stream_obj) = @_;
    local $_ = $self->_dereference($stream_obj);
    unless (defined($_)) {
        die "Error getting stream data. Object not found\n" . _dump($stream_obj);
    }

    # not a stream object
    unless (ref($_) eq 'HASH' && defined($_->{_stream_offset})) {
        die "Error getting stream data. Object is not a stream\n" . _dump($stream_obj);
    }

    $stream_obj = $_;
    my $offset = $stream_obj->{_stream_offset};
    my $length = defined($stream_obj->{_stream_length})
        ? $stream_obj->{_stream_length}
        : $self->_dereference($stream_obj->{'/Length'});
    my @filters;
    if ( defined($stream_obj->{'/Filter'}) ) {
        my $filter = $self->_dereference($stream_obj->{'/Filter'});
        @filters = ref($filter) eq 'ARRAY' ? @{$filter} : ( $filter );
    }

    my @decodeParms;
    if (defined($stream_obj->{'/DecodeParms'})) {
        my $decodeParms = $self->_dereference($stream_obj->{'/DecodeParms'});
        @decodeParms = ref($decodeParms) eq 'ARRAY' ? @{$decodeParms} : ($decodeParms);
    }

    # check for cached version
    return $self->{stream_cache}->{$offset} if defined($self->{stream_cache}->{$offset});

    $self->{core}->pos($offset);
    read($self->{core}->{fh},my $stream_data,$length);
    if (defined($self->{core}->{crypt})) {
        $self->{core}->{crypt}->set_current_object($stream_obj->{_objnum}, $stream_obj->{_gennum});
        $stream_data = $self->{core}->{crypt}->decrypt($stream_data);
    }
    $self->{core}->assert_token('endstream');

    for (my $i=0;$i<scalar(@filters);$i++) {
        my $filter = $self->_dereference($filters[$i]);
        my $decodeParms = $self->_dereference($decodeParms[$i]);
        $filter = $abbreviations{$filter} if defined($abbreviations{$filter});
        if ( $filter eq '/FlateDecode' ) {
            my $f = Mail::SpamAssassin::PDF::Filter::FlateDecode->new($decodeParms);
            $stream_data = $f->decode($stream_data);
        } elsif ( $filter eq '/LZWDecode' ) {
            my $f = Mail::SpamAssassin::PDF::Filter::LZWDecode->new($decodeParms);
            $stream_data = $f->decode($stream_data);
        } elsif ( $filter eq '/ASCII85Decode' ) {
            my $f = Mail::SpamAssassin::PDF::Filter::ASCII85Decode->new();
            $stream_data = $f->decode($stream_data);
        } else {
            die "Filter $filter not implemented";
        }
    }

    return $self->{stream_cache}->{$offset} = $stream_data;

}

#
# Read image stream data for extraction purposes.
#
# Unlike _get_stream_data (which fully decodes or dies), this applies the general byte
# filters (Flate/LZW/ASCII85) and then handles the trailing image codec specially.  It
# never dies on unimplemented image filters.
#
# Returns ($format, $bytes) where $format is one of:
#   'raw'         - fully decoded raw samples (Flate/LZW/ASCII85 chain completed); $bytes
#                   are the raw samples, to be wrapped in an image header by the caller
#   'jpeg'        - DCTDecode reached; $bytes are a complete JPEG file, usable as-is
#   'unsupported' - reached a codec we can't undo and can't pass through (CCITTFax/JPX/
#                   RunLength/etc.); $bytes is undef because the data so far is useless
#                   (neither raw samples nor a standalone image file)
# Returns () if the object isn't a readable stream.
#
sub _get_image_data {
    my ($self,$stream_obj) = @_;
    $stream_obj = $self->_dereference($stream_obj);
    return () unless ref($stream_obj) eq 'HASH' && defined($stream_obj->{_stream_offset});

    my $offset = $stream_obj->{_stream_offset};
    my $length = defined($stream_obj->{_stream_length})
        ? $stream_obj->{_stream_length}
        : $self->_dereference($stream_obj->{'/Length'});

    my @filters;
    if ( defined($stream_obj->{'/Filter'}) ) {
        my $filter = $self->_dereference($stream_obj->{'/Filter'});
        @filters = ref($filter) eq 'ARRAY' ? @{$filter} : ( $filter );
    }
    my @decodeParms;
    if (defined($stream_obj->{'/DecodeParms'})) {
        my $decodeParms = $self->_dereference($stream_obj->{'/DecodeParms'});
        @decodeParms = ref($decodeParms) eq 'ARRAY' ? @{$decodeParms} : ($decodeParms);
    }

    # Read and decrypt raw stream bytes (mirrors _get_stream_data, but uncached since
    # the result here is image-specific and not what other callers expect).
    $self->{core}->pos($offset);
    read($self->{core}->{fh},my $stream_data,$length);
    if (defined($self->{core}->{crypt})) {
        $self->{core}->{crypt}->set_current_object($stream_obj->{_objnum}, $stream_obj->{_gennum});
        $stream_data = $self->{core}->{crypt}->decrypt($stream_data);
    }

    for (my $i=0;$i<scalar(@filters);$i++) {
        my $filter = $self->_dereference($filters[$i]);
        my $decodeParms = $self->_dereference($decodeParms[$i]);
        $filter = $abbreviations{$filter} if defined($abbreviations{$filter});
        if ( $filter eq '/FlateDecode' ) {
            my $f = Mail::SpamAssassin::PDF::Filter::FlateDecode->new($decodeParms);
            $stream_data = $f->decode($stream_data);
        } elsif ( $filter eq '/LZWDecode' ) {
            my $f = Mail::SpamAssassin::PDF::Filter::LZWDecode->new($decodeParms);
            $stream_data = $f->decode($stream_data);
        } elsif ( $filter eq '/ASCII85Decode' ) {
            my $f = Mail::SpamAssassin::PDF::Filter::ASCII85Decode->new();
            $stream_data = $f->decode($stream_data);
        } elsif ( $filter eq '/DCTDecode' ) {
            # Whatever we have so far is a complete JPEG file; return it as-is.
            return ('jpeg', $stream_data);
        } else {
            # CCITTFaxDecode, JPXDecode, RunLengthDecode, etc. - can't decode (yet)
            return ('unsupported', undef);
        }
    }

    return ('raw', $stream_data);
}

#
# Decode the XObject images collected during parsing into descriptors ready for the
# caller to re-encode (e.g. as PNG/JPEG sub-parts).  Returns an arrayref of hashrefs:
#   { format => 'raw'|'jpeg', bytes => $data, width, height, colorspace, bpc }
# Honors caps:
#   max_images - stop after this many usable images (default 4)
#   max_pixels - skip images larger than this (width*height) (default 25_000_000;
#                0 disables the limit)
#
sub extract_images {
    my ($self,%opts) = @_;

    my $context = $self->{context};
    return [] unless $context->can('get_image_candidates');
    my $candidates = $context->get_image_candidates();
    return [] unless ref($candidates) eq 'ARRAY' && @$candidates;

    my $max_images = defined($opts{max_images}) ? $opts{max_images} : 4;
    my $max_pixels = defined($opts{max_pixels}) ? $opts{max_pixels} : 25_000_000;

    my @images;
    my $idx = 0;
    for my $desc ( @$candidates ) {
        $idx++;
        last if @images >= $max_images;

        my $w = $desc->{width}  || 0;
        my $h = $desc->{height} || 0;

        if ( $max_pixels && $w && $h && ($w * $h) > $max_pixels ) {
            debug('image', "image $idx skipped: ${w}x${h} exceeds max_pixels=$max_pixels");
            next;
        }

        my ($format, $bytes) = eval { $self->_get_image_data($desc->{dict}) };
        if ( $@ ) {
            chomp(my $e = $@);
            debug('image', "image $idx decode error: $e");
            next;
        }
        next unless defined($format) && $format ne 'unsupported' && defined($bytes);

        push(@images, {
            format     => $format,
            bytes      => $bytes,
            width      => $w,
            height     => $h,
            colorspace => $desc->{colorspace},
            bpc        => $desc->{bpc},
        });
    }

    return \@images;
}

# PDFDocEncoding mapping table from Adobe specs
my %pdfdoc_to_unicode = (
    # 0x80 - 0x9F (special symbols, different from Latin-1)
    0x80 => 0x2022, # bullet
    0x81 => 0x2020, # dagger
    0x82 => 0x2021, # double dagger
    0x83 => 0x2026, # ellipsis
    0x84 => 0x2014, # em dash
    0x85 => 0x2013, # en dash
    0x86 => 0x0192, # florin
    0x87 => 0x2044, # fraction slash
    0x88 => 0x2039, # single left-pointing angle quote
    0x89 => 0x203A, # single right-pointing angle quote
    0x8A => 0x2212, # minus sign
    0x8B => 0x2030, # per mille sign
    0x8C => 0x201E, # double low-9 quote
    0x8D => 0x201C, # left double quote
    0x8E => 0x201D, # right double quote
    0x8F => 0x2018, # left single quote
    0x90 => 0x2019, # right single quote
    0x91 => 0x201A, # single low-9 quote
    0x92 => 0x2122, # trademark sign
    0x93 => 0xFB01, # fi ligature
    0x94 => 0xFB02, # fl ligature
    # 0x95 - 0xFF (some match Latin-1, some are different)
    0x95 => 0x0141, 0x96 => 0x0152, 0x97 => 0x0160, 0x98 => 0x0178,
    0x99 => 0x017D, 0x9A => 0x0131, 0x9B => 0x0142, 0x9C => 0x0153,
    0x9D => 0x0161, 0x9E => 0x017E, 0x9F => 0xFFFD, # (undefined)
);

sub _to_utf8 {

    if ( $_[0] =~ s/^\xfe\xff// ) {
        from_to($_[0],'UTF-16be', 'UTF-8');
    } elsif ( $_[0] =~ s/^\xff\xfe// ) {
        from_to($_[0],'UTF-16le', 'UTF-8');
    } else {
        # PDFDocEncoding
        $_[0] =~ s/([\x80-\xFF])/exists($pdfdoc_to_unicode{ord($1)}) ? chr($pdfdoc_to_unicode{ord($1)}) : $1/ge;
        utf8::encode($_[0]);
    }

}


sub debug {
    my $level = shift;
    return if !defined($debug);
    if ( $debug eq $level || $debug eq 'all' ) {
        for (@_) {
            print STDERR (ref($_) ? _dump($_) : $_),"\n";
        }
    }
}

# Minimal pure-Perl structure dumper, used only for debug/error messages so the
# parser carries no dependency on Data::Dumper.  Renders hashes, arrays and
# scalars; refs are sorted by key for stable output.
sub _dump {
    my ($obj, $indent) = @_;
    $indent ||= 0;
    my $pad = '  ' x $indent;
    if ( !defined($obj) ) {
        return 'undef';
    } elsif ( ref($obj) eq 'HASH' ) {
        return "{}" unless %$obj;
        my $inner = '';
        for my $k ( sort keys %$obj ) {
            $inner .= $pad.'  '.$k.' => '._dump($obj->{$k}, $indent+1).",\n";
        }
        return "{\n".$inner.$pad."}";
    } elsif ( ref($obj) eq 'ARRAY' ) {
        return "[ ".join(', ', map { _dump($_, $indent+1) } @$obj)." ]";
    } elsif ( ref($obj) ) {
        return ref($obj);   # other refs (objects, scalars): just the type
    }
    return $obj;
}

=back

=cut

1;
