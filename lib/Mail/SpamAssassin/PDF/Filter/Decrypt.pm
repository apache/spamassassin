package Mail::SpamAssassin::PDF::Filter::Decrypt;
use strict;
use warnings FATAL => 'all';
use Digest::MD5;
use Carp;

# Crypt::RC4, Crypt::Mode::CBC and Digest::SHA are optional dependencies: they
# are only needed to decrypt encrypted PDFs.  Load them lazily so unencrypted
# PDFs (the common case) parse fine without them; new() dies with a clear
# message if an encrypted PDF is encountered but the modules are missing, which
# the parser treats as an undecryptable (protected) document.
use constant HAS_CRYPT_RC4     => eval { require Crypt::RC4;      1 };
use constant HAS_CRYPT_MODE_CBC => eval { require Crypt::Mode::CBC; 1 };
use constant HAS_DIGEST_SHA    => eval { require Digest::SHA;     1 };

=head1 ACKNOWLEDGEMENTS

Portions borrowed from CAM::PDF

=cut

my $padding = pack 'C*',
    0x28, 0xbf, 0x4e, 0x5e,
    0x4e, 0x75, 0x8a, 0x41,
    0x64, 0x00, 0x4e, 0x56,
    0xff, 0xfa, 0x01, 0x08,
    0x2e, 0x2e, 0x00, 0xb6,
    0xd0, 0x68, 0x3e, 0x80,
    0x2f, 0x0c, 0xa9, 0xfe,
    0x64, 0x53, 0x69, 0x7a;

sub new {
    my ($class,$encrypt,$doc_id) = @_;

    my $v = $encrypt->{'/V'} || 0;
    my $length = $encrypt->{'/Length'} || 40;

    unless ( $v == 1 || $v == 2 || $v == 4 || $v == 5 ) {
        die "Encryption algorithm $v not implemented";
    }

    # All supported encryption variants need RC4; V4/V5 (AES) also need
    # Crypt::Mode::CBC, and R5/R6 need Digest::SHA.  Bail out clearly if a
    # required crypto module is missing rather than failing deep in decryption.
    die "Crypt::RC4 module not available\n" unless HAS_CRYPT_RC4;
    if ( $v == 4 || $v == 5 ) {
        die "Crypt::Mode::CBC module not available\n" unless HAS_CRYPT_MODE_CBC;
        die "Digest::SHA module not available\n" unless HAS_DIGEST_SHA;
    }

    # /EncryptMetadata defaults to true when absent
    my $encrypt_metadata = !defined($encrypt->{'/EncryptMetadata'})
        || $encrypt->{'/EncryptMetadata'} eq 'true';

    my $self = bless {
        R               => $encrypt->{'/R'},
        O               => $encrypt->{'/O'},
        U               => $encrypt->{'/U'},
        P               => $encrypt->{'/P'},
        CF              => $encrypt->{'/CF'},
        V               => $v,
        ID              => $doc_id,
        EncryptMetadata => $encrypt_metadata,
        keylength       => ($v == 1 ? 40 : $length),
    }, $class;

    if ( $v == 5 ) {
        $self->{OE} = $encrypt->{'/OE'};
        $self->{UE} = $encrypt->{'/UE'};
    }

    my $password = '';

    if ( !$self->_check_user_password($password) ) {
        # Password-protected: the blank-password check failed.  The caller
        # (Parser::_parse_encrypt) treats an undef return as is_protected, and
        # logs it; no warning here so the parser library stays quiet/SA-agnostic.
        return;
    }

    $self;
}

sub set_current_object {
    my $self = shift;
    $self->{objnum} = shift;
    $self->{gennum} = shift;
}

sub decrypt {
    my ($self,$content) = @_;

    return $content unless defined($content) && length($content);

    my $plaintext = eval {

        if ( $self->{V} == 4 || $self->{V} == 5 ) {
            # todo: Implement Crypt Filters besides the standard one
            if ( $self->{CF}->{'/StdCF'}->{'/CFM'} =~ /AES/ ) {
                my $iv = substr($content,0,16);
                my $m = Crypt::Mode::CBC->new('AES');
                my $key = $self->_compute_key();
                return $m->decrypt(substr($content,16),$key,$iv);
            }
        }
        return Crypt::RC4::RC4($self->_compute_key(), $content);

    };
    if ($@) {
        my $err = $@;
        $err =~ s/\n//g;
        croak "Error decrypting object $self->{objnum} $self->{gennum}: $err";
    };

    return $plaintext;
}

#
# Algorithm 3.6 Authenticating the user password
#
sub _check_user_password {
    my ($self,$pass) = @_;
    my ($key,$hash);

    # step 1  Perform all but the last step of Algorithm 3.4 (Revision 2) or Algorithm 3.5 (Revision 3) using the supplied password string.
    if ( $self->{R} == 2 ) {

        # step 1 Create an encryption key based on the user password string, as described in Algorithm 3.2
        $key = $self->_generate_key($pass);

        # step 2 Encrypt the 32-byte padding string using an RC4 encryption function
        $hash = Crypt::RC4::RC4($key,$padding);

        # If the result of step 1 is equal to the value of the encryption dictionary’s U entry
        # (comparing on the first 16 bytes in the case of Revision 3), the password supplied
        # is the correct user password.
        if ( $hash eq $self->{U} ) {
            # Password is valid. Save key for later
            $self->{code} = $key;
            return 1;
        }

    } elsif ( $self->{R} == 3 || $self->{R} == 4 ) {

        #
        # Algorithm 3.5 Computing the encryption dictionary’s U (user password) value (Revision 3)
        #

        # step 1 Create an encryption key based on the user password string, as described in Algorithm 3.2
        $key = $self->_generate_key($pass);

        # step 2 Initialize the MD5 hash function and pass the 32-byte padding string as input to this function
        my $md5 = Digest::MD5->new();
        $md5->add($padding);

        # step 3 Pass the first element of the file’s file identifier array to the hash function
        # and finish the hash.
        $md5->add($self->{ID}) if defined($self->{ID});
        $hash = $md5->digest();

        # step 4  Encrypt the 16-byte result of the hash, using an RC4 encryption function with the
        # encryption key from step 1
        $hash = Crypt::RC4::RC4($key,$hash);

        # step 5 Do the following 19 times: Take the output from the previous invocation of the
        # RC4 function and pass it as input to a new invocation of the function; use an encryption key generated by
        # taking each byte of the original encryption key (obtained in step 1) and performing an XOR (exclusive or)
        # operation between that byte and the single-byte value of the iteration counter (from 1 to 19).
        my $size = $self->{keylength} >> 3;
        for my $i (1..19) {
            my $xor = chr($i) x $size;
            $hash = Crypt::RC4::RC4($key ^ $xor,$hash);
        }

        # If the result of step 1 is equal to the value of the encryption dictionary’s U entry
        # (comparing on the first 16 bytes in the case of Revision 3), the password supplied
        # is the correct user password.
        if ( $hash eq substr($self->{U},0,16) ) {
            # Password is valid. Save key for later
            $self->{code} = $key;
            return 1;
        }
    } elsif ( $self->{R} == 5 ) {

        # calculate the SHA-256 hash of the password + the User Validation Salt
        my $sha = Digest::SHA->new(256);
        $sha->add($pass);
        $sha->add(substr($self->{U},32,8));
        $hash = $sha->digest();

        # validate password
        if ($hash ne substr($self->{U}, 0, 32)) {
            return 0;
        }

        # calculate the SHA-256 hash of the password + the User Key Salt (the intermediate key)
        $sha->reset();
        $sha->add($pass);
        $sha->add(substr($self->{U},40,8));
        my $temp_key = $sha->digest();

        # decrypt the File Encryption Key using the intermediate key
        my $m = Crypt::Mode::CBC->new('AES', 0);
        my $iv = "\0" x 16;
        $self->{code} = $m->decrypt($self->{UE},$temp_key,$iv);
        return 1;

    } elsif ( $self->{R} == 6 ) {

        # truncate the password to 127 bytes
        $pass = substr($pass,0,127);

        # Test the password against the owner key
        my $owner_validation_salt = substr($self->{O},32,8);
        $hash = $self->_compute_hash(
            $self->{R},
            $pass,
            $owner_validation_salt,
            $self->{U},
        );

        if ($hash eq substr($self->{O}, 0, 32)) {
            # Found the owner password
            # Compute intermediate key
            my $owner_key_salt = substr($self->{O},40,8);
            my $temp_key = $self->_compute_hash(
                $self->{R},
                $pass,
                $owner_key_salt,
                $self->{U}
            );
            # The 32-byte result is the key used to decrypt the 32-byte OE string using AES-256 in CBC mode
            # with no padding and an initialization vector of zero. The 32-byte result is the file encryption key.
            my $m = Crypt::Mode::CBC->new('AES', 0);
            my $iv = "\0" x 16;
            $self->{code} = $m->decrypt($self->{OE},$temp_key,$iv);
            return 1;
        }

        # Test the password against the user key
        my $user_validation_salt = substr($self->{U},32,8);
        $hash = $self->_compute_hash(
            $self->{R},
            $pass,
            $user_validation_salt,
            '',
        );

        if ($hash eq substr($self->{U}, 0, 32)) {
            # Found the user password
            # Compute intermediate key
            my $user_key_salt = substr($self->{U},40,8);
            my $temp_key = $self->_compute_hash(
                $self->{R},
                $pass,
                $user_key_salt,
                ''
            );
            # The 32-byte result is the key used to decrypt the 32-byte UE string using AES-256 in CBC mode
            # with no padding and an initialization vector of zero. The 32-byte result is the file encryption key.
            my $m = Crypt::Mode::CBC->new('AES', 0);
            my $iv = "\0" x 16;
            $self->{code} = $m->decrypt($self->{UE},$temp_key,$iv);
            return 1;
        }

        return 0;

    } else {
        croak "Revision $self->{R} not implemented";
    }

    return 0;
}

#
# Algorithm 2.B: Computing a hash (revision 6 and later)
#
sub _compute_hash {
    my ($self,$R,$pass,$salt,$udata) = @_;

    my $k = Digest::SHA::sha256($pass.$salt.$udata);
    return $k if $R < 6;

    my $round = 0;
    while (1) {
        my $k1 = ($pass . $k . $udata) x 64;
        my $m = Crypt::Mode::CBC->new('AES', 0);
        my $iv = substr($k, 16, 16);
        my $key = substr($k, 0, 16);
        my $e = $m->encrypt($k1, $key, $iv);

        my $first16 = substr($e, 0, 16);
        my $mod = 0;
        foreach my $byte (unpack("C*", $first16)) {
            $mod = ($mod * 256 + $byte) % 3;
        }

        if ($mod == 0) {
            $k = Digest::SHA::sha256($e);
        } elsif ($mod == 1) {
            $k = Digest::SHA::sha384($e);
        } else {  # $mod == 2
            $k = Digest::SHA::sha512($e);
        }

        last if ++$round >= 64 && unpack("C", substr($e, -1, 1)) <= ($round - 32);
    }
    return substr($k, 0, 32);
}

#
# Algorithm 3.2 Computing an encryption key
#
sub _generate_key {
    my ($self,$pass) = @_;

    # step 1 Pad or truncate the password string to exactly 32 bytes
    $pass = substr($pass.$padding,0,32);

    # step 2 Initialize the MD5 hash function and pass the result of step 1 as input
    my $md5 = Digest::MD5->new;
    $md5->add($pass);

    # step 3 Pass the value of the encryption dictionary’s O entry to the MD5 hash function
    $md5->add($self->{'O'});

    # step 4 Treat the value of the P entry as an unsigned 4-byte integer and pass these bytes to
    # the MD5 hash function, low-order byte first.
    $md5->add(pack('V',$self->{'P'}+0));

    # step 5 Pass the first element of the file’s file identifier array
    $md5->add($self->{ID}) if defined($self->{ID});

    # step 6 (Revision 4 or greater) If document metadata is not being encrypted, pass 4 bytes with
    # the value 0xFFFFFFFF to the MD5 hash function
    $md5->add(pack('V',0xFFFFFFFF)) if $self->{R} >= 4 && !$self->{EncryptMetadata};

    # step 7 Finish the hash
    my $hash = $md5->digest();

    # step 8 (Revision 3 only) Do the following 50 times: Take the output from the previous
    # MD5 hash and pass it as input into a new MD5 hash.
    if ( $self->{R} >= 3 ) {
        $hash = Digest::MD5::md5($hash) for (1..50);
    }

    # step 9 Set the encryption key to the first n bytes of the output from the final MD5 hash,
    substr($hash,0,$self->{keylength} >> 3)

}

sub _compute_key {
    my ($self) = @_;

    my $method = $self->{CF}->{'/StdCF'}->{'/CFM'} // '';
    if ($method eq '/AESV3') {
        return $self->{code};
    }

    my $id = $self->{objnum} . '_' .$self->{gennum};
    if (!exists $self->{keycache}->{$id}) {
        my $objstr = pack('V', $self->{objnum});
        my $genstr = pack('V', $self->{gennum});

        my $md5 = Digest::MD5->new();
        $md5->add($self->{code});
        $md5->add(substr($objstr, 0, 3).substr($genstr, 0, 2));
        if ( $self->{V} == 4  || $self->{V} == 5 ) {
            $md5->add('sAlT') if $method eq '/AESV2';
        }
        my $hash = $md5->digest();

        my $size = ($self->{keylength} >> 3) + 5;
        $size = 16 if ($size > 16);
        $self->{keycache}->{$id} = substr($hash, 0, $size);
    }
    return $self->{keycache}->{$id};
}

sub _hex {
    my $val = shift;
    return join q{}, map {sprintf '%08x', $_} unpack 'N*', $val;
}

1;
