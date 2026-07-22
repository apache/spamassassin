#!/usr/bin/perl
#
# Parser integration test for Mail::SpamAssassin::PDF::Parser, using synthetic
# fixtures under t/data/pdf/ that exercise every implemented parser code path
# without shipping any real-world (sensitive) PDFs.
#
# Coverage by fixture:
#   sample / rc4_40 / rc4_128 / aesv2 / aesv3 / aesv2_cleartext_meta
#                       - encryption variants (RC4 V1/R2, V2/R3; AES V4/R4, V5/R6;
#                         EncryptMetadata=false), all decrypted with a blank password
#   protected           - non-blank password => Protected=1, all metrics zeroed
#   multipage           - multi-page tree; page-1-only metrics
#   ascii85 / lzw       - ASCII85Decode / LZWDecode content-stream filters
#   inline_image        - BI/ID/EI inline images, colour vs 1-bpc grayscale
#   indirect_mediabox   - indirect /MediaBox reference + XObject image
#   mailto              - mailto: URI and schemeless-URI normalisation
#   openaction_js       - /OpenAction dict + /JavaScript action flags
#   sample              - indirect /URI reference (13 0 R) regression guard

use strict;
use warnings;
# Normalise the working directory so fixtures (data/pdf/*) and lib paths resolve
# whether the test is run from the repo root (make test / prove t/foo.t) or from
# t/.  Mirrors SATest's "(-f t/test_dir) && chdir t".
BEGIN { chdir 't' if -d 't' && -f 't/test_dir'; }
use lib '../blib/lib';
use Test::More;
use Mail::SpamAssassin::PDF::Parser;
use Mail::SpamAssassin::PDF::Context::Info;

my @tests = (
    {
        filename => 'data/pdf/sample.pdf',
        expected => {
            'ClickArea' => 852, 'ClickRatio' => '0.18',
            'CreationDate' => 'D:20260624044120Z00\'00\'', 'Creator' => 'Pages',
            'Encrypted' => 0, 'ImageArea' => 0, 'ImageCount' => 0,
            'ImageRatio' => '0.00', 'JavaScript' => 0, 'LinkCount' => 1,
            'ModDate' => 'D:20260624044120Z00\'00\'', 'OpenAction' => 0,
            'PageArea' => 484704, 'PageCount' => 1,
            'Producer' => 'macOS Version 15.3.1 (Build 24D70) Quartz PDFContext',
            'Protected' => 0, 'Title' => 'sample', 'Version' => '1.3',
            'uris' => { 'http://www.google.com' => 1 },
        }
    },
    {
        filename => 'data/pdf/rc4_40.pdf',
        requires => ['Crypt::RC4'],
        expected => {
            'ClickArea' => 852, 'ClickRatio' => '0.18',
            'CreationDate' => 'D:20260624044120Z00\'00\'', 'Creator' => 'Pages',
            'Encrypted' => 1, 'ImageArea' => 0, 'ImageCount' => 0,
            'ImageRatio' => '0.00', 'JavaScript' => 0, 'LinkCount' => 1,
            'ModDate' => 'D:20260624044120Z00\'00\'', 'OpenAction' => 0,
            'PageArea' => 484704, 'PageCount' => 1,
            'Producer' => 'macOS Version 15.3.1 (Build 24D70) Quartz PDFContext',
            'Protected' => 0, 'Title' => 'sample', 'Version' => '1.3',
            'uris' => { 'http://www.google.com' => 1 },
        }
    },
    {
        filename => 'data/pdf/rc4_128.pdf',
        requires => ['Crypt::RC4'],
        expected => {
            'ClickArea' => 852, 'ClickRatio' => '0.18',
            'CreationDate' => 'D:20260624044120Z00\'00\'', 'Creator' => 'Pages',
            'Encrypted' => 1, 'ImageArea' => 0, 'ImageCount' => 0,
            'ImageRatio' => '0.00', 'JavaScript' => 0, 'LinkCount' => 1,
            'ModDate' => 'D:20260624044120Z00\'00\'', 'OpenAction' => 0,
            'PageArea' => 484704, 'PageCount' => 1,
            'Producer' => 'macOS Version 15.3.1 (Build 24D70) Quartz PDFContext',
            'Protected' => 0, 'Title' => 'sample', 'Version' => '1.4',
            'uris' => { 'http://www.google.com' => 1 },
        }
    },
    {
        filename => 'data/pdf/aesv2.pdf',
        requires => ['Crypt::RC4', 'Crypt::Mode::CBC', 'Digest::SHA'],
        expected => {
            'ClickArea' => 852, 'ClickRatio' => '0.18',
            'CreationDate' => 'D:20260624044120Z00\'00\'', 'Creator' => 'Pages',
            'Encrypted' => 1, 'ImageArea' => 0, 'ImageCount' => 0,
            'ImageRatio' => '0.00', 'JavaScript' => 0, 'LinkCount' => 1,
            'ModDate' => 'D:20260624044120Z00\'00\'', 'OpenAction' => 0,
            'PageArea' => 484704, 'PageCount' => 1,
            'Producer' => 'macOS Version 15.3.1 (Build 24D70) Quartz PDFContext',
            'Protected' => 0, 'Title' => 'sample', 'Version' => '1.6',
            'uris' => { 'http://www.google.com' => 1 },
        }
    },
    {
        filename => 'data/pdf/aesv3.pdf',
        requires => ['Crypt::RC4', 'Crypt::Mode::CBC', 'Digest::SHA'],
        expected => {
            'ClickArea' => 852, 'ClickRatio' => '0.18',
            'CreationDate' => 'D:20260624044120Z00\'00\'', 'Creator' => 'Pages',
            'Encrypted' => 1, 'ImageArea' => 0, 'ImageCount' => 0,
            'ImageRatio' => '0.00', 'JavaScript' => 0, 'LinkCount' => 1,
            'ModDate' => 'D:20260624044120Z00\'00\'', 'OpenAction' => 0,
            'PageArea' => 484704, 'PageCount' => 1,
            'Producer' => 'macOS Version 15.3.1 (Build 24D70) Quartz PDFContext',
            'Protected' => 0, 'Title' => 'sample', 'Version' => '1.7',
            'uris' => { 'http://www.google.com' => 1 },
        }
    },
    {
        filename => 'data/pdf/aesv2_cleartext_meta.pdf',
        requires => ['Crypt::RC4', 'Crypt::Mode::CBC', 'Digest::SHA'],
        expected => {
            'ClickArea' => 852, 'ClickRatio' => '0.18',
            'CreationDate' => 'D:20260624044120Z00\'00\'', 'Creator' => 'Pages',
            'Encrypted' => 1, 'ImageArea' => 0, 'ImageCount' => 0,
            'ImageRatio' => '0.00', 'JavaScript' => 0, 'LinkCount' => 1,
            'ModDate' => 'D:20260624044120Z00\'00\'', 'OpenAction' => 0,
            'PageArea' => 484704, 'PageCount' => 1,
            'Producer' => 'macOS Version 15.3.1 (Build 24D70) Quartz PDFContext',
            'Protected' => 0, 'Title' => 'sample', 'Version' => '1.6',
            'uris' => { 'http://www.google.com' => 1 },
        }
    },
    {
        filename => 'data/pdf/protected.pdf',
        requires => ['Crypt::RC4', 'Crypt::Mode::CBC', 'Digest::SHA'],
        expected => {
            'ClickArea' => 0, 'Encrypted' => 1,
            'ImageArea' => 0, 'ImageCount' => 0, 'JavaScript' => 0,
            'LinkCount' => 0, 'OpenAction' => 0, 'PageArea' => 0,
            'PageCount' => 0, 'Protected' => 1, 'Version' => '1.7',
            'uris' => {},
        }
    },
    {
        filename => 'data/pdf/multipage.pdf',
        expected => {
            'ClickArea' => 852, 'ClickRatio' => '0.18',
            'Encrypted' => 0, 'ImageArea' => 0, 'ImageCount' => 0,
            'ImageRatio' => '0.00', 'JavaScript' => 0, 'LinkCount' => 1,
            'OpenAction' => 0, 'PageArea' => 484704, 'PageCount' => 2,
            'Protected' => 0, 'Version' => '1.3',
            'uris' => { 'http://www.google.com' => 1 },
        }
    },
    {
        filename => 'data/pdf/ascii85.pdf',
        requires => ['Convert::Ascii85'],
        expected => {
            'ClickArea' => 0, 'ClickRatio' => '0.00',
            'Encrypted' => 0, 'ImageArea' => 20000, 'ImageCount' => 1,
            'ImageRatio' => '4.13', 'JavaScript' => 0, 'LinkCount' => 0,
            'OpenAction' => 0, 'PageArea' => 484704, 'PageCount' => 1,
            'Producer' => 'Synthetic Test Suite', 'Protected' => 0,
            'Title' => 'ASCII85', 'Version' => '1.4', 'uris' => {},
        }
    },
    {
        filename => 'data/pdf/lzw.pdf',
        expected => {
            'ClickArea' => 0, 'ClickRatio' => '0.00',
            'Encrypted' => 0, 'ImageArea' => 20000, 'ImageCount' => 1,
            'ImageRatio' => '4.13', 'JavaScript' => 0, 'LinkCount' => 0,
            'OpenAction' => 0, 'PageArea' => 484704, 'PageCount' => 1,
            'Producer' => 'Synthetic Test Suite', 'Protected' => 0,
            'Title' => 'LZW', 'Version' => '1.4', 'uris' => {},
        }
    },
    {
        filename => 'data/pdf/inline_image.pdf',
        expected => {
            'ClickArea' => 0, 'ClickRatio' => '0.00',
            'Encrypted' => 0, 'ImageArea' => 20000, 'ImageCount' => 2,
            'ImageRatio' => '4.13', 'JavaScript' => 0, 'LinkCount' => 0,
            'OpenAction' => 0, 'PageArea' => 484704, 'PageCount' => 1,
            'Producer' => 'Synthetic Test Suite', 'Protected' => 0,
            'Title' => 'InlineImages', 'Version' => '1.3', 'uris' => {},
        }
    },
    {
        filename => 'data/pdf/indirect_mediabox.pdf',
        expected => {
            'ClickArea' => 0, 'ClickRatio' => '0.00',
            'Creator' => 'Crystal Reports', 'Encrypted' => 0,
            'ImageArea' => 20000, 'ImageCount' => 1, 'ImageRatio' => '4.13',
            'JavaScript' => 0, 'LinkCount' => 0, 'OpenAction' => 0,
            'PageArea' => 484704, 'PageCount' => 1,
            'Producer' => 'Synthetic Test Suite', 'Protected' => 0,
            'Version' => '1.7', 'uris' => {},
        }
    },
    {
        filename => 'data/pdf/mailto.pdf',
        expected => {
            'ClickArea' => 5120, 'ClickRatio' => '1.06',
            'Encrypted' => 0, 'ImageArea' => 0, 'ImageCount' => 0,
            'ImageRatio' => '0.00', 'JavaScript' => 0, 'LinkCount' => 2,
            'OpenAction' => 0, 'PageArea' => 484704, 'PageCount' => 1,
            'Producer' => 'Synthetic Test Suite', 'Protected' => 0,
            'Version' => '1.4',
            'uris' => {
                'http://example.test/path'    => 1,
                'mailto:support@example.test' => 1,
            },
        }
    },
    {
        filename => 'data/pdf/openaction_js.pdf',
        expected => {
            'ClickArea' => 0, 'ClickRatio' => '0.00',
            'Encrypted' => 0, 'ImageArea' => 0, 'ImageCount' => 0,
            'ImageRatio' => '0.00', 'JavaScript' => 1, 'LinkCount' => 0,
            'OpenAction' => 1, 'PageArea' => 484704, 'PageCount' => 1,
            'Producer' => 'Synthetic Test Suite', 'Protected' => 0,
            'Title' => 'OpenAction', 'Version' => '1.4', 'uris' => {},
        }
    },
);

plan tests => scalar(@tests);

for my $test (@tests) {

    # Some fixtures need optional CPAN modules to parse (encryption / ASCII85).
    # Skip such fixtures on a minimal install rather than emitting confusing diffs.
    if (my $missing = missing_modules($test->{requires})) {
      SKIP: {
            skip "$test->{filename}: requires $missing", 1;
        }
        next;
    }

    my $context = Mail::SpamAssassin::PDF::Context::Info->new();
    my $pdf = Mail::SpamAssassin::PDF::Parser->new( context => $context );

    my $data = get_file_contents($test->{filename});
    my $ok = eval { $pdf->parse(\$data); 1 };

    if (!$ok) {
        my $err = $@;
        $err =~ s/\s+\z// if defined $err;
        fail($test->{filename});
        diag("parse() died: $err");
        next;
    }

    my $info = $context->get_info();

    is_deeply $info, $test->{expected}, $test->{filename};
}

# Return a comma-joined list of the modules in $required that cannot be loaded,
# or undef if all are available (or none are required).
sub missing_modules {
    my $required = shift;
    return undef unless $required && @$required;
    my @missing = grep {
        my $mod = $_;
        !eval { (my $file = "$mod.pm") =~ s{::}{/}g; require $file; 1 };
    } @$required;
    return @missing ? join(', ', @missing) : undef;
}

sub get_file_contents {
    my $file = shift;
    open my $fh, '<', $file or die "Can't open $file: $!";
    binmode $fh;
    local $/ = undef;
    my $data = <$fh>;
    close $fh;
    return $data;
}
