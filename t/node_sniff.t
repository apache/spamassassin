#!/usr/bin/perl -T

use lib '.';
use lib 't';
use SATest;
sa_t_init("node_sniff");

use strict;

use Test::More;
use Mail::SpamAssassin;
use Mail::SpamAssassin::Util;
use MIME::Base64;

# Signature recognition, tested directly against
# Mail::SpamAssassin::Util::content_type_from_magic.  Every case is built
# inline: a handful of bytes is enough to stand in for each format, so no
# binary fixtures are needed.
my @magic = (
  # --- archives ---
  [ "Rar!\x1a\x07\x00" . "\0" x 16,           'application/vnd.rar',         'rar v4' ],
  [ "Rar!\x1a\x07\x01\x00" . "\0" x 16,       'application/vnd.rar',         'rar v5' ],
  [ "PK\x03\x04" . "\0" x 16,                 'application/zip',             'zip local header' ],
  [ "PK\x05\x06" . "\0" x 16,                 'application/zip',             'zip empty archive' ],
  [ "7z\xbc\xaf\x27\x1c" . "\0" x 16,         'application/x-7z-compressed', '7z' ],
  [ "\x1f\x8b\x08" . "\0" x 16,               'application/gzip',            'gzip' ],
  [ "BZh9" . "\0" x 16,                       'application/x-bzip2',         'bzip2' ],

  # --- images ---
  [ "\xff\xd8\xff\xe0" . "\0" x 16,           'image/jpeg',                  'jpeg' ],
  [ "\x89PNG\x0d\x0a\x1a\x0a" . "\0" x 16,    'image/png',                   'png' ],
  [ "GIF87a" . "\0" x 16,                     'image/gif',                   'gif87a' ],
  [ "GIF89a" . "\0" x 16,                     'image/gif',                   'gif89a' ],
  [ "II\x2a\x00" . "\0" x 16,                 'image/tiff',                  'tiff little-endian' ],
  [ "MM\x00\x2a" . "\0" x 16,                 'image/tiff',                  'tiff big-endian' ],
  [ "RIFF\0\0\0\0WEBPVP8 " . "\0" x 16,       'image/webp',                  'webp' ],
  [ "BM" . pack('V v v V V', 70, 0, 0, 54, 40) . "\0" x 40,
                                              'image/bmp',                   'bmp (BITMAPINFOHEADER)' ],
  [ "BM" . pack('V v v V V', 70, 0, 0, 26, 12) . "\0" x 40,
                                              'image/bmp',                   'bmp (BITMAPCOREHEADER)' ],
  [ "\0\0\0\x18ftypheic" . "\0" x 16,         'image/heic',                  'heic' ],
  [ "\0\0\0\x18ftypmif1" . "\0" x 16,         'image/heif',                  'heif' ],

  # --- documents ---
  [ "%PDF-1.7\n" . "\0" x 16,                 'application/pdf',             'pdf at offset 0' ],
  [ ("\n" x 100) . "%PDF-1.4\n" . "\0" x 16,  'application/pdf',             'pdf behind leading junk' ],

  # --- tar: magic at 257, plus the version bytes ---
  [ _tar("ustar\x0000"),                      'application/x-tar',           'posix tar' ],
  [ _tar("ustar\x20\x20\x00"),                'application/x-tar',           'gnu tar' ],

  # --- negatives: these must NOT be identified ---
  # Other ISO-BMFF brands share the 'ftyp' box but are not still images, and
  # there is no type for them that any handler could use.
  [ "\0\0\0\x18ftypisom" . "\0" x 16,         undef, 'mp4 is not an image' ],
  [ "\0\0\0\x18ftypqt  " . "\0" x 16,         undef, 'quicktime is not an image' ],
  [ "\0\0\0\x18ftypavif" . "\0" x 16,         undef, 'avif has no handler type' ],
  # BMP needs more than its two ASCII bytes to be believed: zero reserved
  # words, a small pixel-data offset and a known DIB header size.
  [ "BMW dealership special offer today",      undef, 'text starting BM is not an image' ],
  [ "BM" . "\0" x 40,                         undef, 'bare BM with an empty header is not a bmp' ],
  [ "BM" . pack('V v v V V', 999999, 7, 3, 999, 99) . "\0" x 40,
                                              undef, 'bmp with bad reserved/DIB fields' ],
  # "ustar" only counts at offset 257 with valid version bytes after it.
  [ ("x" x 257) . "ustar text here",          undef, 'the word ustar is not a tar' ],
  [ ("x" x 257) . "ustarXX00",                undef, 'bad tar version bytes' ],
  [ "\0" x 300,                               undef, 'nul padding is not a tar' ],
  # Ordinary content must sniff to nothing at all, or body rules would lose it.
  [ "Hello, this is an ordinary email body.\n", undef, 'plain text' ],
  [ "<html><body>Hi there</body></html>\n",   undef, 'html' ],
  [ "short",                                  undef, 'below minimum length' ],
  [ "",                                       undef, 'empty string' ],
);

# effective_type() itself: the gating lives there, not in the signature table.
# These parse a whole message so the real code path is exercised.
my $ZIP  = "PK\x03\x04" . "\0" x 60;
my $RAR  = "Rar!\x1a\x07\x01\x00" . "\0" x 60;
my $HTML = qq{<html><body><a href="https://phish.example/">x</a></body></html>\n};

# ".xyz" stands in for any extension %file_type_map doesn't list.  Don't map
# it, or the unknown-extension cases below quietly start testing the map.
my @parts = (
  # The motivating sample, reduced: a RAR named .bz2.
  [ 'application/x-bzip2', 'payload.bz2', $RAR, 'application/vnd.rar',
    'rar named .bz2' ],
  # A known binary label is still overruled by the bytes.
  [ 'application/octet-stream', 'photo.jpg', $ZIP, 'application/zip',
    'zip named .jpg declared octet-stream' ],
  # ...unless the label is a kind of what the bytes are: an OOXML or ODF
  # document is a zip, so it keeps its document type, by extension or by
  # declared type, and stays away from the archive handler.
  [ 'application/octet-stream', 'report.docx', $ZIP,
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'zip magic under a .docx label keeps the docx type' ],
  [ 'application/vnd.oasis.opendocument.text', undef, $ZIP,
    'application/vnd.oasis.opendocument.text',
    'zip magic under a declared odt type keeps the odt type' ],
  # Office opens an OOXML document saved under the legacy extension.
  [ 'application/vnd.ms-excel', 'report.xls', $ZIP, 'application/vnd.ms-excel',
    'zip magic under a .xls label keeps the xls type' ],
  # A .jar is not treated as compatible: archive tools such as WinRAR register
  # .jar, so a plain zip renamed .jar opens as an archive on a machine without
  # Java.  Real malware ships a .js that way; it must reach the archive handler.
  [ 'application/java-archive', 'invoice.jar', $ZIP, 'application/zip',
    'zip under a .jar label is sniffed as a zip' ],
  # A compatible label only covers its own container: RAR bytes are not a docx.
  [ 'application/octet-stream', 'report.docx', $RAR, 'application/vnd.rar',
    'rar magic under a .docx label is still sniffed' ],

  # A text label is never overruled: the recipient's mail client or browser
  # renders it as text whatever it starts with, so a magic number ahead of a
  # phishing page must not take it away from the HTML handler.
  [ 'text/html', 'invoice.hta', "GIF89a$HTML", 'text/html',
    'magic ahead of html, known extension: stays text/html' ],
  [ 'text/html', undef, "GIF89a$HTML", 'text/html',
    'magic ahead of html, no filename: stays text/html' ],
  # ...including a declared text/plain part with no name.  The recipient's
  # client shows it as text; it cannot be opened as the archive it holds.
  [ 'text/plain', undef, $ZIP, 'text/plain',
    'zip declared text/plain with no filename stays text/plain' ],

  # An unknown extension carries no label, so the bytes decide whatever the
  # declared type says.  This is why every extension a browser or mshta
  # renders has to be in %file_type_map.
  [ 'text/html', 'invoice.xyz', "GIF89a$HTML", 'image/gif',
    'magic ahead of html, unknown extension: sniffed' ],
  [ 'text/plain', 'invoice.xyz', $RAR, 'application/vnd.rar',
    'rar declared text/plain, unknown extension: sniffed' ],
  [ 'application/octet-stream', 'invoice.xyz',
    ("\n" x 50) . "%PDF-1.4\n" . ("P" x 200), 'application/pdf',
    'pdf behind junk, unknown extension: sniffed' ],
  # When the bytes say nothing, it falls back to the declared type rather
  # than octet-stream.
  [ 'text/html', 'invoice.xyz', $HTML, 'text/html',
    'html, unknown extension, no magic: keeps its declared type' ],

  # Ordinary parts must be left exactly as they are.
  [ 'text/plain', undef, "Just a normal message body.\n", 'text/plain',
    'plain text part is unchanged' ],
  [ 'text/html', undef, "<html><body>hi</body></html>\n", 'text/html',
    'html part is unchanged' ],
  [ 'application/octet-stream', 'real.pdf', "%PDF-1.7\n" . ("P" x 200),
    'application/pdf', 'named pdf attachment' ],
);

# message/rfc822 is checked separately: it is a container, so the leaves-only
# find_parts() above would return the subparsed child rather than the part
# under test.  No signature yields a message/* type, and demoting one would
# take its whole subtree out of reach of every rule, so it is never sniffed --
# and the subparse that produces that subtree must still happen.
my @rfc822 = (
  'message/rfc822', undef, "From: a\@example.com\nSubject: x\n\nbody\n",
);

plan tests => scalar(@magic) + 1 + scalar(@parts) + 2;

for my $c (@magic) {
  my ($data, $want, $desc) = @$c;
  is(Mail::SpamAssassin::Util::content_type_from_magic(\$data), $want, $desc);
}
is(Mail::SpamAssassin::Util::content_type_from_magic(undef), undef,
   'undef reference');

my $sa = Mail::SpamAssassin->new({
    rules_filename      => $localrules,
    site_rules_filename => $siterules,
    userprefs_filename  => $userrules,
    local_tests_only    => 1,
    debug               => 0,
    dont_copy_prefs     => 1,
});

for my $c (@parts) {
  my ($type, $name, $body, $want, $desc) = @$c;
  my $msg  = _message($type, $name, $body);
  my $mail = $sa->parse(\$msg, 1);
  my ($part) = $mail->find_parts(qr/./, 1);
  is($part && $part->effective_type(), $want, $desc);
  $mail->finish();
}

{
  my $msg  = _message(@rfc822);
  my $mail = $sa->parse(\$msg, 1);
  my ($container) = $mail->find_parts(qr/./, 0);
  is($container && $container->effective_type(), 'message/rfc822',
     'message/rfc822 container is left alone');
  is(join(',', $mail->content_summary()), 'message/rfc822,text/plain',
     'message/rfc822 is still subparsed into its child');
  $mail->finish();
}

# A 512-byte tar header block: a NUL-terminated name, then the magic and
# version fields at offset 257.
sub _tar {
  my ($magic) = @_;
  my $h = "\0" x 512;
  substr($h, 0, 9)     = "test.txt\0";
  substr($h, 257, length $magic) = $magic;
  return $h;
}

# A single-part message carrying $body as a base64 attachment.
sub _message {
  my ($type, $name, $body) = @_;
  my $ct = $type;
  $ct .= qq{; name="$name"}  if defined $name;
  my $disp = defined $name ? qq{Content-Disposition: attachment; filename="$name"\n} : '';
  return "From: sender\@example.com\n"
       . "To: recipient\@example.com\n"
       . "Subject: test\n"
       . "MIME-Version: 1.0\n"
       . "Content-Type: $ct\n"
       . $disp
       . "Content-Transfer-Encoding: base64\n"
       . "\n"
       . encode_base64($body);
}
