#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("handler_archive");

use Test::More;

# ---------------------------------------------------------------------------
# End-to-end test of Mail::SpamAssassin::Handler::Archive.
#
# The handler opens zip / rar attachments and returns each inner file as a
# sub-part, which the framework re-dispatches by filename extension.  So an
# inner *.js reaches the JavaScript handler and an inner *.html is rendered into
# the body.  (Note: a plain *.txt member is deliberately NOT surfaced as body
# text -- only text/plain, text/html and message/* parts feed body rules, and
# .txt is not in the file-type map -- so the fixtures use *.js and *.html.)
#
# We confirm:
#   * an inner *.js member reaches the JavaScript handler ('script' rule);
#   * an inner *.html member is rendered into the body;
#   * the same works when the zip is mislabelled application/octet-stream but
#     named *.zip (Message::Node::effective_type maps it back);
#   * archive_max_files caps how many members are extracted;
#   * rar archives behave the same (only when 'unrar' is installed).
#
# Each fixture under data/nice/ is an ordinary MIME message (100% ASCII) whose
# attachment is a small zip/rar containing inner.js (sentinel INNERJS) and
# inner.html (sentinel INNERHTML), base64-encoded.  The zip uses pure-Perl
# extraction so those cases run everywhere; the rar case needs the 'unrar'
# binary and is skipped cleanly when it is absent.

# Locate unrar the way handler_pdf.t locates pdftotext: SATest scrubs PATH to a
# hermetic default, so also probe a few common install locations.
sub find_bin {
  my ($exe) = @_;
  for my $dir (split(/:/, $ENV{PATH}),
               qw(/usr/bin /usr/local/bin /opt/homebrew/bin /opt/local/bin)) {
    my $cand = "$dir/$exe";
    return $cand if -x $cand;
  }
  return undef;
}
my $unrar = find_bin('unrar');

# 7 zip assertions, +3 octet-stream, +2 max-files, +4 rar (only actually run when unrar present)
plan tests => 7 + 3 + 2 + 4;

tstpre ("
  loadhandler Mail::SpamAssassin::Handler::Archive
  loadhandler Mail::SpamAssassin::Handler::HTML
  loadhandler Mail::SpamAssassin::Handler::JavaScript
" . (defined $unrar ? "  archive_unrar_path $unrar\n" : ""));

tstlocalrules ('
  script ARC_JS         /INNERJS/
  score  ARC_JS         1.0
  describe ARC_JS       an inner .js file reached the JavaScript handler

  body   ARC_HTML       /INNERHTML/
  score  ARC_HTML       1.0
  describe ARC_HTML     an inner .html file reached the HTML renderer

  body   ARC_ORIG       /ORIGINAL_BODY_MARKER/
  score  ARC_ORIG       1.0
  describe ARC_ORIG     original outer body preserved

  body   ARC_COUNT2     eval:check_archive_file_count(2)
  score  ARC_COUNT2     1.0
  describe ARC_COUNT2   archive declares at least 2 files

  body   ARC_COUNT5     eval:check_archive_file_count(5)
  score  ARC_COUNT5     1.0
  describe ARC_COUNT5   archive declares at least 5 files (should NOT fire)
');

# --- zip (real application/zip) ---------------------------------------------
%patterns = (
  ' 1.0 ARC_JS ',     'zip_js_member',
  ' 1.0 ARC_HTML ',   'zip_html_member',
  ' 1.0 ARC_ORIG ',   'original_body_preserved',
  ' 1.0 ARC_COUNT2 ', 'zip_file_count_at_least_2',
);
%anti_patterns = (
  'ARC_COUNT5 ', 'zip_file_count_not_5',  # zip has only 2 entries
);
ok (sarun ("-L -t < data/nice/handler_archive_zip", \&patterns_run_cb));
ok_all_patterns();

# --- same zip mislabelled application/octet-stream but named *.zip -----------
%patterns = (
  ' 1.0 ARC_JS ',   'octet_js_member',
  ' 1.0 ARC_HTML ', 'octet_html_member',
);
%anti_patterns = ();
ok (sarun ("-L -t < data/nice/handler_archive_octet", \&patterns_run_cb));
ok_all_patterns();

# --- archive_max_files cap (extract only the first member) ------------------
# inner.js is first in the zip, so with archive_max_files 1 only ARC_JS fires;
# the inner.html member must NOT be extracted, so ARC_HTML must NOT fire.
{
  local %patterns = (
    ' 1.0 ARC_JS ', 'maxfiles_first_member',
  );
  local %anti_patterns = (
    'ARC_HTML ', 'maxfiles_second_member_skipped',
  );
  ok (sarun ("-L -t --cf='archive_max_files 1' < data/nice/handler_archive_zip",
             \&patterns_run_cb));
  ok_all_patterns();
}

# --- rar (only when unrar is available) -------------------------------------
SKIP: {
  skip("unrar not installed", 4) unless $unrar;

  %patterns = (
    ' 1.0 ARC_JS ',     'rar_js_member',
    ' 1.0 ARC_HTML ',   'rar_html_member',
    ' 1.0 ARC_COUNT2 ', 'rar_file_count_at_least_2',  # count via unrar member list
  );
  %anti_patterns = ();
  ok (sarun ("-L -t < data/nice/handler_archive_rar", \&patterns_run_cb));
  ok_all_patterns();
}
