#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("handler_ics");

use Test::More;

# ---------------------------------------------------------------------------
# End-to-end test of Mail::SpamAssassin::Handler::ICS.
#
# handler_ics attaches the same invite twice -- once inline as text/calendar and
# once as a base64 application/ics file (as Google Calendar does) -- carrying a
# docusign phishing lure in the event SUMMARY/DESCRIPTION, phishing links in
# URL/LOCATION, two ATTENDEE properties, and a DTSTART with non-zero seconds.  We
# confirm:
#   * icstext rules match the event text (and only the ICS, not the plain body);
#   * a plain body rule matches the event text too -- the handler renders it into
#     the body via set_rendered (SA otherwise skips text/calendar for bug 4843);
#   * check_ics_attendee_count() sees exactly two attendees -- the duplicate copy
#     is deduped by UID, so the count is 2 and not 4;
#   * check_ics_random_start_time() fires on the odd (non-zero seconds) DTSTART;
#   * URIs from the invite reach the URI detail list under type 'ics';
#   * the original text/plain body is preserved.
#
# A second message (handler_ics_html) checks that a link hidden in an HTML-typed
# property (X-ALT-DESC;FMTTYPE=text/html) -- with no plain URL: property -- reaches
# the URI detail list: the ICS handler hands the HTML to the HTML handler as a
# child part, and that synthetic part's links are harvested.
#
# The handler is pure Perl (no external binary), so this test runs everywhere.

plan tests => 15;

tstpre ("
  loadhandler Mail::SpamAssassin::Handler::ICS
  loadhandler Mail::SpamAssassin::Handler::HTML
");

tstlocalrules ('
  icstext ICS_SENTINEL   /ICSSENTINEL/
  score   ICS_SENTINEL   1.0
  describe ICS_SENTINEL  ICS event text reached the ICS handler

  icstext ICS_SUSP       /\b(docusign|secure link)\b/i
  score   ICS_SUSP       1.0
  describe ICS_SUSP      suspicious phishing terms in ICS event text

  body    ICS_ATTENDEES  eval:check_ics_attendee_count(\'2\',\'2\')
  score   ICS_ATTENDEES  1.0
  describe ICS_ATTENDEES invite has exactly two attendees (duplicate deduped by UID)

  body    ICS_DTSEC      eval:check_ics_random_start_time()
  score   ICS_DTSEC      1.0
  describe ICS_DTSEC     DTSTART has a non-zero seconds component

  uri-detail ICS_LINK    type =~ /^ics$/  raw =~ /phish\.example/
  score   ICS_LINK       1.0
  describe ICS_LINK      a link inside the invite reached the URI list

  body    ICS_ORIG       /ORIGINAL_BODY_MARKER/
  score   ICS_ORIG       1.0
  describe ICS_ORIG      original body preserved

  body    ICS_RENDERED   /confirm your docusign invoice/
  score   ICS_RENDERED   1.0
  describe ICS_RENDERED  event text rendered into the body via set_rendered

  body    ICS_INLINE_IMG eval:check_ics_event_prop(\'ATTACH\',\'ENCODING=BASE64\')
  score   ICS_INLINE_IMG 1.0
  describe ICS_INLINE_IMG invite carries an inline base64 attachment

  body    ICS_ATTACH_DELIM eval:check_ics_event_prop(\'ATTACH\',\'/ENCODING=BASE64/\')
  score   ICS_ATTACH_DELIM 1.0
  describe ICS_ATTACH_DELIM delimited regex form matches (delimiters stripped)

  uri-detail ICS_HTML_URI  raw =~ /hidden-in-html/
  score   ICS_HTML_URI     1.0
  describe ICS_HTML_URI    a link hidden in an HTML property reached the URI list

  body    ICS_HTML_TEXT    /ICSHTMLBODY/
  score   ICS_HTML_TEXT    1.0
  describe ICS_HTML_TEXT   the HTML property visible text was rendered into the body

  body    ICS_HTML_RAWTAG  /<p>/
  score   ICS_HTML_RAWTAG  1.0
  describe ICS_HTML_RAWTAG raw HTML markup leaked into body rules (should NOT fire)

  icstext ICS_HTML_ICSTEXT /ICSHTMLBODY/
  score   ICS_HTML_ICSTEXT 1.0
  describe ICS_HTML_ICSTEXT HTML property rendered text is visible to icstext rules
');

%patterns = (
  ' 1.0 ICS_SENTINEL ',  'ics_text',
  ' 1.0 ICS_SUSP ',      'ics_suspicious_text',
  ' 1.0 ICS_ATTENDEES ', 'ics_attendee_count',
  ' 1.0 ICS_DTSEC ',     'ics_dtstart_nonzero_seconds',
  ' 1.0 ICS_LINK ',      'ics_uri_detail',
  ' 1.0 ICS_ORIG ',      'original_body_preserved',
  ' 1.0 ICS_RENDERED ',  'ics_rendered_into_body',
  ' 1.0 ICS_INLINE_IMG ','ics_event_prop_matches_raw_param',
  ' 1.0 ICS_ATTACH_DELIM ','ics_event_prop_delimited_regex',
);

ok (sarun ("-L -t < data/nice/handler_ics", \&patterns_run_cb));
ok_all_patterns();

# handler_ics_html carries the same HTML in two properties -- a bare DESCRIPTION
# (no FMTTYPE, detected as HTML by its markup) and a duplicate X-ALT-DESC;
# FMTTYPE=text/html -- with the payload link only in an <a href>, no plain URL:
# property.  The ICS handler hands the HTML to the HTML handler as a child part
# (the duplicate collapses via the framework's content fingerprint).  We confirm:
#   * the link reaches the URI detail list (synthetic-part URI extraction);
#   * the visible text is rendered into the body -- ICS_HTML_TEXT fires;
#   * the raw markup does NOT leak into body rules -- ICS_HTML_RAWTAG must not fire.
# Requires the HTML handler (tstpre above).
%patterns = (
  ' 1.0 ICS_HTML_URI ',     'ics_html_property_uri',
  ' 1.0 ICS_HTML_TEXT ',    'ics_html_rendered_text',
  ' 1.0 ICS_HTML_ICSTEXT ', 'ics_html_rendered_text_icstext',
);
%anti_patterns = (
  ' 1.0 ICS_HTML_RAWTAG ', 'ics_html_raw_markup_leaked',
);
ok (sarun ("-L -t < data/nice/handler_ics_html", \&patterns_run_cb));
ok_all_patterns();
