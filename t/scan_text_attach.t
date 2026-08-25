#!/usr/bin/perl -w -T

use strict;
use lib '.'; use lib 't';
use SATest; sa_t_init("scan_text_attach");
use Test::More tests => 8;

use Mail::SpamAssassin;
use Mail::SpamAssassin::PerMsgStatus;

# A text/html part marked Content-Disposition: attachment is, by default,
# excluded from the rendered body text that body rules see.  The
# scan_text_attachments option includes it.  See t/data/nice/scan_text_attach.
#
# scan_text_attachments gates all three rendered arrays uniformly (rendered,
# visible, invisible): whether a text attachment participates at all is this
# option's job.  Which streams Bayes tokenizes is bayes_token_sources' job --
# the two are orthogonal, so with the flag off the attachment's *invisible*
# text is excluded too (not just its visible text).

my $vis_marker = 'UNIQUEPHISHMARKER';    # visible attachment text
my $inv_marker = 'UNIQUEHIDDENMARKER';   # display:none attachment text

sub bodies {
  my ($post_config_text) = @_;
  my $sa = create_saobj({
    dont_copy_prefs => 1,
    post_config_text => $post_config_text,
  });
  $sa->init(0);
  open (IN, "<data/nice/scan_text_attach") or die "cannot open fixture: $!";
  my $mail = $sa->parse(\*IN);
  close IN;
  # Run the MIME-part handlers, as a real scan does: a text/html part is
  # rendered by Mail::SpamAssassin::Handler::HTML, so without this there is no
  # rendered text for it at all.  apply_handlers() needs a PerMsgStatus for the
  # handlers to accumulate findings on, even though this test reads only the
  # body arrays off the message.
  my $pms = Mail::SpamAssassin::PerMsgStatus->new($sa, $mail);
  $mail->apply_handlers($pms);
  my %b = (
    rendered  => join('||', @{$mail->get_rendered_body_text_array()}),
    invisible => join('||', @{$mail->get_invisible_rendered_body_text_array()}),
  );
  $pms->finish;
  $mail->finish;
  $sa->finish;
  return %b;
}

# ---------------------------------------------------------------------------
# Default: attachment text is excluded from ALL arrays, including invisible

my %off = bodies('');
unlike($off{rendered}, qr/\Q$vis_marker\E/,
  'attachment visible text excluded from body by default');
like($off{rendered}, qr/remittance advice/i,
  'inline text/plain body part still present by default');
unlike($off{invisible}, qr/\Q$inv_marker\E/,
  'attachment invisible text excluded from invisible array by default');

# ---------------------------------------------------------------------------
# scan_text_attachments 1: attachment text is included in all arrays

my %on = bodies('scan_text_attachments 1');
like($on{rendered}, qr/\Q$vis_marker\E/,
  'attachment visible text included in body with scan_text_attachments 1');
like($on{rendered}, qr/remittance advice/i,
  'inline text/plain body part still present with scan_text_attachments 1');
like($on{rendered}, qr/\Q$inv_marker\E/,
  'attachment invisible text folded into body with scan_text_attachments 1');
like($on{invisible}, qr/\Q$inv_marker\E/,
  'attachment invisible text included in invisible array with scan_text_attachments 1');
unlike($on{invisible}, qr/\Q$vis_marker\E/,
  'visible text does not leak into the invisible array');
