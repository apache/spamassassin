=head1 NAME

MSExec - determine if the message includes a Microsoft executable file

This rule works by checking for 3 possibilities in the message in any
application/* or text/* part in the message:

=over 4

=item - in text parts, look for a uuencoded executable start string

=item - in application parts, look for filenames ending in an executable extension

=item - in application parts, look for a base64 encoded executable start string

=back

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::MSExec
  body           MICROSOFT_EXECUTABLE eval:check_microsoft_executable()

=cut

package Mail::SpamAssassin::Plugin::MSExec;

use Mail::SpamAssassin::Plugin;
use strict;
use warnings;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule ("check_microsoft_executable");

  return $self;
}

sub check_microsoft_executable {
  my ($self, $permsgstatus) = @_;

  foreach my $p ($permsgstatus->{msg}->find_parts(qr/^(application|text)\b/)) {
    my ($ctype, $boundary, $charset, $name) =
      Mail::SpamAssassin::Util::parse_content_type($p->get_header('content-type'));

    if (lc $ctype eq 'application/octet-stream') {
      $name ||= '';
      $name = lc $name;

      # file extension indicates an executable ...
      return 1 if ($name =~ /\.(?:scr|bat|com|pif|exe)$/);

      # base64 attached executable ...
      my $cte = lc $p->get_header('content-transfer-encoding') || '';
      return 1 if ($cte =~ /base64/ && $p->raw()->[0] =~ /^TV[opqr].A..[AB].[AQgw][A-H].A/);
    }
    elsif ($ctype =~ /^text\b/i) {
      # uuencoded executable ...
      foreach (@{$p->raw()}) {
        return 1 if (/^M35[GHIJK].`..`..*````/);
      }
    }
  }
  return 0;
}

1;
