# Mail::SpamAssassin::AuditMessage - interface to Mail::Audit message text

package Mail::SpamAssassin::AuditMessage;

use Carp;
use strict;
eval "use bytes";

use Mail::SpamAssassin::NoMailAudit;
use Mail::SpamAssassin::Message;

use vars        qw{
        @ISA
};

@ISA = qw(Mail::SpamAssassin::Message);

###########################################################################

sub create_new {
  my ($self, @args) = @_;
  return Mail::SpamAssassin::NoMailAudit->new(@args);
}

sub put_header {
  my ($self, $hdr, $text) = @_;
  $self->{mail_object}->put_header ($hdr, $text);
}

sub get_all_headers {
  my ($self) = @_;
  $self->{mail_object}->header();
}

1;
