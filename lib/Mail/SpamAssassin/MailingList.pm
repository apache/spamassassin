# $Id: MailingList.pm,v 1.3 2002/08/06 11:36:39 jmason Exp $

# Eval Tests to detect genuine mailing lists.

package Mail::SpamAssassin::MailingList;
1;

package Mail::SpamAssassin::PerMsgStatus;

sub detect_mailing_list {
    my ($self) = @_;
    return 1 if $self->detect_ml_ezmlm();
    return 1 if $self->detect_ml_mailman();
    return 1 if $self->detect_ml_sympa();
    return 0;
}

sub detect_moderated_mailing_list {
    my ($self) = @_;
    return 0;
}

# EZMLM
# Mailing-List: .*run by ezmlm
# Precedence: bulk
# List-Post: <mailto:
# List-Help: <mailto:
# List-Unsubscribe: <mailto:[a-zA-Z\.-]+-unsubscribe@
# List-Subscribe: <mailto:[a-zA-Z\.-]+-subscribe@
sub detect_ml_ezmlm {
    my ($self) = @_;
    return 0 unless $self->get('mailing-list') =~ /ezmlm$/;
    return 0 unless $self->get('precedence') eq 'bulk';
    return 0 unless $self->get('list-post') =~ /^<mailto:/;
    return 0 unless $self->get('list-help') =~ /^<mailto:/;
    return 0 unless $self->get('list-unsubscribe') =~ /<mailto:[a-zA-Z\.-]+-unsubscribe\@/;
    return 0 unless $self->get('list-subscribe') =~ /<mailto:[a-zA-Z\.-]+-subscribe\@/;
    return 1; # assume ezmlm then.
}

# MailMan (the gnu mailing list manager)
#  Precedence: bulk
#  List-Help: <mailto:
#  List-Post: <mailto:
#  List-Subscribe: .*<mailto:.*=subscribe>
#  List-Id: 
#  List-Unsubscribe: .*<mailto:.*=unsubscribe>
#  List-Archive: 
#  X-Mailman-Version: \d
sub detect_ml_mailman {
    my ($self) = @_;
    return 0 unless $self->get('x-mailman-version') =~ /^\d/;
    return 0 unless $self->get('precedence') eq 'bulk';
    return 0 unless $self->get('list-id');
    return 0 unless $self->get('list-help') =~ /^<mailto:/;
    return 0 unless $self->get('list-post') =~ /^<mailto:/;
    return 0 unless $self->get('list-subscribe') =~ /<mailto:.*=subscribe>/;
    return 0 unless $self->get('list-unsubscribe') =~ /<mailto:.*=unsubscribe>/;
    return 0 unless $self->get('list-archive'); # maybe comment this out.
    return 1; # assume this is a valid mailman list
}

# Sympa
# Return-Path: somelist-owner@somedomain.com [...]
# Precedence: list [...]
# List-Id: <somelist@somedomain.com>
# List-Help: <mailto:sympa@somedomain.com?subject=help>
# List-Subscribe: <mailto:somedomain.com?subject=subscribe%20somelist>
# List-Unsubscribe: <mailto:sympa@somedomain.com?subject=unsubscribe%somelist>
# List-Post: <mailto:somelist@somedomain.com>
# List-Owner: <mailto:somelist-request@somedomain.com>
# [and optionally] List-Archive: <http://www.somedomain.com/wws/arc/somelist>

# NB: This isn't implemented, since there is nothing here saying "Sympa".
sub detect_ml_sympa {
    my ($self) = @_;
    return 0;
    return 1;
}

# Lyris
# Not implemented - need headers
sub detect_ml_lyris {
}

1;
