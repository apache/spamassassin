# $Id: MyMailAudit.pm,v 1.2 2001/10/27 09:04:31 jmason Exp $

package Mail::SpamAssassin::MyMailAudit;

use Mail::Audit;
use Mail::Internet;

@Mail::SpamAssassin::MyMailAudit::ISA = ('Mail::Audit');

sub new {
    my $class = shift;
    if ($Mail::Audit::VERSION > 1.9) {
        return $class->SUPER::new(@_);
    }
    
    ## Code copied verbatim from Mail::Audit 1.9, with local patch applied.
    
    my %opts = @_;
    my $self = bless({
        %opts,
        obj => Mail::Internet->new(
                    exists $opts{data}? $opts{data} : \*STDIN,
                    Modify => 0,
                )
    }, $class) ;
    if (exists $self->{loglevel}) {
        $logging =1;
        $loglevel = $self->{loglevel};
    }
    if (exists $self->{log}) {
        $logging = 1;
        $logfile = $self->{log};
    }
    if ($logging) {
        open LOG, ">>$logfile" or die $!;
        _log(1,"Logging started at ".scalar localtime);
        _log(2,"Incoming mail from ".$self->from);
        _log(2,"To: ".$self->to);
        _log(2,"Subject: ".$self->subject);
    }
    return $self;
}

# argh, avoid a "used only once" warning
sub _never_called_shutup_lint { print LOG; }

1;
