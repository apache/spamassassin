#!/usr/bin/perl -w
use strict;
use Getopt::Long qw(GetOptions :config no_ignore_case);
use Time::HiRes qw(gettimeofday tv_interval);

my %opt = (
    host => 'localhost',
    port => 30783,
    conc => 2,
    max  => 0,
);

GetOptions(\%opt, qw(host|h=s port|p=i conc|concurrency|c=i max|m=i));
die "usage:\n\t$0 list of mboxes\n" unless @ARGV;

my (@mboxes, $curr_mbox, $mbox_fh) = @ARGV;

#my $all_all = 0;
#for my $f (@ARGV) {
#    my $mbox = Mail::MboxParser->new($f) or die;
#    $mbox->make_index;
#    push @mboxes, $mbox;
#    print 'mbox ' . $mbox->nmsgs() . "\t$f\n";
#    $all_all += $mbox->nmsgs;
#}

use IO::Socket::INET6;
use IO::Multiplex;

my @sockets;
my %conn = (
    PeerAddr => $opt{host},
    PeerPort => $opt{port},
);

my $mux = IO::Multiplex->new;
$mux->set_callback_object(__PACKAGE__);

my $msgs = 0;
my $tempfoo;
my $start = [gettimeofday];

while ($mux->handles < $opt{conc} && new_conn()) {
    ##warn ~~ $mux->handles();
    die if $mux->handles > $opt{conc};
}
$mux->loop;

my $howlong = tv_interval($start);
my $hour = int($howlong / 3600);
my $min  = int(($howlong % 3600) / 60);
my $sec  = $howlong % 60;
printf
"parsed %d messages in %02d:%02d:%02d (%s s), %.4f msgs/s (%.0f msgs/min, %.0f msgs/h)\n",
  $msgs, $hour, $min, $sec, $howlong, $msgs / $howlong, $msgs * 60 / $howlong,
  $msgs * 60 * 60 / $howlong;

#sleep 1;

sub new_conn {
    my $message = next_message() or return;
    die 'handles: ' . $mux->handles if $mux->handles > $opt{conc};

    return if $opt{max} && $msgs >= $opt{max};
    ++$msgs;

    #   return 1 unless ++$tempfoo >= 6800;
    #die "'$$message'";

    my $s = IO::Socket::INET6->new(%conn) or die;
    $mux->add($s) or die;
    my $spamc = Spamc->new(id => $msgs, s => $s, start => [gettimeofday],);
    $mux->set_callback_object($spamc, $s);
    $mux->set_timeout($s, 20);
    $mux->write($s,
            "SYMBOLS SPAMC/1.9\r\n"
          . 'Content-length: '
          . length($$message)
          . "\r\n\r\n"
          . $$message)
      or die;
    1;
}

sub next_message {
    local $/ = "\nFrom ";
    if ($curr_mbox && !eof $mbox_fh) {
        my $msg = tell $mbox_fh ? <$mbox_fh> : 'From ' . <$mbox_fh>;
        $msg =~ s/\r?\n(?:From )?$//;    # (?:...) is for last message
        return \$msg;
    }
    else {                               # end of mbox or first one
        return unless @mboxes;           # end
        $curr_mbox = shift @mboxes;
        close $mbox_fh if $mbox_fh;
        open $mbox_fh, '<', $curr_mbox or die "open $curr_mbox: $!";
        return next_message();           # ;->
    }
}

package Spamc;

sub mux_input {
    my ($self, $mux, $fh, $in) = @_;

    my $ret = $self->parse($in);
    if (defined $ret) {
        main::new_conn();
        if ($ret) {    # ok
            (my $body = $self->{body}) =~ y/\r\n/  /s;
            $self->{headers}->{spam} =~
              /^([TF])\S+\s*;\s*(-?[\d.]+)\s*\/\s*([\d.]+)\b/
              or die "bad Spam header: '$self->{headers}->{spam}'";
            printf "%-8s %5s %1s %4s/%3s %s\n",
              Time::HiRes::tv_interval($self->{start}),
              ($self->{id} ? $self->{id} : '(wtf)'), $1, $2, $3, $body;
        }
        else {
            warn 'fail for ', ($self->{id} ? $self->{id} : '(wtf)'),
              ": $self->{rcode} $self->{rmsg}\n";
			$mux->kill_output($fh);
        }
        $fh->close;                      # are both needed?
        $mux->close($fh);
    }

    #   undef $$in;
    #   $mux->close($fh);
}

sub mux_timeout {
    my $self = shift;
    my $mux  = shift;
    warn "timeout for $self->{id}\n";
    $mux->close($self->{s});
}

sub new {
    my $class = shift;
    bless {@_}, $class;
}

sub parse {
    my $self = shift;
    my $in = ref $_[0] ? $_[0] : \$_[0];
    my $ret;
    while ($$in =~ /\n/
        or defined $self->{body}
        && (length $$in || $self->{headers}->{content_length} == 0))
    {
        $ret =
            !defined $self->{banner} ? $self->banner($in)
          : !defined $self->{body}   ? $self->headers($in)
          : $self->body($in);
        return $ret if defined $ret;
    }
    undef;
}

sub banner {
    my $self = shift;
    my $in   = shift;
    if ($$in =~ s/^SPAMD\/(\d\.\d)\s+(\d+)\s+([^\r\n]+)\r?\n//) {
        (@{$self}{qw(sver rcode rmsg)}) = ($1, $2, $3);
        $self->{banner}++;
    }
    else {
        warn "unparseable input from spamd: '$$in'";
        return 0;
    }
    if ($self->{rcode} != 0) {
#       warn "fail: $self->{rcode} $self->{rmsg}\n";
        return 0;
    }
    undef;
}

sub headers {
    my $self = shift;
    my $in   = shift;
    die "blah" unless $self->{banner};
    while ($$in =~ s/^([a-z\d_-]+):\s+([^\r\n]+)\r?\n//i) {
        my ($h, $v) = ($1, $2);
        $h =~ y/A-Z-/a-z_/;
        $self->{headers}->{$h} = $v;
    }
    die "content-length not numeric"
      if defined $self->{headers}->{content_length}
      && $self->{headers}->{content_length} !~ /^\d+$/;
    if ($$in =~ s/^\r?\n//) {
        $self->{body} = '';
        unless ($self->{headers}->{spam}) {
            warn "no Spam header", keys %{ $self->{headers} };
            return 0;
        }
        unless (defined $self->{headers}->{content_length}) {
            warn "Content-length is required";
            return 0;
        }
    }
    elsif ($$in =~ /\n/) {
        warn "bad header '$$in'";
        return 0;
    }
    undef;
}

sub body {
    my $self = shift;
    my $in   = shift;
    die "fubar"
      unless $self->{banner} && $self->{headers} && defined $self->{body};
    $self->{body} .= $$in;
    $$in = '';
    if (defined(my $l = $self->{headers}->{content_length})) {
        if (length $self->{body} == $l) {
            return 1;
        }
        elsif (length $self->{body} > $l) {
            warn "body too long";
            return 0;
        }
    }
    else {
        return 1 if $self->{body} =~ /\n/;    # only good for one line output
    }
    undef;
}

#sub DESTROY { my $self = shift; warn "DESTROY $self->{id}"; }
1;
