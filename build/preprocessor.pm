# This code is copied directly from ExtUtils::MakeMaker 6.05.
# It's used if a version of EU::MM prior to 5.45 (not supporting PM_FILTER)
# is installed.

package ExtUtils::Install::Post545;


warn <<ITSALLSOSTUPID;

Your version of ExtUtils::MakeMaker is a pre-5.45. We need to include a
nasty workaround to make it work with our make routines. You will get 
loads of warnings and it is very likely to break at various places.

*Please* consider updating to a version later than 5.45. It's available
on CPAN <http://search.cpan.org/search?module=ExtUtils::MakeMaker>. 

Hint: Perl 5.6.1 and older ship good versions of ExtUtils::MakeMaker;

If anything breaks while building Mail::SpamAssassin, please file a bug
at <http://bugzilla.spamassassin.org>.

ITSALLSOSTUPID


use strict;

use vars qw(
  $VERSION @ISA
  $Is_VMS
);

$VERSION = 1.30;
use ExtUtils::Install;
@ISA = qw(ExtUtils::Install);


$Is_VMS = $^O eq 'VMS';


*forceunlink = *ExtUtils::Install::forceunlink;


sub run_filter {
    my ($cmd, $src, $dest) = @_;
    open(CMD, "|$cmd >$dest") || die "Cannot fork: $!";
    open(SRC, $src)           || die "Cannot open $src: $!";
    my $buf;
    my $sz = 1024;
    while (my $len = sysread(SRC, $buf, $sz)) {
        syswrite(CMD, $buf, $len);
    }
    close SRC;
    close CMD or die "Filter command '$cmd' failed for $src";
}

sub pm_to_blib {
    my($fromto,$autodir,$pm_filter) = @_;

    use File::Basename qw(dirname);
    use File::Copy qw(copy);
    use File::Path qw(mkpath);
    use File::Compare qw(compare);
    use AutoSplit;
    # my $my_req = $self->catfile(qw(auto ExtUtils Install forceunlink.al));
    # require $my_req; # Hairy, but for the first

    if (!ref($fromto) && -r $fromto)
     {
      # Win32 has severe command line length limitations, but
      # can generate temporary files on-the-fly
      # so we pass name of file here - eval it to get hash
      open(FROMTO,"<$fromto") or die "Cannot open $fromto:$!";
      my $str = '$fromto = {qw{'.join('',<FROMTO>).'}}';
      eval $str;
      close(FROMTO);
     }

    mkpath($autodir,0,0755);
    foreach (keys %$fromto) {
        my $dest = $fromto->{$_};
        next if -f $dest && -M $dest < -M $_;

        # When a pm_filter is defined, we need to pre-process the source first
        # to determine whether it has changed or not.  Therefore, only perform
        # the comparison check when there's no filter to be ran.
        #    -- RAM, 03/01/2001

        my $need_filtering = defined $pm_filter && length $pm_filter && /\.pm$/;

        if (!$need_filtering && 0 == compare($_,$dest)) {
            print "Skip $dest (unchanged)\n";
            next;
        }
        if (-f $dest){
            forceunlink($dest);
        } else {
            mkpath(dirname($dest),0,0755);
        }
        if ($need_filtering) {
            run_filter($pm_filter, $_, $dest);
            print "$pm_filter <$_ >$dest\n";
        } else {
            copy($_,$dest);
            print "cp $_ $dest\n";
        }
        my($mode,$atime,$mtime) = (stat)[2,8,9];
        utime($atime,$mtime+$Is_VMS,$dest);
        chmod(0444 | ( $mode & 0111 ? 0111 : 0 ),$dest);
        next unless /\.pm$/;
        autosplit($dest,$autodir);
    }
}

1;
