#!/usr/bin/perl -w

# CVS Build script for SpamAssassin Debian packages
# Options:
# -d           Automatically build package
# -e <email>   Set email to use in changelog
# -f <name>    Set full name to use in changelog

use lib 'lib';
use Mail::SpamAssassin;
use Getopt::Std;
use POSIX;
use strict;

our ($email, $name, %opts);
getopts('de:f:', \%opts); # d = do it!

# check env
sub check_environment {
    if (! -x 'debian/rules') {
	die 'Run from top level spamassassin CVS directory';
    }
    if (!$ENV{EMAIL} && !$ENV{DEBEMAIL} && !$opts{e}) {
	warn 'No e-mail address specified. Using nobody@nowhere';
    }
    if(system("/usr/bin/dpkg-checkbuilddeps") != 0) {
	die 'Build dependencies not satisfied, or dpkg-checkbuilddeps not available.';
    }
}

sub set_maintainer {
    $email = undef;
    $name = undef;
    
    if ($opts{e}) {
	$email = $opts{e};
    }

    if ($opts{f}) {
	$name = $opts{f};
    }

    return if (defined $name and defined $email);

    if ($ENV{DEBEMAIL}) {
	if ($ENV{DEBEMAIL} =~ /^(.*)\s+<(.*)>$/) {
	    $name ||= $1;
	    $email ||= $2;
	}
    }

    return if (defined $name and defined $email);

    if ($ENV{EMAIL}) {
	if ($ENV{EMAIL} =~ /^(.*)\s+<(.*)>$/) {
	    $name ||= $1;
	    $email ||= $2;
	}
    }

    return if (defined $name and defined $email);

    # Don't bother looking up user's name from /etc/passwd
    $name ||= 'Anonymous CVS Builder';
    $email ||= 'nobody@nowhere';

}

sub get_version {
    return Mail::SpamAssassin::Version();
}

sub update_changelog {
    my ($datel, $dates);
    my $version = get_version();
    chomp($datel = `822-date`);
    chomp($dates = `date +"%Y%m%d"`);
    open OUT, '>debian/changelog';
    print OUT <<EOF;
spamassassin ($version+$dates-1) experimental; urgency=low

  * CVS packaged version
  * A changelog to previous versions is not included. Please see the
    official Debian packages for changelog information.
  
 -- $name <$email>  $datel
EOF
    close OUT;
}

# Merge templates
sub check_debconfpo {
    if (! -x '/usr/bin/po2debconf') {
	open IN, 'debian/spamassassin.templates';
	open OUT, '>debian/spamassassin.templates.stripped';
	while (<IN>) {
	    s#^__?##;
	    print OUT $_;
	}
	close IN;
	close OUT;
	rename 'debian/spamassassin.templates', 'debian/spamassassin.templates.orig';
	rename 'debian/spamassassin.templates.stripped', 'debian/spamassassin.templates'
    }
}

sub doit {
    print "Trying to run dpkg-buildpackage\n";
    exec('/usr/bin/dpkg-buildpackage', '-rfakeroot', '-b');
    die "Exec failed! Error: $?";
}

check_environment();
set_maintainer();
update_changelog();
check_debconfpo();
doit() if $opts{d};
