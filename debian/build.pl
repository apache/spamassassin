#!/usr/bin/perl -w

die 'Run from top level spamassassin directory' unless -d 'debian';

use lib 'lib';
use Mail::SpamAssassin;
use Getopt::Std;

getopts('d'); # d = do it!

our $opt_d;

# Checking that everything is where we need it.
warn 'You might want to set $EMAIL or $DEBEMAIL'
    if !$ENV{EMAIL} && !$ENV{DEBEMAIL};

warn 'You might want to set $DEBFULLNAME'
    if !$ENV{DEBFULLNAME};

die 'dch not available: run apt-get install devscripts' unless -x '/usr/bin/dch';

die 'dpkg-buildpackage not available: run apt-get install dpkg-dev' unless -x '/usr/bin/dpkg-buildpackage';

die 'debhelper not available: run apt-get install debhelper' unless -x '/usr/bin/dh_testroot';


# Let's go.
if (!-f 'changelog') {
    system ("/bin/cp", "debian/changelog.in", "debian/changelog") == 0
	or die "Couldn't copy, error $?";
}

my ($cvsversion, $oldversion, $datecode, $debianversion, $revisioncode);

$cvsversion = $Mail::SpamAssassin::VERSION;
print "Current CVS version: $cvsversion\n";

$datecode = `date -u +%Y%m%d`;
chomp $datecode;

open (CHANGELOG, "debian/changelog");

while (<CHANGELOG>) {
    if (/spamassassin \((\d+\.\d+)pre(\d+.\d+)cvs(\d+)-(\d+)\) unstable;/) {
	$oldversion = $1;
	warn "Using current CVS version, not version from changelog" if $2 != $cvsversion;
	if ($3 == $datecode) {
	    $revisioncode = $4 + 1;
	    print "Already built today, using revision $revisioncode\n";
	} else {
	    $revisioncode = 1;
	}
	last;
    }
	 
    if (/spamassassin \((\d+\.\d+)-\d\) unstable; urgency=/) { # Should ignore cvs versions
	$oldversion = $1;
	print "Last Debian version: $oldversion\n";
	$revisioncode = 1;
	last;
    }
}

close CHANGELOG;

die "Can't determine old version\n" if !$oldversion;

$debianversion = "${oldversion}pre${cvsversion}cvs${datecode}-${revisioncode}"; # Not pretty but informative

print "Building debian version $debianversion\n";

unlink "debian/changelog"; # We don't need accumulating changelogs!
system ("/bin/cp", "debian/changelog.in", "debian/changelog") == 0
  or die "Couldn't copy, error $?";

system('/usr/bin/dch', "--newversion=$debianversion", 'Packaging from CVS') == 0 or die "system() error: $?";

print "OK!\n";

if ($opt_d) {
    print "Trying to run dpkg-buildpackage\n";
    exec('/usr/bin/dpkg-buildpackage', '-rfakeroot', '-b');
    die "Exec failed! Error: $?";
}

