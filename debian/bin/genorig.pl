#!/usr/bin/perl
# Create an orig.tar.xz file from upstream SVN snapshots.
#
# Copyright 2019 Noah Meyerhans <frodo@morgul.net>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Upstream does not publish rules as part of the snapshot, so this
# script additionally grabs the current trunk rules, rulesrc, and
# t.rules subdirectories

use warnings;
use strict;
use File::Temp qw(tempdir);
use File::Basename;
use File::Path qw(remove_tree);

use constant {
    SVNROOT => q(http://svn.apache.org/repos/asf/spamassassin),
    ORIGDIR => q(../orig),
};

# Certain subdirectories in upstream svn contain files (including binary object
# files) that we need to remove from the .orig tarball.  List them here:
my @PRUNE_SUBDIRS = qw(build/pga),

my $snapshotpath = SVNROOT . "/tags";
my $trunkpath    = SVNROOT . "/trunk";

sub logcmd {
    my $cmd = shift;
    print "EXEC $cmd\n";
    my $rv = system($cmd);
    if($rv != 0) {
        die "Command returned $rv\n";
    }
    return 0;
}

sub get_upstream_version {
    my $version = `dpkg-parsechangelog -S version`;
    if( $version =~ m/(\S+)-[^-]+/ ) {
        return $1;
    }
    return "";
}

sub get_snapshot_name($) {
    my $version = shift;
    if(length($version) > 0) {
        if ($version =~ m/~(pre|rc)\d+$/n) {
            print "This seems to be an RC release. Frobbing version string accordingly...\n";
            $version =~ s/(\d+)$/_$1/;
        } elsif($version =~ m/svn\d+/) {
            return "trunk";
        }
        $version =~ s/[-~\.]/_/g;
        return "spamassassin_release_$version";
    }
    return "";
}

sub get_svn_revision($) {
    my ($version) = @_;
    if($version =~ m/svn(\d+)/) {
        return $1;
    }
    return "";
}

sub export($$$) {
    my ($svnpath, $svnrev, $outdir) = @_;
    logcmd("svn export -r $svnrev $svnpath $outdir");
}

sub dejunkify($$) {
    my ($topdir, $subdirs) = @_;
    warn "Called dejunkify...";
    foreach my $subdir (@$subdirs) {
        warn "Removing $topdir/$subdir\n";
        my $fspath = join('/', $topdir, $subdir);
        remove_tree($fspath) or die "Removing $fspath: $!";
    }
}

sub generate_snapshot_dir($$) {
    my ($version, $topdir) = @_;
    my $svnpath;
    my $svnrev = "HEAD";
    if(defined($ENV{'SPAMASSASSIN_OVERRIDE_SNAPSHOT_PATH'})) {
        warn "WARNING: OVERRIDING SPAMASSASSIN SVN LOCATION!\n";
        $svnpath = $ENV{'SPAMASSASSIN_OVERRIDE_SNAPSHOT_PATH'};
    } else {
        my $snap = get_snapshot_name($version);
        die if $snap eq "";
        if($snap eq "trunk") {
            $svnpath = $trunkpath;
            $svnrev = get_svn_revision($version);
            if($svnrev =~ /\D/) {
                die "svn revision $svnrev is not numeric\n";
            }
        } else {
            $svnpath = join('/', $snapshotpath, $snap);
        }
    }
    export($svnpath, $svnrev, $topdir);
    if($svnpath =~ /(trunk|release_4_)/) {
        warn "NOTICE: Using embedded upstream components, skipping additional exports\n";
    } else {
        foreach my $component (qw/rules rulesrc t.rules/) {
            my $svnpath = join('/', $trunkpath, $component);
            export($svnpath, $svnrev, "$topdir/$component");
        }
    }
    dejunkify($topdir, \@PRUNE_SUBDIRS);
    return $topdir;
}

sub generate_tarball($$) {
    my ($version, $workdir) = @_;
    my $filename = "spamassassin_${version}.orig.tar.xz";
    my $outfile = join('/', ORIGDIR, $filename);
    my $tarcmd = "tar cJf $outfile -C $workdir spamassassin-$version";
    logcmd($tarcmd);
    symlink "orig/$filename", ORIGDIR . "/../$filename";
}

sub cleanup($) {
    my ($workdir) = @_;
    remove_tree($workdir, verbose => 1);
}

my $workdir = tempdir( DIR => ORIGDIR );
my $version = get_upstream_version();
my $snapshotdir = "$workdir/spamassassin-$version";
generate_snapshot_dir($version, $snapshotdir);
generate_tarball($version, $workdir);
cleanup($workdir);

# Local variables:
# mode: perl
# tab-width: 4
# indent-tabs-mode: nil
# end:
