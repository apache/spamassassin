#!/usr/bin/perl -w
#
# A quick Win32 installer that creates .bat files for the Perl scripts.

@EXE_FILES = qw{
  	spamassassin
};

my $runperl;
for (".", split ';', $ENV{PATH}) {
  $_ = "." if $_ eq "";
  $runperl = "$_/runperl.bat" , goto doit if -f "$_/runperl.bat";
}
die "'runperl.bat' not found. Is the Perl 'bin' directory in your PATH?\n";

use File::Copy;

doit:
foreach my $file (@EXE_FILES) {
  copy ($runperl, $file.".bat");
  print "Created: $file.bat\n";
}

# generate a quick maketest.pl script which runs the tests
{
  my $file = 'maketest';
  open (OUT, ">$file") or die "cannot write to $file\n";
  print OUT q{#!/usr/bin/perl -w
    $ENV{'PERL_DL_NONLAZY'} = 1;
    @tees = <t/*.t>;
    use Test::Harness qw(&runtests);
    runtests @tees;
  };
  copy ($runperl, $file.".bat");
  print "Created: $file.bat\n";
  close OUT or die "cannot write to $file\n";
}

print "
You will still need to install the modules to use this script. See
the README file, and your perl documentation, for more details.
";
