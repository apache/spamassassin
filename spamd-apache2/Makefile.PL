#!/usr/bin/perl
use strict;
use ExtUtils::MakeMaker;
use Apache::TestMM qw(test clean);

unless (grep /^-?-apxs$/, @ARGV) {
	if (my $apxs = find_in_path('apxs')) {
		push @ARGV, '--apxs', $apxs;
	}
	else {
		warn 'apxs not found in PATH; ',
		  'try "perl Makefile.PL --apxs /path/to/apxs"', "\n";
	}
}

Apache::TestMM::filter_args();
Apache::TestMM::generate_script('t/TEST');

WriteMakefile(
	VERSION   => '0.03',
	NAME      => 'Mail::SpamAssassin::Spamd::Apache2',
	ABSTRACT  => 'mod_perl2 module implementing spamd in Apache2',
	AUTHOR    => 'Radoslaw Zielinski <radek@pld-linux.org>',
	EXE_FILES => [qw(bin/apache-spamd.pl)],
	PREREQ_PM => {
		'mod_perl2'          => 2,
		'Mail::SpamAssassin' => 3.001,
		'File::Path'         => 0,
		'File::Temp'         => 0,
		'Getopt::Long'       => 2.34,
		'Apache::Test'       => 0,
	},
);


sub find_in_path {
	require File::Spec;
	my $prog = shift or die;
	return $_
	  for grep -x, map File::Spec->catfile($_, $prog), File::Spec->path();
	undef;
}

# Apache::Test checks if server is alive by trying "GET / HTTP/1.0".
# Can be skipped either with this hack, or... by allowing GET.
#sub MY::postamble {
#	"PASSENV += APACHE_TEST_PRETEND_NO_LWP=1\n"
#}

# vim: ts=4 sw=4 noet
