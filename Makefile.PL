require 5.005;
use ExtUtils::MakeMaker;

sub MY::libscan {
  my($self,$path) = @_;

  return '' if ($path =~ /windows_install/
                );

  $path;
}

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Mail::SpamBlok',
    'VERSION_FROM' => 'lib/Mail/SpamBlok/Main.pm', # finds $VERSION

    'EXE_FILES'	=> [ 'spamblok'],

    'PL_FILES' => '',

    'PMLIBDIRS' => [ 'lib' ],

    'dist' => { COMPRESS => 'gzip -9f', SUFFIX => 'gz',
	      DIST_DEFAULT => 'tardist' },

    'clean' => { FILES =>
	'pod2html* '
    },

    'AUTHOR' => 'Justin Mason <jm@jmason.org>',

    'ABSTRACT' => 'mail filter with rules to block UCE'

);
