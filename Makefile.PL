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
    'NAME'	=> 'Mail::SpamAssassin',
    'VERSION_FROM' => 'lib/Mail/SpamAssassin.pm', # finds $VERSION

    'EXE_FILES'	=> [ 'spamassassin'],

    'PL_FILES' => '',

    'PMLIBDIRS' => [ 'lib' ],

    'PREREQ_PM' => {
                        'File::Copy' => 0,
                        'Mail::Audit' => 0,
                        'Net::DNS' => 0,
                  },


    'dist' => {
      		COMPRESS => 'gzip -9f', SUFFIX => 'gz',
	      	DIST_DEFAULT => 'tardist'
	      },

    'clean' => { FILES =>
	'pod2html* '
    },

    'AUTHOR' => 'Justin Mason <jm@jmason.org>',

		  #----------------------------------------
    'ABSTRACT' => 'identify spam mail using text analysis'

);

sub MY::install {
  package MY;
  my $inherited = shift->SUPER::install (@_);

  $inherited =~ s/^(install :: .*)$/$1 inst_cfs/gm;
  $inherited;
}

sub MY::postamble {
q{

inst_cfs: spamassassin.cf spamassassin.prefs
	$(CP) spamassassin.cf $(INSTALLSITELIB)/spamassassin.cf
	$(CP) spamassassin.prefs $(INSTALLSITELIB)/spamassassin.prefs

};
}
