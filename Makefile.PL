require 5.005;
use ExtUtils::MakeMaker;

sub MY::libscan {
  my($self,$path) = @_;

  return '' if ($path =~ /windows_install/
  		|| $path =~ /fixpath/
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
	'pod2html* spamassassin'
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

pm_to_blib: spamassassin

spamassassin: spamassassin.raw
	$(PERL) fixpath.pl spamassassin.raw $@
	$(CHMOD) $(PERM_RWX) $@

inst_cfs: spamassassin.cf spamassassin.prefs
	$(CP) spamassassin.cf $(INSTALLSITELIB)/spamassassin.cf
	$(CP) spamassassin.prefs $(INSTALLSITELIB)/spamassassin.prefs

text_html_doc: $(MAN1PODS) $(MAN3PODS)
	-mkdir doc
	for f in $(MAN1PODS) ; do pod2html $$f > doc/$$f.html ; done
	for f in $(MAN1PODS) ; do pod2text $$f > doc/$$f.txt ; done
	for f in $(MAN3PODS) ; do pod2html $$f > doc/`echo $$f | sed \
	  	-e 's/lib\///' -e 's/\//::/g' -e 's/\.pm//'`.html ; done
	for f in $(MAN3PODS) ; do pod2text $$f > doc/`echo $$f | sed \
	  	-e 's/lib\///' -e 's/\//::/g' -e 's/\.pm//'`.txt ; done

};
}
