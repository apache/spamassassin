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

    'EXE_FILES'	=> [ 'spamassassin', 'spamd/spamc', 'spamd/spamd' ],

    'MAN1PODS' => {
	    'spamassassin' => '$(INST_MAN1DIR)/spamassassin.$(MAN1EXT)',
	    'spamd/spamc.pod' => '$(INST_MAN1DIR)/spamc.$(MAN1EXT)',
	    'spamd/spamd' => '$(INST_MAN1DIR)/spamd.$(MAN1EXT)',
    },

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
	'pod2htm* spamassassin spamd/spamc spamd/spamd'
    },

    'AUTHOR' => 'Justin Mason <jm@jmason.org>',

		  #----------------------------------------
    'ABSTRACT' => 'identify spam mail using text analysis'

);

sub MY::tools_other {
	package MY;
	my $inherited = shift->SUPER::tools_other (@_);
	$inherited."\nCFLAGS=-g\n";
}

sub MY::install {
  package MY;
  my $inherited = shift->SUPER::install (@_);

  $inherited =~ s/^(install :: .*)$/$1 inst_cfs/gm;
  $inherited;
}

sub MY::postamble {
q{

EXTRAPODS = spamd/spamc.pod

pm_to_blib: spamassassin

spamassassin: spamassassin.raw
	$(PERL) fixpath.pl spamassassin.raw $@
	$(CHMOD) $(PERM_RWX) $@

spamd/spamd: spamd/spamd.raw
	$(PERL) fixpath.pl spamd/spamd.raw $@
	$(CHMOD) $(PERM_RWX) $@

inst_cfs: spamassassin.cf spamassassin.prefs
	$(CP) spamassassin.cf $(INSTALLSITELIB)/spamassassin.cf
	$(CP) spamassassin.prefs $(INSTALLSITELIB)/spamassassin.prefs

text_html_doc: $(MAN1PODS) $(MAN3PODS)
	-mkdir doc
	for f in $(MAN1PODS) $(MAN3PODS) $(EXTRAPODS) ; do \
	      pod2html $$f > doc/`echo $$f | perl -pe \
	  	's/(lib|spamd)\///; s/\//::/g; s/\.(pod|pm)//;'`.html ; \
	      pod2text $$f > doc/`echo $$f | perl -pe \
	  	's/(lib|spamd)\///; s/\//::/g; s/\.(pod|pm)//;'`.txt ; \
	done

};
}
