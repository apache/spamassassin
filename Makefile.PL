require 5.005;

use Config;
use ExtUtils::MakeMaker;

my $mycflags = '';		# this is a good place to put -g etc.

# if (-d 'CVS' && !-f 'doc/spamassassin.html') {
# print <<EOWARN;
# 
# Note: I see you have a 'CVS' directory.  SpamAssassin's MANIFEST file is set up
# to deal with the distribution-tarball case, not the CVS case, so you may see a
# warning about missing files, particularly in the 'doc' subdirectory.  This can
# be safely ignored.
# 
# EOWARN
# }

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
	'pod2htm* spamassassin spamd/spamc spamd/spamd doc'
    },

    'AUTHOR' => 'Justin Mason <jm@jmason.org>',

		  #----------------------------------------
    'ABSTRACT' => 'identify spam mail using text analysis'

);

sub MY::install {
  package MY;
  my $self = shift;
  my $inherited = $self->SUPER::install (@_);

  $inherited =~ s/^(install :: .*)$/$1 inst_cfs/gm;
  $inherited;
}

sub MY::postamble {
    # import some C-linkage stuff from %Config.  We can't seem to
    # do this with MakeMaker without it trying to build the perl
    # modules as .so's :(

qq{

CFCC		= $Config{cc}
CFCCFLAGS	= $Config{ccflags} $mycflags
CFOPTIMIZE	= $Config{optimize}
CFLIBS		= $Config{libs}
CFLDFLAGS	= $Config{ldflags}

}. q{

pm_to_blib: spamassassin doc/.made

spamassassin: spamassassin.raw
	$(PERL) fixpath.pl spamassassin.raw $@
	$(CHMOD) $(PERM_RWX) $@

spamd/spamd: spamd/spamd.raw
	$(PERL) fixpath.pl spamd/spamd.raw $@
	$(CHMOD) $(PERM_RWX) $@

spamd/spamc: spamd/spamc.c
	$(CFCC) $(CFCCFLAGS) $(CFOPTIMIZE) spamd/spamc.c \
			-o $@ $(CFLDFLAGS) $(CFLIBS)

inst_cfs: spamassassin.cf spamassassin.prefs
	$(CP) spamassassin.cf $(INSTALLSITELIB)/spamassassin.cf
	$(CP) spamassassin.prefs $(INSTALLSITELIB)/spamassassin.prefs

text_html_doc: doc/.made

doc/.made: $(MAN1PODS) $(MAN3PODS)
	-mkdir doc
	for f in $(MAN1PODS) $(MAN3PODS) $(EXTRAPODS) ; do \
	      pod2html $$f > doc/`echo $$f | perl -pe \
	  	's/(lib|spamd)\///; s/\//::/g; s/\.(pod|pm)//;'`.html ; \
	      pod2text $$f > doc/`echo $$f | perl -pe \
	  	's/(lib|spamd)\///; s/\//::/g; s/\.(pod|pm)//;'`.txt ; \
	done
	touch doc/.made

};
}
