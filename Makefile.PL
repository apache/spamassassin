require 5.005;

# RPM builders, or people building in their home dirs:
# set PREFIX (default = /usr)
# set SYSCONFDIR (default = /etc)
# e.g. "perl Makefile.PL PREFIX=/home/jm/sausr SYSCONFDIR=/home/jm/saetc"
#
# You can also override the automatic ./configure step by just
# running that yourself first.

###########################################################################

$ExtUtils::MakeMaker::Recognized_Att_Keys{'SYSCONFDIR'} = 1;

use Config;
use ExtUtils::MakeMaker;

# do this in perl, it's more portable
my @rulesfiles = map { substr($_, 6) } (<rules/*.cf>);
my $rulesfiles = join(' ', grep { /^[0-6][0-9]_/ } @rulesfiles); # Include only .cfs in the range 00-69
$rulesfiles   .= " user_prefs.template triplets.txt languages";

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

    'EXE_FILES'	=> [ 'spamassassin', 'spamd/spamc',
    		'spamd/spamd', ],

    'MAN1PODS' => {
	    'spamassassin' => '$(INST_MAN1DIR)/spamassassin.$(MAN1EXT)',
	    'spamd/spamc.pod' => '$(INST_MAN1DIR)/spamc.$(MAN1EXT)',
	    'spamd/spamd' => '$(INST_MAN1DIR)/spamd.$(MAN1EXT)',
    },

    'PL_FILES' => { },

    'PMLIBDIRS' => [ 'lib' ],

    # be quite explicit about this; afaik CPAN.pm is sensible using this
    'PREREQ_PM' => {
                        'File::Spec' => 0.8,
                        'File::Copy' => 0,
                        'Pod::Usage' => 0,
                        'HTML::Parser' => 3.0,
                        'Text::Wrap' => 0,
                        'Time::Local' => 0,
                  },

    'dist' => {
      		COMPRESS => 'gzip -9f', SUFFIX => 'gz',
	      	DIST_DEFAULT => 'tardist'
	      },

    'clean' => { FILES =>
	'pod2htm* spamassassin spamd/spamc spamd/libspamc.so spamd/spamd doc '.
	'binaries.mk config.h config.status config.cache config.log'
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

  package MY;
  my $self = shift;

  my $sysconfdir = $self->{SYSCONFDIR};
  $sysconfdir ||= '/etc';

qq#

RULES		= $rulesfiles
SYSCONFDIR      = $sysconfdir

#. q#

DEF_RULES_DIR	= $(PREFIX)/share/spamassassin
LOCAL_RULES_DIR	= $(SYSCONFDIR)/mail/spamassassin

FIXPATHFLAGS    = -DDEF_RULES_DIR="$(DEF_RULES_DIR)" \
		  -DLOCAL_RULES_DIR="$(LOCAL_RULES_DIR)" \
		  -DINSTALLSITELIB="$(INSTALLSITELIB)"

pm_to_blib: spamassassin doc/.made

spamassassin: spamassassin.raw
	$(PERL) fixpath.pl $(FIXPATHFLAGS) spamassassin.raw $@
	$(CHMOD) $(PERM_RWX) $@

spamd/spamd: spamd/spamd.raw
	$(PERL) fixpath.pl $(FIXPATHFLAGS) spamd/spamd.raw $@
	$(CHMOD) $(PERM_RWX) $@

spamd/libspamc.so: binaries.mk
	$(MAKE) -f binaries.mk $@

spamd/spamc: binaries.mk
	$(MAKE) -f binaries.mk $@

binaries.mk: configure
	./configure

inst_cfs: $(DEF_RULES_DIR) $(LOCAL_RULES_DIR) $(LOCAL_RULES_DIR)/local.cf
	$(RM_F) $(DEF_RULES_DIR)/*
	for file in $(RULES) ; do \
	  $(CP) rules/$$file $(DEF_RULES_DIR)/$$file; \
	done
	$(CHMOD) $(PERM_RW) $(DEF_RULES_DIR)/*

$(DEF_RULES_DIR):
	$(MKPATH) $@

$(LOCAL_RULES_DIR):
	$(MKPATH) $@

$(LOCAL_RULES_DIR)/local.cf: rules/local.cf
	test -e $@ || \
	  $(CP) rules/local.cf $@

text_html_doc: doc/.made
	@true

doc:
	$(MKPATH) $@

doc/.made: doc $(MAN1PODS) $(MAN3PODS)
	echo $(MAN1PODS) $(MAN3PODS)
	for f in $(MAN1PODS) $(MAN3PODS) $(EXTRAPODS) ; do \
	      pod2html $$f > doc/`echo $$f | $(PERL) -pe \
	        's/(lib|spamd)\///; tr/\//_/; s/\.(pod|pm)$$//;'`.html ; \
	      pod2text $$f > doc/`echo $$f | $(PERL) -pe \
	        's/(lib|spamd)\///; tr/\//_/; s/\.(pod|pm)$$//;'`.txt ; \
	done
	touch doc/.made
	$(RM_F) pod2htm*

#;

}
