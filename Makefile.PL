require 5.005;

# RPM builders, or people building in their home dirs:
# set PREFIX (default = /usr)
# set SYSCONFDIR (default = /etc)
# e.g. "perl Makefile.PL PREFIX=/home/jm/sausr SYSCONFDIR=/home/jm/saetc"
#
# You can also override the automatic ./configure step by just
# running that yourself first.
#
###########################################################################

use strict;
use Config;
use ExtUtils::MakeMaker;

$ExtUtils::MakeMaker::Recognized_Att_Keys{'SYSCONFDIR'} = 1;
$ExtUtils::MakeMaker::Recognized_Att_Keys{'DEF_RULES_DIR'} = 1;
$ExtUtils::MakeMaker::Recognized_Att_Keys{'LOCAL_RULES_DIR'} = 1;


# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

my $mm_version = $ExtUtils::MakeMaker::VERSION;

# Gather the rules files in the range 00-69; we do this in perl because it's more portable
my @rulesfiles = map { s,^rules/,,; $_ } (<rules/*.cf>);
my $rulesfiles = join(' ', (grep { /^[0-6][0-9]_/ } @rulesfiles), qw(user_prefs.template triplets.txt languages)); 


my %makefile = (
    'NAME'	=> 'Mail::SpamAssassin',
    'VERSION_FROM' => 'lib/Mail/SpamAssassin.pm', # finds $VERSION

    'EXE_FILES'	=> [ 'spamassassin', 'spamd/spamc$(EXE_EXT)', 'spamd/spamd' ],

    'MAN1PODS' => { 
        'spamassassin'    => '$(INST_MAN1DIR)/spamassassin.$(MAN1EXT)',
        'spamd/spamc.pod' => '$(INST_MAN1DIR)/spamc.$(MAN1EXT)',
        'spamd/spamd'     => '$(INST_MAN1DIR)/spamd.$(MAN1EXT)',
    },

    'PL_FILES' => { },

    'PMLIBDIRS' => [ 'lib' ],
   
    'PM_FILTER' => '$(PERL) build/preprocessor -Mconditional -Mvars -DVERSION=$(VERSION) -DPREFIX="$(PREFIX)"',

    'macro' => {
        RULES => $rulesfiles,
    },

    # be quite explicit about this; afaik CPAN.pm is sensible using this
    'PREREQ_PM' => {
                        'ExtUtils::MakeMaker' => 5.45,
                        'File::Spec' => 0.8,
                        'File::Copy' => 0,
                        'Pod::Usage' => 0,
                        'HTML::Parser' => 3.0,
                        'Text::Wrap' => 0,
                        'Time::Local' => 0,
                        'Errno' => 0,
                  },

    'dist' => {
      		COMPRESS => 'gzip -9f', SUFFIX => 'gz',
	      	DIST_DEFAULT => 'tardist'
	      },

    'clean' => { FILES =>
	'pod2htm* spamassassin spamd/spamc$(EXE_EXT) spamd/libspamc.so spamd/spamd doc '.
	'binaries.mk config.h config.status config.cache config.log'
    },

    'AUTHOR' => 'Justin Mason <jm@jmason.org>',

		  #----------------------------------------
    'ABSTRACT' => 'identify spam mail using text analysis',

);

# MakeMaker prior to 5.45 doesn't support PM_FILTER, so we have to implement it ourselves
if($mm_version < 5.45) {
  $makefile{SKIP} = [ 'pm_to_blib' ];
  $makefile{macro}{PM_FILTER} = $makefile{PM_FILTER};
  delete $makefile{PM_FILTER};
}

# All the $(*MAN1*) stuff is empty/zero if Perl was Configured with -Dman1dir=none
unless($Config{installman1dir}) {
  delete $makefile{MAN1PODS};
}

WriteMakefile(%makefile);


unlink('t/do_razor', 't/do_razor2');
if (eval { require Razor::Client }) {
  if (prompt('Run Razor v1 tests (these may fail due to network problems)? (y/n)', "n") =~ /^y(es)?$/i) {
    open(FILE, ">t/do_razor"); close(FILE);
  }
}
if (eval { require Razor2::Client::Agent }) {
  if (prompt('Run Razor v2 tests (these may fail due to network problems)? (y/n)', "n") =~ /^y(es)?$/i) {
    open(FILE, ">t/do_razor2"); close(FILE);
  }
}


#######################################################################

package MY;

sub MY::libscan {
  my($self,$path) = @_;

  return '' if ($path !~ /\.pm$/ && $path !~ /spamc/);
  return $path;
}

sub MY::install {
  my $self = shift;
  my $inherited = $self->SUPER::install (@_);

  $inherited =~ s/^(install :: .*)$/$1 inst_cfs/gm;
  $inherited;
}

sub MY::postamble {
  # import some C-linkage stuff from %Config.  We can't seem to
  # do this with MakeMaker without it trying to build the perl
  # modules as .so's :(

  my $self = shift;

  my $sysconfdir  = $self->{SYSCONFDIR}      || '/etc';
  my $defrulesdir = $self->{DEF_RULES_DIR}   || '$(PREFIX)/share/spamassassin';
  my $locrulesdir = $self->{LOCAL_RULES_DIR} || '$(SYSCONFDIR)/mail/spamassassin';

  my $gotpods = keys(%{$self->{MAN1PODS}}) || keys(%{$self->{MAN3PODS}}) || keys(%{$self->{EXTRAPODS}}) || 0;

qq#
SYSCONFDIR      = $sysconfdir
DEF_RULES_DIR	= $defrulesdir
LOCAL_RULES_DIR	= $locrulesdir
# . q#

FIXVARS		= -Mvars \
		  -DVERSION="$(VERSION)" \
		  -DPREFIX="$(PREFIX)" \
		  -DDEF_RULES_DIR="$(DEF_RULES_DIR)" \
		  -DLOCAL_RULES_DIR="$(LOCAL_RULES_DIR)" \
		  -DINSTALLSITELIB="$(INSTALLSITELIB)"

# . ($mm_version < 5.45 ? q#
pm_to_blib: $(TO_INST_PM)
	@$(PERL) "-I$(INST_ARCHLIB)" "-I$(INST_LIB)" \
        "-I$(PERL_ARCHLIB)" "-I$(PERL_LIB)" -Ibuild \
	-MExtUtils::Install -Mpreprocessor \
	-e "ExtUtils::Install::Post545::pm_to_blib({qw{$(PM_TO_BLIB)}}, '$(INST_LIB)/auto', '$(PM_FILTER)')"# : '') . q#

spamassassin: spamassassin.raw
	$(PERL) build/preprocessor $(FIXVARS) -Msharpbang <$? >$@
	$(CHMOD) $(PERM_RWX) $@

spamd/spamd: spamd/spamd.raw
	$(PERL) build/preprocessor $(FIXVARS) -Msharpbang <$? >$@
	$(CHMOD) $(PERM_RWX) $@

spamd/libspamc.so: binaries.mk
	$(MAKE) -f binaries.mk $@

spamd/spamc$(EXE_EXT): binaries.mk
	$(MAKE) -f binaries.mk $@

binaries.mk: configure
	./configure

inst_cfs: $(DEF_RULES_DIR) $(LOCAL_RULES_DIR) $(LOCAL_RULES_DIR)/local.cf
	$(RM_F) $(DEF_RULES_DIR)/*; \
	for file in $(RULES) ; do \
	  $(PERL) build/preprocessor $(FIXVARS) <rules/$$file >$(DEF_RULES_DIR)/$$file; \
	done
	$(CHMOD) $(PERM_RW) $(DEF_RULES_DIR)/*

$(DEF_RULES_DIR):
	$(MKPATH) $@

$(LOCAL_RULES_DIR):
	$(MKPATH) $@

$(LOCAL_RULES_DIR)/local.cf: rules/local.cf
	test -f $@ || \
	  $(CP) rules/local.cf $@

text_html_doc: doc/.made
	@true

doc:
	$(MKPATH) $@

doc/.made: doc#. ($gotpods ? q# $(MAN1PODS) $(MAN3PODS) $(EXTRAPODS)
	for f in $(MAN1PODS) $(MAN3PODS) $(EXTRAPODS) ; do \
	      echo Converting POD in $$f; \
	      pod2html $$f > doc/`echo $$f | $(PERL) -pe \
	        's,^(lib|spamd)/|\.(pod|pm)$$,,g; tr,/,_,;'`.html ; \
	      pod2text $$f > doc/`echo $$f | $(PERL) -pe \
	        's,^(lib|spamd)/|\.(pod|pm)$$,,g; tr,/,_,;'`.txt ; \
	done# : '') . q#
	touch doc/.made
	$(RM_F) pod2htm*

#;

}
