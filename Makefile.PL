require 5.005;

# RPM builders, or people building in their home dirs:
# set PREFIX (default = /usr)
# set SYSCONFDIR (default = /etc)
# set INST_PREFIX (default = [same as PREFIX])
# set INST_SYSCONFDIR (default = [same as SYSCONFDIR])
#
# For example, to install in your home dir:
#
#   perl Makefile.PL PREFIX=/home/jm/sausr SYSCONFDIR=/home/jm/saetc
#
# Or to build a package in /tmp/build, but with its internal paths
# referring to /usr and /etc:
#
#   perl Makefile.PL PREFIX=/tmp/build/usr SYSCONFDIR=/tmp/build/etc \
#                       INST_PREFIX=/usr INST_SYSCONFDIR=/etc
#
# You can also override the automatic ./configure step by just
# running that yourself first.  But the plan is that this should not
# be necessary.

###########################################################################

$ExtUtils::MakeMaker::Recognized_Att_Keys{'SYSCONFDIR'} = 1;
$ExtUtils::MakeMaker::Recognized_Att_Keys{'INST_SYSCONFDIR'} = 1;
$ExtUtils::MakeMaker::Recognized_Att_Keys{'INST_PREFIX'} = 1;

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

# All the $(*MAN1*) stuff is empty/zero if Perl was Configured with -Dman1dir=none
my %man1pods = (
  'spamassassin'    => '$(INST_MAN1DIR)/spamassassin.$(MAN1EXT)',
  'spamd/spamc.pod' => '$(INST_MAN1DIR)/spamc.$(MAN1EXT)',
  'spamd/spamd'     => '$(INST_MAN1DIR)/spamd.$(MAN1EXT)',
) if ($Config{installman1dir});

WriteMakefile(
    'NAME'	=> 'Mail::SpamAssassin',
    'VERSION_FROM' => 'lib/Mail/SpamAssassin.pm', # finds $VERSION

    'EXE_FILES'	=> [ 'spamassassin', 'spamd/spamc$(EXE_EXT)', 'spamd/spamd' ],

    'MAN1PODS' => { %man1pods },

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
	'pod2htm* spamassassin spamd/spamc$(EXE_EXT) spamd/libspamc.so spamd/spamd doc '.
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

  my $instsysconfdir = $self->{INST_SYSCONFDIR};
  $instsysconfdir ||= $sysconfdir;

  my $instprefix = $self->{INST_PREFIX};
  $instprefix ||= $self->{PREFIX};

  my $gotpods = keys(%{$self->{MAN1PODS}}) || keys(%{$self->{MAN3PODS}}) || keys(%{$self->{EXTRAPODS}}) || 0;


qq#

RULES		= $rulesfiles
SYSCONFDIR      = $sysconfdir
INST_SYSCONFDIR = $instsysconfdir
INST_PREFIX     = $instprefix

#. q#

DEF_RULES_DIR           = $(INST_PREFIX)/share/spamassassin
PKG_DEF_RULES_DIR	= $(PREFIX)/share/spamassassin

LOCAL_RULES_DIR         = $(INST_SYSCONFDIR)/mail/spamassassin
PKG_LOCAL_RULES_DIR	= $(SYSCONFDIR)/mail/spamassassin

FIXVARS		= -Mvars \
		  -DVERSION="$(VERSION)" \
		  -DPREFIX="$(INST_PREFIX)" \
		  -DDEF_RULES_DIR="$(DEF_RULES_DIR)" \
		  -DLOCAL_RULES_DIR="$(LOCAL_RULES_DIR)" \
		  -DINSTALLSITELIB="$(INSTALLSITELIB)"

pm_to_blib: spamassassin doc/.made

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

inst_cfs: $(PKG_DEF_RULES_DIR) $(PKG_LOCAL_RULES_DIR) $(PKG_LOCAL_RULES_DIR)/local.cf
	$(RM_F) $(PKG_DEF_RULES_DIR)/*; \
	for file in $(RULES) ; do \
	  $(PERL) build/preprocessor $(FIXVARS) <rules/$$file >$(PKG_DEF_RULES_DIR)/$$file; \
	done
	$(CHMOD) $(PERM_RW) $(PKG_DEF_RULES_DIR)/*

$(PKG_DEF_RULES_DIR):
	$(MKPATH) $@

$(PKG_LOCAL_RULES_DIR):
	$(MKPATH) $@

$(PKG_LOCAL_RULES_DIR)/local.cf: rules/local.cf
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
