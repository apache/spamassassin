require 5.005;

# RPM builders, or people building in their home dirs:
#
# VARIABLE                DEFAULT
# -------------           -----------------
# PREFIX               *  /usr
# INST_PREFIX          +  $PREFIX
# SYSCONFDIR           *  /etc
# INST_SYSCONFDIR      +  $SYSCONFDIR
# PKG_DEF_RULES_DIR    *  $DEF_RULES_DIR or $(PREFIX)/share/spamassassin
# DEF_RULES_DIR        +  $(INST_PREFIX)/share/spamassassin
# PKG_LOCAL_RULES_DIR  *  $LOCAL_RULES_DIR
#                         or $(SYSCONFDIR)/mail/spamassassin
# LOCAL_RULES_DIR      +  $(INST_SYSCONFDIR)/mail/spamassassin
# INST_SITELIB	       +  $(INSTALLSITELIB)
#
# RUN_RAZOR1_TESTS        (prompt if Razor 1 found)
# RUN_RAZOR2_TESTS        (prompt if Razor 2 found)
#
# PERL_BIN             *  current path to Perl
# PERL_VERSION         *  current Perl version
# PERL_WARN            *  'yes' for CVS builds; else 'no'
#
# * means the variable is used for build time
# + means the variable is used for run time
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
# running that yourself first. But this should not be necessary.
#
# The Razor prompts ("run Razor 1 tests?" and "run Razor 2 tests?"
# can be overridden by setting RUN_RAZOR1_TESTS or RUN_RAZOR2_TESTS to
# "y" or "n".
#
###########################################################################

use strict;
use Config;
use ExtUtils::MakeMaker;

$ExtUtils::MakeMaker::Recognized_Att_Keys{'INST_PREFIX'} = 1;
$ExtUtils::MakeMaker::Recognized_Att_Keys{'SYSCONFDIR'} = 1;
$ExtUtils::MakeMaker::Recognized_Att_Keys{'INST_SYSCONFDIR'} = 1;
$ExtUtils::MakeMaker::Recognized_Att_Keys{'DEF_RULES_DIR'} = 1;
$ExtUtils::MakeMaker::Recognized_Att_Keys{'PKG_DEF_RULES_DIR'} = 1;
$ExtUtils::MakeMaker::Recognized_Att_Keys{'LOCAL_RULES_DIR'} = 1;
$ExtUtils::MakeMaker::Recognized_Att_Keys{'PKG_LOCAL_RULES_DIR'} = 1;
$ExtUtils::MakeMaker::Recognized_Att_Keys{'INST_SITELIB'} = 1;

$ExtUtils::MakeMaker::Recognized_Att_Keys{'RUN_RAZOR1_TESTS'} = 1;
$ExtUtils::MakeMaker::Recognized_Att_Keys{'RUN_RAZOR2_TESTS'} = 1;

$ExtUtils::MakeMaker::Recognized_Att_Keys{'PERL_BIN'} = 1;
$ExtUtils::MakeMaker::Recognized_Att_Keys{'PERL_WARN'} = 1;
$ExtUtils::MakeMaker::Recognized_Att_Keys{'PERL_VERSION'} = 1;

use constant RUNNING_ON_WINDOWS => ($^O =~ /^(?:mswin|dos|os2)/oi);


# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

my $mm_version = $ExtUtils::MakeMaker::VERSION;

# Gather the rules files in the range 00-69; we do this in perl because it's more portable
my @rulesfiles = map { s,^rules/,,; $_ } (<rules/*.cf>);
my $rulesfiles = join(' ', (grep { /^[0-6][0-9]_/ } @rulesfiles), qw(user_prefs.template triplets.txt languages)); 

# Only build spamd and spamc on non-Windows platforms
my @SPAMD_EXE_FILES = ();
if (!RUNNING_ON_WINDOWS) {
  @SPAMD_EXE_FILES = ('spamd/spamc$(EXE_EXT)', 'spamd/spamd');
}

my %makefile = (
    'NAME'	=> 'Mail::SpamAssassin',
    'VERSION_FROM' => 'lib/Mail/SpamAssassin.pm', # finds $VERSION

    'EXE_FILES'	=> [
			'spamassassin', 'sa-learn',
			@SPAMD_EXE_FILES
		],

    'MAN1PODS' => { 
	'spamassassin'    => '$(INST_MAN1DIR)/spamassassin.$(MAN1EXT)',
	'sa-learn'        => '$(INST_MAN1DIR)/sa-learn.$(MAN1EXT)',
	'spamd/spamc.pod' => '$(INST_MAN1DIR)/spamc.$(MAN1EXT)',
	'spamd/spamd'     => '$(INST_MAN1DIR)/spamd.$(MAN1EXT)',
    },

    'PL_FILES' => { },

    'PMLIBDIRS' => [ 'lib' ],

    'PM_FILTER' => '$(PERL) build/preprocessor -Mconditional $(FIXBYTES) -Mvars -DVERSION="$(VERSION)" -DPREFIX="$(INST_PREFIX)"',

    'macro' => {
	RULES => $rulesfiles,
    },

    # be quite explicit about this; afaik CPAN.pm is sensible using this
    'PREREQ_PM' => {
	'ExtUtils::MakeMaker' => 5.45 *0, # we have compatibility code in build/preprocessor.pm
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
	'pod2htm* spamassassin sa-learn '.
	'spamd/spamc$(EXE_EXT) spamd/libspamc.so spamd/spamd doc '.
	'spamd/sslspamc$(EXE_EXT) spamd/libsslspamc.so '.
	'binaries.mk config.h config.status config.cache config.log '.
	'qmail/qmail-spamc '
    },

    'AUTHOR' => 'Justin Mason <jm@jmason.org>',

		  #----------------------------------------
    'ABSTRACT' => 'identify spam mail using text analysis',

);

# MakeMaker prior to 5.45 doesn't support PM_FILTER, so we have to implement it ourselves
if($mm_version < 5.45) {
warn <<ITSALLSOSTUPID;

Your version of ExtUtils::MakeMaker is a pre-5.45. We need to include a
nasty workaround to make it work with our make routines. You will get
loads of warnings and it is very likely to break at various places.

*Please* consider updating to a version later than 5.45. It's available
on CPAN <http://search.cpan.org/search?module=ExtUtils::MakeMaker>.

Hint: Perl 5.6.1 and older ship good versions of ExtUtils::MakeMaker;

If anything breaks while building Mail::SpamAssassin, please file a bug
at <http://bugzilla.spamassassin.org>.

ITSALLSOSTUPID

  $makefile{SKIP} = [ 'pm_to_blib' ];
  $makefile{macro}{PM_FILTER} = $makefile{PM_FILTER};
  delete $makefile{PM_FILTER};
}

# All the $(*MAN1*) stuff is empty/zero if Perl was Configured with -Dman1dir=none
unless($Config{installman1dir}) {
  delete $makefile{MAN1PODS};
}

WriteMakefile(%makefile);


#######################################################################

unlink('t/do_razor', 't/do_razor2');
my $runrazor1tests = 0;
my $runrazor2tests = 0;

# what a PITA.  we can't get at MakeMaker's parsed args. do it ourselves,
# again....
$_ = join (' ', @ARGV);
if (/\bRUN_RAZOR1_TESTS=y/) { $runrazor1tests = 1; }
elsif (/\bRUN_RAZOR1_TESTS=n/) { $runrazor1tests = 0; }
elsif (eval { require Razor::Client }) {
  if (prompt('Run Razor v1 tests (these may fail due to network problems)? (y/n)', "n") =~ /^y(es)?$/i)
				{ $runrazor1tests = 1; }
}

$_ = join (' ', @ARGV); # again; never know what prompt() might do
if (/\bRUN_RAZOR2_TESTS=y/) { $runrazor2tests = 1; }
elsif (/\bRUN_RAZOR2_TESTS=n/) { $runrazor2tests = 0; }
elsif (eval { require Razor2::Client::Agent }) {
  if (prompt('Run Razor v2 tests (these may fail due to network problems)? (y/n)', "n") =~ /^y(es)?$/i)
				{ $runrazor2tests = 1; }
}

if ($runrazor1tests) { open(FILE, ">t/do_razor"); close(FILE); }
if ($runrazor2tests) { open(FILE, ">t/do_razor2"); close(FILE); }

#######################################################################

package MY;

sub MY::libscan {
  my($self,$path) = @_;

  return '' if ($path =~ /windows_install/ || $path =~ /\.(orig|diff|patch|bak|backup|my)$/i);
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

  my $instprefix = $self->{INST_PREFIX} || $self->{PREFIX};
  my $sysconfdir  = $self->{SYSCONFDIR}      || '/etc';
  my $instsysconfdir = $self->{INST_SYSCONFDIR} || $sysconfdir;
  my $pkgdefrulesdir = $self->{PKG_DEF_RULES_DIR} || $self->{DEF_RULES_DIR}
    || '$(PREFIX)/share/spamassassin';
  my $defrulesdir = $self->{DEF_RULES_DIR}
    || '$(INST_PREFIX)/share/spamassassin';
  my $pkglocalrulesdir = $self->{PKG_LOCAL_RULES_DIR}
    || $self->{LOCAL_RULES_DIR} || '$(SYSCONFDIR)/mail/spamassassin';
  my $localrulesdir = $self->{LOCAL_RULES_DIR} || '$(INST_SYSCONFDIR)/mail/spamassassin';
  my $instsitelib = $self->{INST_SITELIB} || '$(INSTALLSITELIB)';
  
  my $perl_bin     = $self->{PERL_BIN}     || 'this';
  my $perl_warn    = $self->{PERL_WARN}    || 'auto';
  my $perl_version = $self->{PERL_VERSION} || 'this';


  my $gotpods = keys(%{$self->{MAN1PODS}}) || keys(%{$self->{MAN3PODS}}) || keys(%{$self->{EXTRAPODS}}) || 0;

qq#
INST_PREFIX     	= $instprefix
SYSCONFDIR      	= $sysconfdir
INST_SYSCONFDIR 	= $instsysconfdir
PKG_DEF_RULES_DIR 	= $pkgdefrulesdir
DEF_RULES_DIR		= $defrulesdir
PKG_LOCAL_RULES_DIR	= $pkglocalrulesdir
LOCAL_RULES_DIR		= $localrulesdir
INST_SITELIB		= $instsitelib

PERL_BIN		= $perl_bin
PERL_WARN		= $perl_warn
PERL_VERSION 		= $perl_version

# . q#

FIXVARS		= -Mvars \
		  -DVERSION="$(VERSION)" \
		  -DPREFIX="$(INST_PREFIX)" \
		  -DDEF_RULES_DIR="$(DEF_RULES_DIR)" \
		  -DLOCAL_RULES_DIR="$(LOCAL_RULES_DIR)" \
		  -DINSTALLSITELIB="$(INST_SITELIB)"

FIXBYTES	= -Mbytes \
		  -DPERL_VERSION="$(PERL_VERSION)"
                  
FIXBANG		= -Msharpbang \
		  -DPERL_BIN="$(PERL_BIN)" \
		  -DPERL_WARN="$(PERL_WARN)"

SPAMC_SOURCES = spamd/spamc.c qmail/qmail-spamc.c spamd/libspamc.c spamd/utils.c

# . ($mm_version < 5.45 ? q#
pm_to_blib: $(TO_INST_PM)
	@ $(PERL) "-I$(INST_ARCHLIB)" "-I$(INST_LIB)" \
	"-I$(PERL_ARCHLIB)" "-I$(PERL_LIB)" -Ibuild \
	-MExtUtils::Install -Mpreprocessor \
	-e "ExtUtils::Install::Post545::pm_to_blib({qw{$(PM_TO_BLIB)}}, '$(INST_LIB)/auto', '$(PM_FILTER)')"# : '') . q#

spamassassin: spamassassin.raw
	$(PERL) build/preprocessor $(FIXBYTES) $(FIXVARS) $(FIXBANG) -i$? -o$@
	$(CHMOD) $(PERM_RWX) $@

sa-learn: sa-learn.raw
	$(PERL) build/preprocessor $(FIXBYTES) $(FIXVARS) $(FIXBANG) -i$? -o$@
	$(CHMOD) $(PERM_RWX) $@

spamd/spamd: spamd/spamd.raw
	$(PERL) build/preprocessor $(FIXBYTES) $(FIXVARS) $(FIXBANG) -i$? -o$@
	$(CHMOD) $(PERM_RWX) $@

spamd/libspamc.so: binaries.mk $(SPAMC_SOURCES)
	$(MAKE) -f binaries.mk $@

spamd/libspamc.dll: binaries.mk $(SPAMC_SOURCES)
	$(MAKE) -f binaries.mk $@

spamd/spamc$(EXE_EXT): binaries.mk $(SPAMC_SOURCES)
	$(MAKE) -f binaries.mk $@

spamd/libsslspamc.so: binaries.mk $(SPAMC_SOURCES)
	$(MAKE) -f binaries.mk $@

spamd/libsslspamc.dll: binaries.mk $(SPAMC_SOURCES)
	$(MAKE) -f binaries.mk $@

spamd/sslspamc$(EXE_EXT): binaries.mk $(SPAMC_SOURCES)
	$(MAKE) -f binaries.mk $@

qmail/qmail-spamc: binaries.mk $(SPAMC_SOURCES)
	$(MAKE) -f binaries.mk $@

binaries.mk: configure
	./configure

inst_cfs: $(PKG_LOCAL_RULES_DIR) $(PKG_LOCAL_RULES_DIR)/local.cf
	$(MKPATH) $(PKG_DEF_RULES_DIR)
	$(RM_RF) $(PKG_DEF_RULES_DIR)/*
	$(PERL) build/preprocessor $(FIXVARS) -Irules -O$(PKG_DEF_RULES_DIR) $(RULES)
	$(CHMOD) $(PERM_RWX) $(PKG_DEF_RULES_DIR)

$(PKG_LOCAL_RULES_DIR):
	$(MKPATH) $@

$(PKG_LOCAL_RULES_DIR)/local.cf: rules/local.cf
	$(PERL) -e "use File::Copy; (-f '$@') or copy ('$?', '$@');"

text_html_doc: made-doc-stamp
	$(NOOP)

doc:
	$(MKPATH) $@

made-doc-stamp: doc#. ($gotpods ? q# $(MAN1PODS) $(MAN3PODS) $(EXTRAPODS)
	$(PERL) build/convert_pods_to_doc $(MAN1PODS) $(MAN3PODS) $(EXTRAPODS)
	# : '') . q#
	$(TOUCH) made-doc-stamp
	$(RM_F) pod2htm*

#;

}
