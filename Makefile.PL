require 5.005;

# RPM builders, or people building in their home dirs:
# set PREFIX (default = /usr)
# set SYSCONFDIR (default = /etc)
# e.g. "perl Makefile.PL PREFIX=/home/jm/sausr SYSCONFDIR=/home/jm/saetc"
#
# You can also override the automatic ./configure step by just
# running that yourself first.
#
# The Razor prompts ("run Razor 1 tests?" and "run Razor 2 tests?"
# can be overridden by setting RUN_RAZOR1_TESTS or RUN_RAZOR2_TESTS to
# "y" or "n".
#
###########################################################################

use strict;
use Config;
use ExtUtils::MakeMaker;

$ExtUtils::MakeMaker::Recognized_Att_Keys{'SYSCONFDIR'} = 1;
$ExtUtils::MakeMaker::Recognized_Att_Keys{'DEF_RULES_DIR'} = 1;
$ExtUtils::MakeMaker::Recognized_Att_Keys{'LOCAL_RULES_DIR'} = 1;
$ExtUtils::MakeMaker::Recognized_Att_Keys{'RUN_RAZOR1_TESTS'} = 1;
$ExtUtils::MakeMaker::Recognized_Att_Keys{'RUN_RAZOR2_TESTS'} = 1;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

my $mm_version = $ExtUtils::MakeMaker::VERSION;

# Gather the rules files in the range 00-69; we do this in perl because it's more portable
my @rulesfiles = map { s,^rules/,,; $_ } (<rules/*.cf>);
my $rulesfiles = join(' ', (grep { /^[0-6][0-9]_/ } @rulesfiles), qw(user_prefs.template triplets.txt languages)); 


my %makefile = (
    'NAME'	=> 'Mail::SpamAssassin',
    'VERSION_FROM' => 'lib/Mail/SpamAssassin.pm', # finds $VERSION

    'EXE_FILES'	=> [ 'spamassassin', 'spamd/spamc$(EXE_EXT)', 'spamd/spamd',
			'sa-learn-spam', 'sa-learn-nonspam', 'sa-forget'
		],

    'MAN1PODS' => { 
	'spamassassin'    => '$(INST_MAN1DIR)/spamassassin.$(MAN1EXT)',
	'sa-learn-spam'    => '$(INST_MAN1DIR)/sa-learn-spam.$(MAN1EXT)',
	'sa-learn-nonspam'    => '$(INST_MAN1DIR)/sa-learn-nonspam.$(MAN1EXT)',
	'sa-forget'    => '$(INST_MAN1DIR)/sa-forget.$(MAN1EXT)',
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
	'pod2htm* spamassassin sa-forget sa-learn-spam sa-learn-nonspam '.
	'spamd/spamc$(EXE_EXT) spamd/libspamc.so spamd/spamd doc '.
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
	@ $(PERL) "-I$(INST_ARCHLIB)" "-I$(INST_LIB)" \
	"-I$(PERL_ARCHLIB)" "-I$(PERL_LIB)" -Ibuild \
	-MExtUtils::Install -Mpreprocessor \
	-e "ExtUtils::Install::Post545::pm_to_blib({qw{$(PM_TO_BLIB)}}, '$(INST_LIB)/auto', '$(PM_FILTER)')"# : '') . q#

spamassassin: spamassassin.raw
	$(PERL) build/preprocessor $(FIXVARS) -Msharpbang -i$? -o$@
	$(CHMOD) $(PERM_RWX) $@

sa-learn-spam: sa-learn-spam.raw
	$(PERL) build/preprocessor $(FIXVARS) -Msharpbang -i$? -o$@
	$(CHMOD) $(PERM_RWX) $@

sa-learn-nonspam: sa-learn-nonspam.raw
	$(PERL) build/preprocessor $(FIXVARS) -Msharpbang -i$? -o$@
	$(CHMOD) $(PERM_RWX) $@

sa-forget: sa-forget.raw
	$(PERL) build/preprocessor $(FIXVARS) -Msharpbang -i$? -o$@
	$(CHMOD) $(PERM_RWX) $@

spamd/spamd: spamd/spamd.raw
	$(PERL) build/preprocessor $(FIXVARS) -Msharpbang -i$? -o$@
	$(CHMOD) $(PERM_RWX) $@

spamd/libspamc.so: binaries.mk
	$(MAKE) -f binaries.mk $@

spamd/spamc$(EXE_EXT): binaries.mk
	$(MAKE) -f binaries.mk $@

binaries.mk: configure
	./configure

inst_cfs: $(LOCAL_RULES_DIR) $(LOCAL_RULES_DIR)/local.cf
	$(RM_RF) $(DEF_RULES_DIR)
	$(MKPATH) $(DEF_RULES_DIR)
	$(PERL) build/preprocessor $(FIXVARS) -Irules -O$(DEF_RULES_DIR) $(RULES)
	$(CHMOD) $(PERM_RWX) $(DEF_RULES_DIR)

$(LOCAL_RULES_DIR):
	$(MKPATH) $@

$(LOCAL_RULES_DIR)/local.cf: rules/local.cf
	$(PERL) -e 'use File::Copy; (-f "$@") or copy ("$?", "$@");'

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
