require 5.005;

my $DEF_RULES_DIR	= '$(PREFIX)/share/spamassassin';

my $LOCAL_RULES_DIR	= '/etc/mail/spamassassin';

my $MYCFLAGS		= '';		# this is a good place to put -g etc.

###########################################################################

use Config;
use ExtUtils::MakeMaker;

# do this in perl, it's more portable
my $rulesfiles = join (' ', map { s/rules.//; $_ } (<rules/*.cf>));
$rulesfiles =~ s/local\.cf//;

$rulesfiles .= " triplets.txt";

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
    		'spamd/spamd', 'spamproxy/spamproxyd' ],

    'MAN1PODS' => {
	    'spamassassin' => '$(INST_MAN1DIR)/spamassassin.$(MAN1EXT)',
	    'spamd/spamc.pod' => '$(INST_MAN1DIR)/spamc.$(MAN1EXT)',
	    'spamd/spamd' => '$(INST_MAN1DIR)/spamd.$(MAN1EXT)',
	    'spamproxy/spamproxyd' => '$(INST_MAN1DIR)/spamproxyd.$(MAN1EXT)',
    },

    'PL_FILES' => '',

    'PMLIBDIRS' => [ 'lib' ],

    'PREREQ_PM' => {
                        'File::Copy' => 0,
                  },

    'dist' => {
      		COMPRESS => 'gzip -9f', SUFFIX => 'gz',
	      	DIST_DEFAULT => 'tardist'
	      },

    'clean' => { FILES =>
	'pod2htm* spamassassin spamd/spamc spamd/spamd spamproxy/spamproxyd doc'
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

RULES		= $rulesfiles

CFCC		= $Config{cc}
CFCCFLAGS	= $Config{ccflags} $MYCFLAGS
CFOPTIMIZE	= $Config{optimize}
CFLIBS		= $Config{libs}
CFLDFLAGS	= $Config{ldflags}

DEF_RULES_DIR	= $DEF_RULES_DIR
LOCAL_RULES_DIR	= $LOCAL_RULES_DIR

}. q{

pm_to_blib: spamassassin doc/.made

spamassassin: spamassassin.raw
	$(PERL) fixpath.pl spamassassin.raw $@
	$(CHMOD) $(PERM_RWX) $@

spamd/spamd: spamd/spamd.raw
	$(PERL) fixpath.pl spamd/spamd.raw $@
	$(CHMOD) $(PERM_RWX) $@

spamproxy/spamproxyd: spamproxy/spamproxyd.raw
	$(PERL) fixpath.pl spamproxy/spamproxyd.raw $@
	$(CHMOD) $(PERM_RWX) $@

spamd/spamc: spamd/spamc.c
	$(CFCC) $(CFCCFLAGS) $(CFOPTIMIZE) spamd/spamc.c \
			-o $@ $(CFLDFLAGS) $(CFLIBS)

inst_cfs: $(LOCAL_RULES_DIR) $(DEF_RULES_DIR) $(DEF_RULES_DIR)/user_prefs.template $(LOCAL_RULES_DIR)/local.cf migrate_cfs
	for file in $(RULES) ; do \
	  $(CP) rules/$$file $(DEF_RULES_DIR)/$$file; \
	done

$(DEF_RULES_DIR)/user_prefs.template: rules/user_prefs.template
	$(CP) rules/user_prefs.template $(DEF_RULES_DIR)/user_prefs.template

$(LOCAL_RULES_DIR)/local.cf: rules/local.cf
	[ -f $(LOCAL_RULES_DIR)/local.cf ] || $(CP) rules/local.cf $(LOCAL_RULES_DIR)/local.cf

migrate_cfs:
	[ ! -f /etc/spamassassin.cf ] || $(MV) /etc/spamassassin.cf /etc/mail/spamassassin/migrated.cf
	[ ! -f /etc/mail/spamassassin.cf ] || $(MV) /etc/mail/spamassassin.cf /etc/mail/spamassassin/migrated.cf

$(DEF_RULES_DIR):
	mkdir -p $(DEF_RULES_DIR)

$(LOCAL_RULES_DIR):
	mkdir -p $(LOCAL_RULES_DIR)

doc:
	mkdir -p doc

text_html_doc: doc/.made
	@true

doc/.made: doc $(MAN1PODS) $(MAN3PODS)
	for f in $(MAN1PODS) $(MAN3PODS) $(EXTRAPODS) ; do \
	      pod2html $$f > doc/`echo $$f | perl -pe \
	  	's/(lib|spamd)\///; s/\//_/g; s/\.(pod|pm)//;'`.html ; \
	      pod2text $$f > doc/`echo $$f | perl -pe \
	  	's/(lib|spamd)\///; s/\//_/g; s/\.(pod|pm)//;'`.txt ; \
	done
	touch doc/.made
	-rm -f pod2htm*

};
}
