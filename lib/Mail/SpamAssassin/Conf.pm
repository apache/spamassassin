#

package Mail::SpamAssassin::Conf;

use Carp;
use strict;

use vars	qw{
  	@ISA $type_body_tests $type_head_tests $type_head_evals
	$type_body_evals $type_full_tests $type_full_evals
};

@ISA = qw();

$type_head_tests = 101;
$type_head_evals = 102;
$type_body_tests = 103;
$type_body_evals = 104;
$type_full_tests = 105;
$type_full_evals = 106;

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = {
    'main' => shift,
  }; bless ($self, $class);

  $self->{tests} = { };
  $self->{descriptions} = { };
  $self->{test_types} = { };
  $self->{scores} = { };

  # after parsing, tests are refiled into these hashes for each test type.
  # this allows e.g. a full-text test to be rewritten as a body test in
  # the user's ~/.spamassassin.cf file.
  $self->{body_tests} = { };
  $self->{head_tests} = { };
  $self->{head_evals} = { };
  $self->{body_evals} = { };
  $self->{full_tests} = { };
  $self->{full_evals} = { };

  $self->{required_hits} = 5;
  $self->{auto_report_threshold} = 20;
  $self->{report_template} = '';
  $self->{terse_report_template} = '';
  $self->{spamtrap_template} = '';

  $self->{razor_config} = $self->{main}->sed_path ("~/razor.conf");

  # this will be sedded by whitelist implementations, so ~ is OK
  $self->{auto_whitelist_path} = "~/.spamassassin/auto-whitelist";
  $self->{auto_whitelist_file_mode} = '0700';	# as string, with --x bits

  $self->{auto_whitelist_threshold} = 3;
  $self->{rewrite_subject} = 1;
  $self->{report_header} = 0;
  $self->{use_terse_report} = 0;
  $self->{defang_mime} = 1;
  $self->{skip_rbl_checks} = 0;
  $self->{ok_locales} = '';

  $self->{whitelist_from} = { };
  $self->{blacklist_from} = { };
  $self->{whitelist_from_doms} = { };
  $self->{blacklist_from_doms} = { };

  $self->{whitelist_to} = { };
  $self->{whitelist_to_doms} = { };
  $self->{more_spam_to} = { };
  $self->{more_spam_to_doms} = { };
  $self->{all_spam_to} = { };
  $self->{all_spam_to_doms} = { };

  # this will hold the database connection params
  $self->{user_scores_dsn} = '';
  $self->{user_scores_sql_username} = '';
  $self->{user_scores_sql_passowrd} = '';

  $self->{_unnamed_counter} = 'aaaaa';

  $self;
}

sub mtime {
    my $self = shift;
    if (@_) {
	$self->{mtime} = shift;
    }
    return $self->{mtime};
}

###########################################################################

sub parse_scores_only {
  my ($self, $rules) = @_;
  $self->_parse ($rules, 1);
}

sub parse_rules {
  my ($self, $rules) = @_;
  $self->_parse ($rules, 0);
}

sub _parse {
  my ($self, $rules, $scoresonly) = @_;
  local ($_);

  foreach $_ (split (/\n/, $rules)) {
    s/\r//g; s/(^|(?<!\\))\#.*$/$1/;
    s/^\s+//; s/\s+$//; /^$/ and next;

    # note: no eval'd code should be loaded before the SECURITY line below.
    #
    if (/^whitelist[-_]from\s+(.+)\s*$/) {
      $self->add_to_addrlist ('whitelist_from',
      	'whitelist_from_doms', split (' ', $1)); next;
    }

    if (/^blacklist[-_]from\s+(.+)\s*$/) {
      $self->add_to_addrlist ('blacklist_from',
      	'blacklist_from_doms', split (' ', $1)); next;
    }

    ###############################################
    # added by DJ
    #
    if (/^whitelist[-_]to\s+(.+)\s*$/) {
      $self->add_to_addrlist ('whitelist_to',
              'whitelist_to_doms', split (' ', $1)); next;
    }

    if (/^more[-_]spam[-_]to\s+(.+)\s*$/) {
      $self->add_to_addrlist ('more_spam_to',
              'more_spam_to_doms', split (' ', $1)); next;
    }

    if (/^all[-_]spam[-_]to\s+(.+)\s*$/) {
      $self->add_to_addrlist ('all_spam_to',
              'all_spam_to_doms', split (' ', $1)); next;
    }

    ###############################################

    if (/^describe\s+(\S+)\s+(.*)$/) {
      $self->{descriptions}->{$1} = $2; next;
    }

    if (/^required[-_]hits\s+(\S+)$/) {
      $self->{required_hits} = $1+0; next;
    }

    if (/^score\s+(\S+)\s+(\-*[\d\.]+)$/) {
      $self->{scores}->{$1} = $2+0.0; next;
    }

    if (/^clear[-_]report[-_]template$/) {
      $self->{report_template} = ''; next;
    }

    if (/^report\b\s*(.*?)$/) {
      $self->{report_template} .= $1."\n"; next;
    }

    if (/^clear[-_]terse[-_]report[-_]template$/) {
      $self->{terse_report_template} = ''; next;
    }

    if (/^terse[-_]report\b\s*(.*?)$/) {
      $self->{terse_report_template} .= $1."\n"; next;
    }

    if (/^clear[-_]spamtrap[-_]template$/) {
      $self->{spamtrap_template} = ''; next;
    }

    if (/^spamtrap\s*(.*?)$/) {
      $self->{spamtrap_template} .= $1."\n"; next;
    }

    if (/^auto[-_]report[-_]threshold\s+(\d+)$/) {
      $self->{auto_report_threshold} = $1+0; next;
    }

    if (/^rewrite[-_]subject\s+(\d+)$/) {
      $self->{rewrite_subject} = $1+0; next;
    }

    if (/^report[-_]header\s+(\d+)$/) {
      $self->{report_header} = $1+0; next;
    }

    if (/^use[-_]terse[-_]report\s+(\d+)$/) {
      $self->{use_terse_report} = $1+0; next;
    }

    if (/^defang[-_]mime\s+(\d+)$/) {
      $self->{defang_mime} = $1+0; next;
    }

    if (/^skip[-_]rbl[-_]checks\s+(\d+)$/) {
      $self->{skip_rbl_checks} = $1+0; next;
    }

    if (/^ok[-_]locales\s+(.+)$/) {
      $self->{ok_locales} = $1; next;
    }

    # SECURITY: no eval'd code should be loaded before this line.
    #
    if ($scoresonly) { goto failed_line; }

    if (/^header\s+(\S+)\s+eval:(.*)$/) {
      $self->add_test ($1, $2, $type_head_evals); next;
    }
    if (/^header\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, $type_head_tests); next;
    }
    if (/^body\s+(\S+)\s+eval:(.*)$/) {
      $self->add_test ($1, $2, $type_body_evals); next;
    }
    if (/^body\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, $type_body_tests); next;
    }
    if (/^full\s+(\S+)\s+eval:(.*)$/) {
      $self->add_test ($1, $2, $type_full_evals); next;
    }
    if (/^full\s+(\S+)\s+(.*)$/) {
      $self->add_test ($1, $2, $type_full_tests); next;
    }

    if (/^razor[-_]config\s*(.*)\s*$/) {
      $self->{razor_config} = $1; next;
    }

    if (/^auto[-_]whitelist[-_]path\s*(.*)\s*$/) {
      $self->{auto_whitelist_path} = $1; next;
    }
    if (/^auto[-_]whitelist[-_]file[-_]mode\s*(.*)\s*$/) {
      $self->{auto_whitelist_file_mode} = $1; next;
    }
    if (/^auto[-_]whitelist[-_]threshold\s*(.*)\s*$/) {
      $self->{auto_whitelist_threshold} = $1; next;
    }

    if (/^user[-_]scores[-_]dsn\s+(\S+)$/) {
      $self->{user_scores_dsn} = $1; next;
    }
    if(/^user[-_]scores[-_]sql[-_]username\s+(\S+)$/) {
      $self->{user_scores_sql_username} = $1; next;
    }
    if(/^user[-_]scores[-_]sql[-_]password\s+(\S+)$/) {
      $self->{user_scores_sql_password} = $1; next;
    }

failed_line:
    dbg ("Failed to parse line in SpamAssassin configuration, skipping: $_");
  }
}

sub add_test {
  my ($self, $name, $text, $type) = @_;
  if ($name eq '.') { $name = ($self->{_unnamed_counter}++); }
  $self->{tests}->{$name} = $text;
  $self->{test_types}->{$name} = $type;
  $self->{scores}->{$name} ||= 1.0;
}

sub finish_parsing {
  my ($self) = @_;

  foreach my $name (keys %{$self->{tests}}) {
    my $type = $self->{test_types}->{$name};
    my $text = $self->{tests}->{$name};

    if ($type == $type_body_tests) { $self->{body_tests}->{$name} = $text; }
    elsif ($type == $type_head_tests) { $self->{head_tests}->{$name} = $text; }
    elsif ($type == $type_head_evals) { $self->{head_evals}->{$name} = $text; }
    elsif ($type == $type_body_evals) { $self->{body_evals}->{$name} = $text; }
    elsif ($type == $type_full_tests) { $self->{full_tests}->{$name} = $text; }
    elsif ($type == $type_full_evals) { $self->{full_evals}->{$name} = $text; }
    else {
      # 70 == SA_SOFTWARE
      sa_die (70, "unknown type $type for $name: $text");
    }
  }

  delete $self->{tests};		# free it up
}

sub add_to_addrlist {
  my ($self, $singlelist, $domlist, @addrs) = @_;

  foreach my $addr (@addrs) {
    if ($addr =~ /^\*\@(\S+)/) {
      $self->{$domlist}->{lc $1} = 1;
    } else {
      $self->{$singlelist}->{lc $addr} = 1;
    }
  }
}

sub dbg { Mail::SpamAssassin::dbg (@_); }
sub sa_die { Mail::SpamAssassin::sa_die (@_); }

###########################################################################

1;
