#

package Mail::SpamAssassin::Conf;

use Carp;
use strict;

use Mail::Audit;

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
  $self->{spamtrap_template} = '';

  $self->{whitelist_from} = [ ];

  $self;
}

###########################################################################

sub parse_rules {
  my ($self, $rules) = @_;
  local ($_);

  $self->{unnamed_counter} = 'aaaaa';

  foreach $_ (split (/\n/, $rules)) {
    s/\r//g; s/(?:^|(?<!\\))\#.*$//;
    s/^\s+//; s/\s+$//; /^$/ and next;

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

    if (/^describe\s+(\S+)\s+(.*)$/) {
      $self->{descriptions}->{$1} = $2; next;
    }

    if (/^required_hits\s+(\d+)$/) {
      $self->{required_hits} = $1+0; next;
    }

    if (/^score\s+(\S+)\s+(\-*\d+)$/) {
      $self->{scores}->{$1} = $2+0; next;
    }

    if (/^report\s*(.*)$/) {
      $self->{report_template} .= $1."\n"; next;
    }

    if (/^spamtrap\s*(.*)$/) {
      $self->{spamtrap_template} .= $1."\n"; next;
    }

    if (/^whitelist_from\s+(\S+)\s*$/) {
      push (@{$self->{whitelist_from}}, $1); next;
    }

    if (/^auto_report_threshold\s+(\d+)$/) {
      $self->{auto_report_threshold} = $1+0; next;
    }

failed_line:
    dbg ("Failed to parse line in SpamAssassin configuration, skipping: $_");
  }
}

sub add_test {
  my ($self, $name, $text, $type) = @_;
  if ($name eq '.') { $name = ($self->{unnamed_counter}++); }
  $self->{tests}->{$name} = $text;
  $self->{test_types}->{$name} = $type;
  $self->{scores}->{$name} ||= 1;
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
    else { die "unknown type $type for $name: $text"; }
  }

  $self->{tests} = { };		# free it up
}

sub dbg { Mail::SpamAssassin::dbg (@_); }

###########################################################################

1;
