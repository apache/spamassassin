#

package Mail::SpamAssassin::Conf;

use Carp;
use strict;

use Mail::Audit;

use vars	qw{
  	@ISA
};

@ISA = qw();

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = {
    'main' => shift,
  }; bless ($self, $class);

  $self->{body_tests} = { };
  $self->{head_tests} = { };
  $self->{head_evals} = { };
  $self->{body_evals} = { };
  $self->{full_tests} = { };
  $self->{full_evals} = { };
  $self->{descriptions} = { };

  $self->{scores} = { };
  $self->{required_hits} = 5;
  $self->{auto_report_threshold} = 20;
  $self->{report_template} = '';

  $self;
}

###########################################################################

sub parse_rules {
  my ($self, $rules) = @_;
  local ($_);

  my $counter = 'aaaaa';

  foreach $_ (split (/\n/, $rules)) {
    s/\r//g; s/(?<!\\)\#.*$//; s/^\s+//; s/\s+$//; /^$/ and next;

    if (/^header\s+(\S+)\s+eval:(.*)$/) {
      my $name = $1; my $sub = $2;
      $self->{head_evals}->{$name} = $sub;
      $self->{scores}->{$name} ||= 1;
      next;
    }

    if (/^header\s+(\S+)\s+(.*)$/) {
      my $name = $1; my $tst = $2;
      $self->{head_tests}->{$name} = $tst;
      $self->{scores}->{$name} ||= 1;
      next;
    }

    if (/^describe\s+(\S+)\s+(.*)$/) {
      $self->{descriptions}->{$1} = $2;
      next;
    }

    if (/^body\s+(\S+)\s+eval:(.*)$/) {
      my $name = $1; my $sub = $2;
      $self->{body_evals}->{$name} = $sub;
      $self->{scores}->{$name} ||= 1;
      next;
    }

    if (/^body\s+(\S+)\s+(.*)$/) {
      my $name = $1; my $tst = $2;
      if ($name eq '.') { $name = ($counter++); }
      $self->{body_tests}->{$name} = $tst;
      $self->{scores}->{$name} ||= 1;
      next;
    }

    if (/^full\s+(\S+)\s+eval:(.*)$/) {
      my $name = $1; my $sub = $2;
      $self->{full_evals}->{$name} = $sub;
      $self->{scores}->{$name} ||= 1;
      next;
    }

    if (/^full\s+(\S+)\s+(.*)$/) {
      my $name = $1; my $sub = $2;
      $self->{full_tests}->{$name} = $sub;
      $self->{scores}->{$name} ||= 1;
      next;
    }

    if (/^required_hits\s+(\d+)$/) {
      $self->{required_hits} = $1+0;
      next;
    }

    if (/^score\s+(\S+)\s+(\-*\d+)$/) {
      $self->{scores}->{$1} = $2+0;
      next;
    }

    if (/^report\s*(.*)$/) {
      $self->{report_template} .= $1."\n";
      next;
    }

    if (/^auto_report_threshold\s+(\d+)$/) {
      $self->{auto_report_threshold} = $1+0;
      next;
    }

failed_line:
    dbg ("Failed to parse line in SpamAssassin configuration, skipping: $_");
  }
}

sub dbg { Mail::SpamAssassin::dbg (@_); }

###########################################################################

1;
