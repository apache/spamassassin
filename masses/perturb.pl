#!/usr/bin/perl -w

my $threshold = 5;
my $iterlimit = 0;
my $use_c_loop = 1;

srand (time ^ $$);
my %is_spam = ();
my %tests_hit = ();

print "Reading per-message hit stat logs and scores...\n";
my $total;
readlogs();

my $scores;
readscores();
my $origscores = $scores;

if ($use_c_loop) {
  print "Writing logs and current scores as C arrays, and compiling...\n";
  writescores_c();
  writetests_c();
  system ("gcc perturb.c -o perturb");
  if (($? >> 8) != 0) { die "compile failed"; }

  print "Using compiled C loop for tests...\n";
  exec("./perturb") or die;
}

# else use perl loop...

my $results;
counthits();
print "At start...\n"; printhits();
my $origresults = $results;

open (OUT, ">perturb.baseline");
select OUT;
printhits();
writescores();
close OUT;

my ($iter);
my @scorenames = keys %{$scores};
my $numscores = scalar @scorenames;

for ($iter = 1; $iter != $iterlimit; $iter++) {
  if ($iter % 100 == 0) { print "Progress: $iter\n"; }

  %{$scores} = %{$origscores};
  %{$results} = %{$origresults};

  my $numperturbed = int rand(5)+1;
  # my $log = '';

  my $j = 0;
  while ($j < $numperturbed) {
    my $delta = int ((rand 4.0) - 2.0);
    next if ($delta == 0);

    my $snum = (int rand $numscores);
    my $score = $scores->{$scorenames[$snum]};
    $score += $delta;
    if ($score <= 0) { next; }
    $scores->{$scorenames[$snum]} = $score;

    # $log .= " $scorenames[$snum]:$delta";
    $j++;
  }
  # print "[$numperturbed: $log]\n";

  counthits();
  if ($results->{yn} <= $origresults->{yn}
    	&& $results->{ny} <= $origresults->{ny}
    	&& !($results->{ny} == $origresults->{ny}
			&& $results->{yn} == $origresults->{yn}))
  {
    print "Improved results at $iter:\n";
    printhits();

    open (OUT, ">perturb.good.$iter");
    select OUT;
    printhits();
    writescores();
    close OUT;

    select STDOUT;
  }
}
exit;

sub counthits {
  $results = { };
  $results->{ny} = $results->{nn} = 0;
  $results->{yy} = $results->{yn} = 0;

  my $file;
  for ($file = 0; $file < $total; $file++) {
    my $hits = 0;

    foreach my $test (@{$tests_hit{$file}}) {
      $hits += $scores->{$test};
    }

    if ($is_spam{$file}) {
      if ($hits > $threshold) {
	$results->{yy}++;
      } else {
	$results->{yn}++;
      }

    } else {
      if ($hits > $threshold) {
	$results->{ny}++;
      } else {
	$results->{nn}++;
      }
    }

    # print "$file: $hits $prevhits{$file}\n";
  }
}

sub printhits {
  $total ||= 1;	# avoid div by 0
  printf "Correctly non-spam: %6d  %3.2f%%\n",
  	$results->{nn}, ($results->{nn} / $total) * 100.0;
  printf "Correctly spam:     %6d  %3.2f%%\n",
  	$results->{yy}, ($results->{yy} / $total) * 100.0;
  printf "False positives:    %6d  %3.2f%%\n",
  	$results->{ny}, ($results->{ny} / $total) * 100.0;
  printf "False negatives:    %6d  %3.2f%%\n",
  	$results->{yn}, ($results->{yn} / $total) * 100.0;
  printf "TOTAL:              %6d  %3.2f%%\n",
  	$total, 100;
}

sub readlogs {
  my $count = 0;
  foreach my $file ("spam.log", "nonspam.log") {
    open (IN, "<$file");

    while (<IN>) {
      /^.\s+(\d+)\s+(\S+)\s*(\S*)/ or next;
      my $hits = $1;
      my @tests = split (/,/, $3);

      # $prevhits{$count} = $hits;
      $tests_hit{$count} = \@tests;

      if ($file eq "spam.log") {
	$is_spam{$count} = 1;
      } else {
	$is_spam{$count} = 0;
      }
      $count++;
    } 
    close IN;
  }
  $total = $count;
}


sub readscores {
  $scores = { };

  open (IN, "<../spamassassin.cf");
  while (<IN>) {
    s/#.*$//g; s/^\s+//; s/\s+$//;

    if (/^(header|body|full)\s+(\S+)\s+/) {
      $scores->{$2} ||= 1;
    } elsif (/^score\s+(\S+)\s+(.+)$/) {
      $scores->{$1} = $2;
    }
  }
  close IN;
}

sub writescores {
  foreach my $name (sort keys %{$scores}) {
    print "score $name ".$scores->{$name}."\n";
  }
}

sub writescores_c {
  open (OUT, ">scores.h");
  my $size = (scalar keys %{$scores}) + 1;
  print OUT "

int num_scores = $size;
int origscores[$size];
int scores[$size];
char *score_names[$size];

void loadscores (void) {

";
  my $count = 0;
  foreach my $name (sort keys %{$scores}) {
    $score_c_index{$name} = $count;
    print OUT "  origscores[$count] = ".$scores->{$name}.";\t",
    		"score_names[$count] = \"".$name."\";\n";
    $count++;
  }

  print OUT "\n}\n";
  close OUT;
}

sub writetests_c {
  my $file;

  # figure out max hits per message
  my $max_hits_per_msg = 0;
  for ($file = 0; $file < $total; $file++) {
    my $hits = scalar @{$tests_hit{$file}} + 1;
    if ($hits > $max_hits_per_msg) { $max_hits_per_msg = $hits; }
  }

  open (OUT, ">tests.h");
  print OUT "

int num_tests = $total;
int max_hits_per_msg = $max_hits_per_msg;
unsigned char num_tests_hit[$total];
unsigned char is_spam[$total];
unsigned short tests_hit[$total][$max_hits_per_msg];

void loadtests (void) {

";
  for ($file = 0; $file < $total; $file++) {
    my $num_tests_hit = scalar @{$tests_hit{$file}};
    print OUT "\n",
	"  num_tests_hit[$file] = $num_tests_hit;\n",
	"  is_spam[$file] = $is_spam{$file};\n";

    my $count = 0;
    foreach my $test (@{$tests_hit{$file}}) {
      if (!defined $score_c_index{$test}) {
	warn "test with no C index: $test\n";
      }
      print OUT "  tests_hit[$file][$count] = $score_c_index{$test};\n";
      $count++;
      if ($count >= $max_hits_per_msg) {
	die "Need to increase \$max_hits_per_msg";
      }
    }
  }

  print OUT "\n}\n";
  close OUT;
}

