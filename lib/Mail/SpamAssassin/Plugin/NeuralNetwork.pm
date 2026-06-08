# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>
#
# Author: Giovanni Bechis <gbechis@apache.org>

=head1 NAME

Mail::SpamAssassin::Plugin::NeuralNetwork - check messages using Fast Artificial Neural Network library

=head1 SYNOPSIS

  loadplugin Mail::SpamAssassin::Plugin::NeuralNetwork

=head1 DESCRIPTION

This plugin checks emails using Neural Network algorithm.

=head1 CAVEATS

The SpamAssassin learning subsystem routes all training through the Bayes
scanner infrastructure.  As a result, C<Mail::SpamAssassin::Plugin::Bayes>
must be loaded and C<use_bayes 1> must be set for this plugin's training to
be triggered.

=cut

package Mail::SpamAssassin::Plugin::NeuralNetwork;

use strict;
use warnings;
use re 'taint';

my $VERSION = 0.11.1;

use AI::FANN qw(:all);
use Storable qw(store retrieve);
use File::Copy qw(copy);
use File::Spec;
use Errno qw(EXDEV);

use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Util qw(untaint_file_path);

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg { my $msg = shift; Mail::SpamAssassin::Logger::dbg("NeuralNetwork: $msg", @_); }
sub info { my $msg = shift; Mail::SpamAssassin::Logger::info("NeuralNetwork: $msg", @_); }

sub finish {
  my $self = shift;

  if ($self->{dbh}) {
    eval {
      local $SIG{PIPE} = 'IGNORE';
      $self->{dbh}->disconnect();
    };
    undef $self->{dbh};
  }
}

sub new {
  my ($class, $mailsa) = @_;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless ($self, $class);

  $self->set_config($mailsa->{conf});
  $self->register_eval_rule("check_neuralnetwork_spam", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("check_neuralnetwork_ham", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("check_neuralnetwork", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

=over 4

=item use_neuralnetwork (0|1)          (default: 1)

Whether to use Neural Network, if it is available.

=item neuralnetwork_data_dir dirname (default: undef)

Where NeuralNetwork plugin will store its data.

=item neuralnetwork_min_text_len n (default: 256)

Minimum number of characters of visible text required to run prediction or learning on a message.

=item neuralnetwork_min_word_len n (default: 4)

Minimum token length considered when building the vocabulary and feature vectors.

=item neuralnetwork_max_word_len n (default: 24)

Maximum token length considered when building the vocabulary and feature vectors.

=item neuralnetwork_vocab_cap n (default: 10000)

Maximum number of vocabulary terms to retain; least-frequent terms are pruned when exceeded.

=item neuralnetwork_cache_ttl n (default: 300)

Time-to-live in seconds for the in-memory vocabulary and model caches
Set to 0 to disable caching.

=item neuralnetwork_min_spam_count n (default: 100)

Minimum number of spam messages in the vocabulary required to enable prediction.

=item neuralnetwork_min_ham_count n (default: 100)

Minimum number of ham messages in the vocabulary required to enable prediction.

=item neuralnetwork_spam_threshold f (default: 0.6)

Prediction values above this threshold are considered spam.

=item neuralnetwork_ham_threshold f (default: 0.4)

Prediction values below this threshold are considered ham.

=item neuralnetwork_learning_rate f (default: 0.1)

Learning rate used by the underlying FANN network during incremental training.

=item neuralnetwork_momentum f (default: 0.1)

Momentum used for training updates.

=item neuralnetwork_train_epochs n (default: 50)

Number of training epochs to perform when learning a single message.

=item neuralnetwork_train_algorithm FANN_TRAIN_QUICKPROP|FANN_TRAIN_RPROP|FANN_TRAIN_BATCH|FANN_TRAIN_INCREMENTAL (default: FANN_TRAIN_RPROP)

Algorithm used by Fann neural network used when training, might increase speed depending on the data volume.

=item neuralnetwork_lock_timeout n (default: 10)

Maximum number of seconds to wait for the exclusive training lock before giving up and skipping the learn operation.
Set to 0 to wait indefinitely.

=item neuralnetwork_rprop_delta_max n (default: 0.5)

Delta value to apply to RPROP training replay loop.

=item neuralnetwork_retrain_interval n (default: 100)

Number of successful learn_message calls between forced full retrains of the
neural network from the persisted vocabulary. After each retrain the
incrementally-trained network is replaced with the freshly rebuilt one.
Set to 0 to disable periodic retraining and keep online learning only.

=item neuralnetwork_stopwords words (default: "the and for with that this from there their have be not but you your")

Space-separated list of stopwords to ignore when tokenizing text.

=item neuralnetwork_autolearn 0|1 (default 0)

When SpamAssassin declares a message a clear spam or ham during the message
scan, and launches the auto-learn process, message is autolearned as spam/ham
in the same way as during the manual learning.
Value 0 at this option disables the auto-learn process for this plugin.

=item neuralnetwork_autolearn_vocab_only 0|1 (default 0)

When set to 1 and auto-learn is enabled, autolearned messages
update the vocabulary and training buffer but skip FANN model training and saving.
This avoids slow I/O operations and temporary files during C<spamd>
processing. The model is rebuilt from the accumulated vocabulary on the next
manual C<sa-learn> run.

=item neuralnetwork_dsn                (default: none)

The DBI dsn of the database to use.

For SQLite, the database will be created automatically if it does not
already exist, the supplied path and file must be read/writable by the
user running spamassassin or spamd.

For MySQL/MariaDB or PostgreSQL, see sql-directory for database table
creation clauses.

You will need to have the proper DBI module for your database.  For example
DBD::SQLite, DBD::mysql, DBD::MariaDB or DBD::Pg.

Minimum required SQLite version is 3.24.0 (available from DBD::SQLite 1.59_01).

Examples:

 neuralnetwork_dsn dbi:SQLite:dbname=/var/lib/spamassassin/NeuralNetwork.db

=item neuralnetwork_username  (default: none)

The username that should be used to connect to the database.  Not used for
SQLite.

=item neuralnetwork_password (default: none)

The password that should be used to connect to the database.  Not used for
SQLite.

=item neuralnetwork_min_vocab_hits n (default: 10)

Minimum number of tokens in the email that must exist in the vocabulary for
prediction to run.

=back

=head1 EVAL RULES

=over 4

=item check_neuralnetwork_spam()

Body eval rule. Returns true when the neural network prediction score exceeds
C<neuralnetwork_spam_threshold> (default 0.6).

=item check_neuralnetwork_ham()

Body eval rule. Returns true when the neural network prediction score is below
C<neuralnetwork_ham_threshold> (default 0.4).

=item check_neuralnetwork(low, high)

Body eval rule accepting two optional floating-point arguments. Returns true
when the raw prediction score falls within the inclusive range C<[low, high]>.
Defaults: C<low = 0.0>, C<high = 1.0>.

Use this rule to define finer-grained confidence tiers.

  body      NN_CONFIDENT_SPAM  eval:check_neuralnetwork(0.75, 1.0)
  describe  NN_CONFIDENT_SPAM  Email classified as spam with high confidence by Neural Network
  score     NN_CONFIDENT_SPAM  2.0

  body      NN_PROBABLE_SPAM   eval:check_neuralnetwork(0.55, 0.75)
  describe  NN_PROBABLE_SPAM   Email classified as probable spam by Neural Network
  score     NN_PROBABLE_SPAM   1.0

  body      NN_PROBABLE_HAM    eval:check_neuralnetwork(0.0, 0.4)
  describe  NN_PROBABLE_HAM    Email classified as ham by Neural Network
  score     NN_PROBABLE_HAM    -1.0

=back

=cut

  push(@cmds, {
    setting => 'use_neuralnetwork',
    default => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });
  push(@cmds, {
    setting => 'neuralnetwork_data_dir',
    is_admin => 1,
    default => undef,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
  });
  push(@cmds, {
    setting => 'neuralnetwork_min_text_len',
    is_admin => 1,
    default => 256,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  push(@cmds, {
    setting => 'neuralnetwork_min_word_len',
    is_admin => 1,
    default => 4,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  push(@cmds, {
    setting => 'neuralnetwork_max_word_len',
    is_admin => 1,
    default => 24,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  push(@cmds, {
    setting => 'neuralnetwork_vocab_cap',
    is_admin => 1,
    default => 10000,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  push(@cmds, {
    setting => 'neuralnetwork_cache_ttl',
    is_admin => 1,
    default => 300,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  push(@cmds, {
    setting => 'neuralnetwork_min_spam_count',
    is_admin => 1,
    default => 100,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  push(@cmds, {
    setting => 'neuralnetwork_min_ham_count',
    is_admin => 1,
    default => 100,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  push(@cmds, {
    setting => 'neuralnetwork_spam_threshold',
    is_admin => 1,
    default => 0.6,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  push(@cmds, {
    setting => 'neuralnetwork_ham_threshold',
    is_admin => 1,
    default => 0.4,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  push(@cmds, {
    setting => 'neuralnetwork_learning_rate',
    is_admin => 1,
    default => 0.1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  push(@cmds, {
    setting => 'neuralnetwork_momentum',
    is_admin => 1,
    default => 0.1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  push(@cmds, {
    setting => 'neuralnetwork_train_epochs',
    is_admin => 1,
    default => 50,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  push(@cmds, {
    setting => 'neuralnetwork_train_algorithm',
    is_admin => 1,
    default => FANN_TRAIN_RPROP,
    code        => sub {
        my ($self, $key, $value, $line) = @_;
        my %algorithm_map = (
            'FANN_TRAIN_QUICKPROP'    => FANN_TRAIN_QUICKPROP,
            'FANN_TRAIN_RPROP'        => FANN_TRAIN_RPROP,
            'FANN_TRAIN_BATCH'        => FANN_TRAIN_BATCH,
            'FANN_TRAIN_INCREMENTAL'  => FANN_TRAIN_INCREMENTAL,
        );
        if (!exists $algorithm_map{$value}) {
            return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }
        $self->{neuralnetwork_train_algorithm} = $algorithm_map{$value};
    },
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  push(@cmds, {
    setting  => 'neuralnetwork_rprop_delta_max',
    is_admin => 1,
    default  => 0.5,
    type     => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  push(@cmds, {
    setting  => 'neuralnetwork_weight_prune_factor',
    is_admin => 1,
    default  => 0.5,
    type     => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  push(@cmds, {
    setting  => 'neuralnetwork_retrain_interval',
    is_admin => 1,
    default  => 100,
    type     => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  push(@cmds, {
    setting => 'neuralnetwork_lock_timeout',
    is_admin => 1,
    default => 10,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  push(@cmds, {
    setting => 'neuralnetwork_stopwords',
    is_admin => 1,
    default => 'the and for with that this from there their have be not but you your',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
  });
  push(@cmds, {
    setting => 'neuralnetwork_autolearn',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });
  push(@cmds, {
    setting => 'neuralnetwork_autolearn_vocab_only',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });
  push(@cmds, {
    setting => 'neuralnetwork_dsn',
    is_admin => 1,
    default => undef,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
  });
  push(@cmds, {
    setting => 'neuralnetwork_username',
    is_admin => 1,
    default => '',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
  });
  push(@cmds, {
    setting => 'neuralnetwork_password',
    is_admin => 1,
    default => '',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
  });
  push(@cmds, {
    setting => 'neuralnetwork_min_vocab_hits',
    is_admin => 1,
    default => 10,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub autolearn {
  my ($self, $params) = @_;

  $self->{last_pms} = $params->{permsgstatus};
  return $self->{autolearn} = 1;
}

sub finish_parsing_end {
  my ($self, $opts) = @_;

  my $conf = $self->{main}->{conf};
  return unless $conf->{use_neuralnetwork};

  my $nn_data_dir = $conf->{neuralnetwork_data_dir};

  # Initialize SQL connection if configured
  if (defined $conf->{neuralnetwork_dsn}) {
    $self->_init_sql_connection($conf);
  }

  return unless defined $nn_data_dir;

  $nn_data_dir = Mail::SpamAssassin::Util::untaint_file_path($nn_data_dir);
  if (not -d $nn_data_dir) {
    dbg("neuralnetwork_data_dir is invalid");
    return;
  }

  my $dataset_path = Mail::SpamAssassin::Util::untaint_file_path($self->_model_path($nn_data_dir));
  if (-f $dataset_path) {
    eval {
      $self->{neural_model} = AI::FANN->new_from_file($dataset_path);
      $self->{_neural_model_load_time} = time();
      1;
    } or do {
      my $err = $@ || 'unknown';
      info("Failed to load neural model from $dataset_path: $err");
    };
  }
}

# Converts a list of pre-tokenised messages into a list of
# numerical feature vectors (dense arrays), suitable for Neural Networks training.
sub _text_to_features {
    my ($self, $conf, $nn_data_dir, $train, $label, $target_vocab_ref, @token_lists) = @_;

    my $vocab_cap    = $conf->{neuralnetwork_vocab_cap};

    return unless defined $nn_data_dir;
    $nn_data_dir = Mail::SpamAssassin::Util::untaint_file_path($nn_data_dir);

    if( not -d $nn_data_dir) {
      info("Cannot access directory $nn_data_dir");
      return;
    }

    # Read the vocabulary (format: { terms => {word => {total=>n,docs=>m,spam=>s,ham=>h}}, _doc_count => N, _spam_count => S, _ham_count => H })
    my %vocabulary = %{ $self->_load_vocabulary($conf, $nn_data_dir, $train) };

    # Ensure we have enough spam and ham examples in the vocabulary
    my $min_spam = $conf->{neuralnetwork_min_spam_count};
    my $min_ham  = $conf->{neuralnetwork_min_ham_count};
    my $username = lc($self->{main}->{username});
    if ($train == 0) {
      if ( ($vocabulary{_spam_count} < $min_spam) || ($vocabulary{_ham_count} < $min_ham) ) {
        dbg("Insufficient spam/ham data for prediction for user $username: spam=".$vocabulary{_spam_count}.", ham=".$vocabulary{_ham_count});
        return ([], 0, []);
      }
    }

    # When training, build per-document term sets to update doc counts
    my $local_doc_increment = 0;
    my %term_deltas;
    if ($train == 1) {
      foreach my $tok_ref (@token_lists) {
        next unless ref($tok_ref) eq 'ARRAY' && @$tok_ref;
        my @tokens = @$tok_ref;
        $local_doc_increment++;

        # count doc-level presence once per unique token
        my %seen;
        foreach my $t (@tokens) {
          $vocabulary{terms}{$t}{total} = ($vocabulary{terms}{$t}{total} || 0) + 1;
          $term_deltas{$t}{total}      = ($term_deltas{$t}{total}      || 0) + 1;
          $seen{$t} = 1;
        }
        foreach my $t (keys %seen) {
          $vocabulary{terms}{$t}{docs} = ($vocabulary{terms}{$t}{docs} || 0) + 1;
          $term_deltas{$t}{docs}       = ($term_deltas{$t}{docs}       || 0) + 1;
          # Track spam/ham sources
          if (defined $label && $label == 1) {
            $vocabulary{terms}{$t}{spam} = ($vocabulary{terms}{$t}{spam} || 0) + 1;
            $term_deltas{$t}{spam}       = ($term_deltas{$t}{spam}       || 0) + 1;
          } elsif (defined $label && $label == 0) {
            $vocabulary{terms}{$t}{ham} = ($vocabulary{terms}{$t}{ham} || 0) + 1;
            $term_deltas{$t}{ham}       = ($term_deltas{$t}{ham}       || 0) + 1;
          }
        }
      }

      # increment global doc count
      $vocabulary{_doc_count} += $local_doc_increment if $local_doc_increment > 0;

      # increment spam/ham counters
      if (defined $label && $label == 1 && $local_doc_increment > 0) {
        $vocabulary{_spam_count} += $local_doc_increment;
      } elsif (defined $label && $label == 0 && $local_doc_increment > 0) {
        $vocabulary{_ham_count} += $local_doc_increment;
      }

      $self->_prune_vocabulary(\%vocabulary, $vocab_cap);

      my $vocab_path;
      if (defined $conf->{neuralnetwork_dsn} && $self && $self->{dbh}) {
        # SQL vocabulary is updated via training-buffer flush at retrain time
      } else {
        $vocab_path = File::Spec->catfile($nn_data_dir, 'vocabulary-' . lc($self->{main}->{username}) . '.data');
        $vocab_path = Mail::SpamAssassin::Util::untaint_file_path($vocab_path);
        eval {
          store(\%vocabulary, $vocab_path) or die "store failed";
          1;
        } or do {
          warn("Failed to store vocabulary to $vocab_path: " . ($@ || 'unknown'));
        };
        # Keep file-based cache in sync with the freshly saved vocabulary
        my $ttl = $conf->{neuralnetwork_cache_ttl} || 0;
        if ($ttl > 0) {
          $self->{_file_vocab_cache}{$username} = \%vocabulary;
          $self->{_file_vocab_cache_time}{$username} = time();
        }
      }
      # learn_message cache
      $self->{_last_train_vocab} = \%vocabulary if $self;
    }

    # Build vocabulary index
    my @vocab_keys = ($target_vocab_ref && @$target_vocab_ref)
        ? @$target_vocab_ref
        : sort keys %{ $vocabulary{terms} };
    my %vocab_index = map { $vocab_keys[$_] => $_ } 0..$#vocab_keys;
    my $vocab_size = scalar @vocab_keys;
    return ([], 0, []) unless $vocab_size > 0;

    # Precompute IDF: log((N+1)/(df+1)) + 1 smoothing
    my $N = $vocabulary{_doc_count} || 1;
    my %idf;
    foreach my $w (@vocab_keys) {
      my $df = $vocabulary{terms}{$w}{docs} || 0;
      $idf{$w} = log( ($N + 1) / ($df + 1) ) + 1;
    }

    # Create TF-IDF vectors and L2-normalize
    my @feature_vectors;
    foreach my $tok_ref (@token_lists) {
      next unless ref($tok_ref) eq 'ARRAY';
      my @tokens = @$tok_ref;
      my %tf;
      $tf{$_}++ for @tokens;
      # Build raw tf-idf vector
      my @vec = (0) x $vocab_size;
      foreach my $term (keys %tf) {
        next unless exists $vocab_index{$term};
        my $i = $vocab_index{$term};
        my $tf_val = $tf{$term} / (scalar @tokens || 1);  # normalized TF
        $vec[$i] = $tf_val * ($idf{$term} || 1);
      }
      # L2 normalization
      my $norm = 0;
      $norm += $_ * $_ for @vec;
      $norm = sqrt($norm) || 1;
      @vec = map { $_ / $norm } @vec;

      # Count how many vocabulary positions are non-zero (vocab hit count)
      my $hits = scalar grep { $_ != 0 } @vec;
      push @feature_vectors, { vec => \@vec, hits => $hits };
    }

    return \@feature_vectors, $vocab_size, \@vocab_keys;
}

sub learn_message {
  my ($self, $params) = @_;
  my $isspam = $params->{isspam};
  my $msg = $params->{msg};
  my $conf = $self->{main}->{conf};

  return unless $conf->{use_neuralnetwork};

  $self->_init_sql_connection($conf) if defined $conf->{neuralnetwork_dsn};
  my $min_text_len = $conf->{neuralnetwork_min_text_len};
  my $learning_rate = $conf->{neuralnetwork_learning_rate};
  my $momentum = $conf->{neuralnetwork_momentum};
  my $train_epochs = $conf->{neuralnetwork_train_epochs};
  my $train_algorithm = $conf->{neuralnetwork_train_algorithm};
  my @training_data;
  my $autolearn = defined $self->{autolearn};
  my $last_pms  = $self->{last_pms};
  $self->{last_pms} = $self->{autolearn} = undef;

  if ($autolearn && !$conf->{neuralnetwork_autolearn}) {
    dbg("autolearning disabled, quitting");
    return 0;
  }

  my $msgid = $msg->get_msgid();
  $msgid //= $msg->generate_msgid();

  # do not relearn messages
  if($self->_is_msgid_in_neural_seen($msgid)) {
    dbg("Message $msgid found in neural_seen, skipping");
    return;
  }

  dbg("learning a message");
  my $pms = ($last_pms && defined $last_pms->{main}) ? $last_pms : Mail::SpamAssassin::PerMsgStatus->new($self->{main}, $params->{msg});
  if (!defined $pms->{relays_internal} && !defined $pms->{relays_external}) {
    $pms->extract_message_metadata();
  }
  my $nn_data_dir = $self->{main}->{conf}->{neuralnetwork_data_dir};
  unless (defined $nn_data_dir) {
    dbg("neuralnetwork_data_dir not set");
    return;
  }
  $nn_data_dir = Mail::SpamAssassin::Util::untaint_file_path($nn_data_dir);
  if (not -d $nn_data_dir) {
    info("Invalid neuralnetwork_data_dir path");
    return;
  }

  if( not defined $isspam ) {
    dbg("Unknown spam value");
    return;
  }

  if(defined $msg) {
    my $vis_text = $self->_get_visible_text($msg);
    if (length($vis_text) < $min_text_len) {
      dbg("Not enough text, skipping neural network processing");
      return;
    }
    my $tokens_ref = $self->_extract_features_from_message($pms, $conf, $msg);
    push(@training_data, { label => $isspam, tokens => $tokens_ref } );
  }

  my $dataset_path = Mail::SpamAssassin::Util::untaint_file_path($self->_model_path($nn_data_dir));

  my $locker = $self->{main}->{locker};
  unless ($locker->safe_lock($dataset_path, $conf->{neuralnetwork_lock_timeout})) {
    dbg("Cannot acquire lock on '$dataset_path', skipping learning");
    return;
  }

  # Extract the per-message token lists and labels
  my @email_token_lists = map { $_->{tokens} } @training_data;
  my @labels = map { $_->{label} } @training_data;

  if (!defined $self->{neural_model} && -f $dataset_path) {
    eval {
      $self->{neural_model} = AI::FANN->new_from_file($dataset_path);
      $self->{_neural_model_load_time} = time();
      1;
    } or do {
      dbg("Failed to load model before training: " . ($@ || 'unknown'));
    };
  } elsif (!-f $dataset_path) {
    undef $self->{neural_model};
  }
  # Invalidate vocabulary cache
  if (defined $self->{_vocab_cache}) {
    my $username = lc($self->{main}->{username});
    delete $self->{_vocab_cache}{$username};
    delete $self->{_vocab_cache_time}{$username};
  }

  # Update the vocabulary
  my $update_vocab = 1;

  # Convert per-message token lists to numerical feature vectors
  my ($feature_vectors, $vocab_size, $vocab_keys_ref) = _text_to_features($self, $self->{main}->{conf}, $nn_data_dir, $update_vocab, $isspam, undef, @email_token_lists);

  unless ($feature_vectors && @$feature_vectors) {
    $locker->safe_unlock($dataset_path);
    return;
  }

  my $num_input = scalar(@{$feature_vectors->[0]{vec}});
  if ($num_input == 0) {
    dbg("No valid features found in message, skipping learning");
    $locker->safe_unlock($dataset_path);
    return;
  }

  my ($buffer_spam_count, $buffer_ham_count, $rb_needs_retrain) =
    $self->_push_to_training_buffer($conf, $nn_data_dir, \@email_token_lists, \@labels);

  # defer model training if autolearning is enabled
  # and `neuralnetwork_autolearn_vocab_only` is set, model training could be a slow task
  if ($autolearn && $conf->{neuralnetwork_autolearn_vocab_only}) {
    dbg("autolearn vocab-only mode: vocabulary updated, skipping model training");
    if (defined $msg && defined $msgid && length($msgid) > 0) {
      $self->_save_msgid_to_neural_seen($msgid, $isspam);
    }
    $locker->safe_unlock($dataset_path);
    return 1;
  }

  # Defer model creation until minimum training corpus is built
  unless (defined $self->{neural_model}) {
    my $min_spam = $conf->{neuralnetwork_min_spam_count};
    my $min_ham  = $conf->{neuralnetwork_min_ham_count};
    my $vocab = $self->{_last_train_vocab} // {};
    my $sc = $vocab->{_spam_count} || 0;
    my $hc = $vocab->{_ham_count}  || 0;
    if ($sc < $min_spam || $hc < $min_ham) {
      dbg("Deferring model creation: spam=$sc/$min_spam ham=$hc/$min_ham (vocabulary updated)");
      # Record message as learned to prevent re-learning.
      if (defined $msg && defined $msgid && length($msgid) > 0) {
        $self->_save_msgid_to_neural_seen($msgid, $isspam);
      }
      $locker->safe_unlock($dataset_path);
      return 0;
    }
  }

  # Snapshot the on-disk model mtime so the save section can detect that
  # another writer modified the model file while we were training.
  my $lock1_mtime = (stat($dataset_path))[9];

  # Two-layer hidden sizing: layer1 ~0.25*sqrt(inputs), layer2 half of layer1.
  my $num_hidden1 = int(sqrt($num_input) * 0.25 + 0.5);
  $num_hidden1 = 4 if $num_hidden1 < 4;
  my $num_hidden2 = int($num_hidden1 / 2);
  $num_hidden2 = 2 if $num_hidden2 < 2;
  my $num_output_neurons = 1;

  my ($network, $network_rebuilt) = $self->_get_or_create_network(
    $conf, $nn_data_dir, $dataset_path,
    $num_input, $num_hidden1, $num_hidden2, $num_output_neurons,
    $buffer_spam_count, $buffer_ham_count, $train_algorithm);

  # When _retrain_from_vocabulary couldn't supply a balanced training set
  # (training buffer one-sided) and no existing model is in memory or on disk,
  # there is nothing meaningful to train or save. Persist the message-id so
  # we don't reprocess this learn, release the lock, and return.
  if (!defined $network) {
    dbg("Skipping training and model save: training buffer too one-sided to " .
        "build a balanced batch (spam=$buffer_spam_count, ham=$buffer_ham_count)");
    if (defined $msg && defined $msgid && length($msgid) > 0) {
      $self->_save_msgid_to_neural_seen($msgid, $isspam);
    }
    $locker->safe_unlock($dataset_path);
    return 1;
  }

  $network->learning_rate($learning_rate);
  $network->learning_momentum($momentum);
  $network->training_algorithm($train_algorithm);
  if ($train_algorithm == FANN_TRAIN_RPROP) {
    $network->rprop_delta_max($conf->{neuralnetwork_rprop_delta_max});
  }

  # reuse the cached vocabulary for class-balance accounting
  my %vocab_for_balance = %{ delete $self->{_last_train_vocab} || {} };
  my $raw_spam  = $vocab_for_balance{_spam_count} || 0;
  my $raw_ham   = $vocab_for_balance{_ham_count}  || 0;
  my $spam_docs = $raw_spam || 1;
  my $ham_docs  = $raw_ham  || 1;

  # For SQL-backed deployments, merge training buffer and retrain counter from the
  # training buffer table
  if (defined $conf->{neuralnetwork_dsn} && $self->{dbh}) {
    my $meta = $self->_load_meta($conf);
    $vocab_for_balance{_learns_since_retrain} = $meta->{_learns_since_retrain};
    $vocab_for_balance{_tbuf}                 = $meta->{_tbuf};
    dbg("SQL metadata loaded: learns_since_retrain=$meta->{_learns_since_retrain}, " .
        "tbuf_spam=" . scalar(@{ $meta->{_tbuf}{spam} || [] }) .
        " tbuf_ham=" . scalar(@{ $meta->{_tbuf}{ham}  || [] }));
  }

  my $class_weight;
  if ($isspam) {
    $class_weight = ($spam_docs > 0) ? $ham_docs / $spam_docs : 1.0;
  } else {
    $class_weight = ($ham_docs > 0) ? $spam_docs / $ham_docs : 1.0;
  }
  $class_weight = 1.0 if $class_weight < 1.0;
  $class_weight = 4.0 if $class_weight > 4.0;
  my $weighted_epochs = int($train_epochs * $class_weight) || 1;

  dbg("Incremental training: weighted_epochs=$weighted_epochs " .
      "(base=$train_epochs, class_weight=$class_weight, " .
      "spam_docs=$spam_docs, ham_docs=$ham_docs, isspam=$isspam, " .
      "num_input=$num_input)");

  my $locked_num_input      = $num_input;
  my $locked_vocab_keys_ref = $vocab_keys_ref;

  $self->_run_balanced_replay(
    $network, $conf, $nn_data_dir, $feature_vectors,
    $vocab_for_balance{_tbuf}, $locked_vocab_keys_ref, $locked_num_input,
    $weighted_epochs, $network_rebuilt, $train_algorithm);

  my $new_counter;
  my $tbuf_after_retrain;
  ($network, $locked_num_input, $locked_vocab_keys_ref, $new_counter, $tbuf_after_retrain) =
    $self->_periodic_retrain_if_needed($conf, $nn_data_dir, $network,
      $vocab_for_balance{_learns_since_retrain},
      $locked_num_input, $locked_vocab_keys_ref, $rb_needs_retrain);

  # Use the cleared buffer returned by a successful retrain,
  # or fall back to the current in-memory buffer.
  my $tbuf_to_save = $tbuf_after_retrain // $vocab_for_balance{_tbuf};
  $self->_save_meta($conf, $nn_data_dir, $new_counter, $tbuf_to_save);

  my $model_saved = $self->_save_model_atomic(
    $network, $dataset_path, $lock1_mtime,
    $locked_vocab_keys_ref, $locked_num_input, $nn_data_dir, $locker);

  if ($model_saved) {
    dbg("Model saved to '$dataset_path' (input:$locked_num_input)");
    $self->{neural_model}            = $network;
    $self->{_neural_model_load_time} = time();
    $self->_save_msgid_to_neural_seen($msgid, $isspam)
      if defined $msg && defined $msgid && length($msgid) > 0;
  }
  return $model_saved;
}

sub forget_message {
  my ($self, $params) = @_;
  my $conf = $self->{main}->{conf};

  return unless $conf->{use_neuralnetwork};

  $self->_init_sql_connection($conf) if defined $conf->{neuralnetwork_dsn};

  my $username = $self->{main}->{username};
  my $msg = $params->{msg};
  my $msgid = $msg->get_msgid();
  $msgid //= $msg->generate_msgid();

  my $flag = $self->_is_msgid_in_neural_seen($msgid);
  if ($flag) {
    dbg("Message $msgid found in neural_seen (flag=$flag), forgetting");
    $self->{forgetting} = 1;

    unless ($self->{main}->{conf}->{neuralnetwork_dsn} =~ /^dbi:/i) {
      dbg("It's not possible to forget a message if neuralnetwork_dsn has not been configured");
      return;
    }

    # Decrement vocabulary counts for tokens in this message
    my $tokens_ref = $self->_extract_features_from_message(undef, $conf, $msg);

    my $deleted_count = 0;
    if (ref $tokens_ref eq 'ARRAY' && @$tokens_ref) {
        my %token_total;
        foreach my $t (@$tokens_ref) {
          $token_total{$t}++;
        }

        my $is_spam = ($flag eq 'S') ? 1 : 0;
        eval {
          $self->{dbh}->begin_work();

          my $update_sql = "
            UPDATE neural_vocabulary
            SET total_count = CASE WHEN total_count > ? THEN total_count - ? ELSE 0 END,
                docs_count  = CASE WHEN docs_count > 0 THEN docs_count - 1 ELSE 0 END,
                spam_count  = CASE WHEN spam_count > ? THEN spam_count - ? ELSE 0 END,
                ham_count   = CASE WHEN ham_count > ? THEN ham_count - ? ELSE 0 END
            WHERE username = ? AND keyword = ?
          ";
          my $sth_update = $self->{dbh}->prepare($update_sql);

          foreach my $t (keys %token_total) {
            my $spam_dec = $is_spam ? 1 : 0;
            my $ham_dec  = $is_spam ? 0 : 1;
            $sth_update->execute(
              $token_total{$t}, $token_total{$t},  # total_count
              $spam_dec, $spam_dec,                  # spam_count
              $ham_dec, $ham_dec,                     # ham_count
              lc($username), $t
            );
          }

          # Remove unused terms, but keep rows still referenced by the
          # trained model (model_position IS NOT NULL) so the FANN input
          # ordering on disk stays consistent with SQL until the next
          # retrain reclaims the slot.
          my $cleanup_sql = "
            DELETE FROM neural_vocabulary
            WHERE username = ?
              AND total_count = 0 AND docs_count = 0
              AND spam_count = 0 AND ham_count = 0
              AND model_position IS NULL
          ";
          my $sth_cleanup = $self->{dbh}->prepare($cleanup_sql);
          $sth_cleanup->execute(lc($username));
          $deleted_count = $sth_cleanup->rows();

          $self->{dbh}->commit();
          dbg("Decremented vocabulary counts for message $msgid");
          1;
        } or do {
          my $err = $@ || 'unknown';
          eval { $self->{dbh}->rollback() if !$self->{dbh}{AutoCommit} };
          dbg("Failed to decrement vocabulary during forget: $err");
        };
    }

    my $del_sql = "
      DELETE FROM neural_seen
      WHERE username = ? AND msgid = ?
    ";
    my $sth = $self->{dbh}->prepare($del_sql);
    if (not $sth->execute(lc($username), $msgid)) {
      info("Error forgetting message $msgid");
      return 0;
    }

    # Invalidate vocabulary cache
    my $lc_user = lc($username);
    if (defined $self->{_vocab_cache}) {
      delete $self->{_vocab_cache}{$lc_user};
      delete $self->{_vocab_cache_time}{$lc_user};
    }
    if (defined $self->{_file_vocab_cache}) {
      delete $self->{_file_vocab_cache}{$lc_user};
      delete $self->{_file_vocab_cache_time}{$lc_user};
    }

    # Vocabulary terms were removed, retrain so the model stays consistent
    if ($deleted_count > 0) {
      my $nn_data_dir  = Mail::SpamAssassin::Util::untaint_file_path($conf->{neuralnetwork_data_dir});
      my $dataset_path = File::Spec->catfile($nn_data_dir, 'fann-' . $lc_user . '.model');
      if (-d $nn_data_dir && -f $dataset_path) {
        my $full_vocab_ref  = $self->_load_vocabulary_from_sql($username);
        my $full_terms      = ref($full_vocab_ref) eq 'HASH' ? ($full_vocab_ref->{terms} || {}) : {};
        my $full_vocab_size = scalar keys %$full_terms;
        if ($full_vocab_size > 0) {
          my ($rebuilt) = eval { $self->_retrain_from_vocabulary($conf, $nn_data_dir, $full_vocab_size) };
          if (!$rebuilt) {
            dbg("NeuralNetwork: Retrain after forget failed: " . ($@ || 'undef'));
          } else {
            # Pre-stage the FANN model to a temp file BEFORE acquiring the lock.
            my $tmp_path;
            my $file_mode = 0666 & ~umask();
            my $prestage_ok = eval {
              ($tmp_path, my $tmp_fh) = Mail::SpamAssassin::Util::secure_tmpfile();
              die "could not create temp file" unless defined $tmp_path;
              close $tmp_fh;
              $tmp_path = Mail::SpamAssassin::Util::untaint_file_path($tmp_path);
              chmod($file_mode, $tmp_path) or info("chmod $file_mode on '$tmp_path' failed: $!");
              $rebuilt->save($tmp_path) or die "save failed";
              1;
            };
            if (!$prestage_ok) {
              info("NeuralNetwork: Could not pre-stage retrained model after forget: " . ($@ || 'unknown'));
              unlink($tmp_path) if defined $tmp_path && -f $tmp_path;
            } else {
              my $locker   = $self->{main}->{locker};
              my $got_lock = 0;
              eval { $got_lock = $locker->safe_lock($dataset_path, $conf->{neuralnetwork_lock_timeout}); 1 };
              if (!$got_lock) {
                info("NeuralNetwork: Cannot acquire lock for save after forget; in-memory model not persisted");
                unlink($tmp_path) if defined $tmp_path && -f $tmp_path;
              } else {
                eval {
                  _rename_or_copy($tmp_path, $dataset_path)
                    or die "rename/copy failed: $!";
                  $tmp_path = undef;
                  1;
                } or do {
                  info("NeuralNetwork: Could not persist retrained model after forget: " . ($@ || 'unknown'));
                  unlink($tmp_path) if defined $tmp_path && -f $tmp_path;
                };
                my $new_vocab_keys = [ sort keys %$full_terms ];
                if (defined $conf->{neuralnetwork_dsn} && $self->{dbh}) {
                  $self->_save_model_vocab_to_sql($new_vocab_keys);
                } else {
                  $self->_save_model_vocab($new_vocab_keys, $nn_data_dir);
                }
                $self->{neural_model}            = $rebuilt;
                $self->{_neural_model_load_time} = time();
                delete $self->{_model_vocab_cache};
                info("NeuralNetwork: Retrained model with $full_vocab_size vocabulary terms after forget");
                $locker->safe_unlock($dataset_path);
              }
            }
          }
        }
      }
    }

    $self->{forgetting} = undef;
    return 1;
  }
  return 0;
}

sub check_neuralnetwork_spam {
  my ($self, $pms) = @_;

  _check_neuralnetwork($self, $pms);
  return $pms->{neuralnetwork_spam};
}

sub check_neuralnetwork_ham {
  my ($self, $pms) = @_;

  _check_neuralnetwork($self, $pms);
  return $pms->{neuralnetwork_ham};
}

sub check_neuralnetwork {
  my ($self, $pms, $body, $low, $high) = @_;

  _check_neuralnetwork($self, $pms);
  my $pred = $pms->{neuralnetwork_prediction};
  return 0 unless defined $pred;
  return ($pred >= $low && $pred <= $high) ? 1 : 0;
}

# Compute chi-squared score measuring how discriminative a vocabulary term
# is between spam and ham. Returns 0 when there is insufficient data.
sub _chi2_score {
  my ($spam, $ham, $total_spam, $total_ham) = @_;
  my $total = $total_spam + $total_ham;
  return 0 unless $total > 0;
  my $total_spam_noterm = $total_spam - $spam;
  my $total_ham_noterm = $total_ham  - $ham;
  my $denom = ($spam+$ham) * ($total - $spam - $ham) * $total_spam * $total_ham;
  return 0 unless $denom > 0;
  return ($total * ($spam*$total_ham_noterm - $ham*$total_spam_noterm)**2) / $denom;
}

# Prune vocabulary to keep only the top $vocab_cap terms ranked by chi-squared
# discriminativeness score, ensuring the most class-separating terms are kept.
sub _prune_vocabulary {
  my ($self, $vocabulary, $vocab_cap) = @_;

  my $terms = $vocabulary->{terms} || {};
  my $terms_count = scalar keys %{$terms};
  return () unless $terms_count > $vocab_cap;

  # Prune to 90% of cap so the vocabulary has room to grow before the next
  # prune is triggered.
  my $prune_target = int($vocab_cap * 0.9) || 1;

  my $spam_docs = $vocabulary->{_spam_count} || 1;
  my $ham_docs  = $vocabulary->{_ham_count}  || 1;

  # Score every term by chi-squared discriminativeness and keep the best
  my %scores;
  for my $w (keys %{$terms}) {
    $scores{$w} = _chi2_score(
      $terms->{$w}{spam} || 0,
      $terms->{$w}{ham}  || 0,
      $spam_docs, $ham_docs
    );
  }

  my %kept;
  for my $w (sort { $scores{$b} <=> $scores{$a} } keys %{$terms}) {
    last if scalar keys %kept >= $prune_target;
    $kept{$w} = $terms->{$w};
  }
  my @pruned = grep { !exists $kept{$_} } keys %{$terms};
  $vocabulary->{terms} = \%kept;

  if (@pruned && defined $self->{main}->{conf}->{neuralnetwork_dsn} && ($self->{main}->{conf}->{neuralnetwork_dsn} =~ /^dbi:/i)) {
    eval {
      my $user = $self->{main}->{username};
      my $placeholders = join(',', ('?') x scalar(@pruned));
      # Skip rows still referenced by the trained model - deleting them
      # would leave the FANN input vector smaller than num_inputs() and
      # force prediction to zero-pad. Orphans get reclaimed at retrain.
      my $del_sql = "DELETE FROM neural_vocabulary
                     WHERE username = ?
                       AND keyword IN ($placeholders)
                       AND model_position IS NULL";
      my $sth_del = $self->{dbh}->prepare($del_sql);
      $sth_del->execute(lc($user), @pruned);
      my $removed = $sth_del->rows();
      $removed = 0 if !defined $removed || $removed < 0;
      dbg("Deleted $removed terms for user: $user");
      1;
    } or do {
      dbg("Failed to delete terms: " . ($@ || 'unknown'));
    };
  }
  dbg("Pruned vocabulary from $terms_count to $prune_target terms (cap: $vocab_cap)");
  return @pruned;
}

# Sub to ensure vector matches expected size
sub _adjust_vector_size {
  my ($vec, $expected) = @_;
  return unless defined $vec && defined $expected && $expected >= 0;
  my @v = @$vec;
  my $len = scalar @v;
  if ($len < $expected) {
    dbg("Adjusting input vector: padding from $len to $expected");
    push @v, (0) x ($expected - $len);
  } elsif ($len > $expected) {
    dbg("Adjusting input vector: truncating from $len to $expected");
    $#v = $expected - 1;
  }
  return \@v;
}

# Build L2-normalised TF-IDF spam and ham vectors from a vocabulary hash.
sub _build_class_tfidf_vectors {
  my ($vocabulary, $vocab_keys) = @_;
  return () unless ref($vocabulary) eq 'HASH' && ref($vocab_keys) eq 'ARRAY' && @$vocab_keys;

  my $terms     = $vocabulary->{terms} || {};
  my $N         = $vocabulary->{_doc_count}  || 1;
  my $spam_docs = $vocabulary->{_spam_count} || 1;
  my $ham_docs  = $vocabulary->{_ham_count}  || 1;

  my @spam_vec = (0) x scalar(@$vocab_keys);
  my @ham_vec = (0) x scalar(@$vocab_keys);

  for my $i (0 .. $#$vocab_keys) {
    my $w   = $vocab_keys->[$i];
    my $td  = $terms->{$w} // {};
    my $idf       = log(($N + 1) / (($td->{docs} || 0) + 1)) + 1;
    my $spam_rate = ($td->{spam} || 0) / $spam_docs;
    my $ham_rate  = ($td->{ham}  || 0) / $ham_docs;
    $spam_vec[$i] = ($spam_rate > $ham_rate) ? ($spam_rate - $ham_rate) * $idf : 0;
    $ham_vec[$i]  = ($ham_rate > $spam_rate) ? ($ham_rate - $spam_rate) * $idf : 0;
  }

  for my $vec (\@spam_vec, \@ham_vec) {
    my $norm = sqrt(do { my $s = 0; $s += ($_ // 0) ** 2 for @$vec; $s }) || 1;
    @$vec = map { ($_ // 0) / $norm } @$vec;
  }

  return (\@spam_vec, \@ham_vec);
}

# Create a baseline model from vocabulary statistics when vocab size has changed.
sub _retrain_from_vocabulary {
  my ($self, $conf, $nn_data_dir, $vocab_size, $restricted_keys_ref) = @_;

  return unless defined $nn_data_dir && $vocab_size > 0;

  my $learning_rate   = $conf->{neuralnetwork_learning_rate};
  my $momentum        = $conf->{neuralnetwork_momentum};
  my $train_epochs    = $conf->{neuralnetwork_train_epochs};
  my $train_algorithm = $conf->{neuralnetwork_train_algorithm};

  my %vocabulary;
  if (defined $conf->{neuralnetwork_dsn} && $self->{dbh}) {
    my $vocab_ref = $self->_load_vocabulary_from_sql($self->{main}->{username});
    %vocabulary = %{$vocab_ref} if ref($vocab_ref) eq 'HASH';
  }
  if (!keys %{$vocabulary{terms} || {}}) {
    my $vocab_path = File::Spec->catfile($nn_data_dir, 'vocabulary-' . lc($self->{main}->{username}) . '.data');
    if (-f $vocab_path) {
      eval {
        my $ref = retrieve($vocab_path);
        %vocabulary = %{$ref} if ref $ref eq 'HASH';
        1;
      } or do {
        info("Failed to load vocabulary for retraining: " . ($@ || 'unknown'));
        return;
      };
    }
  }

  my $terms = $vocabulary{terms} || {};
  return unless scalar keys %{$terms};

  my @vocab_keys;
  if (defined $restricted_keys_ref) {
    @vocab_keys = @$restricted_keys_ref;
    $vocab_size = scalar @vocab_keys;
  } else {
    @vocab_keys = sort keys %{$terms};
    my $actual_size = scalar @vocab_keys;
    return unless $actual_size == $vocab_size;
  }

  my $spam_docs = $vocabulary{_spam_count} || 1;
  my $ham_docs  = $vocabulary{_ham_count}  || 1;

  # For SQL-backed deployments, _tbuf is not stored in neural_vocabulary.
  if (defined $conf->{neuralnetwork_dsn} && $self->{dbh}) {
    my $meta = $self->_load_meta($conf);
    if (ref($meta->{_tbuf}) eq 'HASH') {
      $vocabulary{_tbuf} = $meta->{_tbuf};
      dbg("Training buffer loaded from SQL tables for batch retrain");
    }
  }

  dbg("Retraining from vocabulary: spam_docs=$spam_docs, ham_docs=$ham_docs, " .
      "epochs=$train_epochs (no class-weight upweighting)");

  # Build a class-balanced training batch from the training buffer. The buffer
  # stores tokens (not vectors) so it survives vocabulary changes -- we
  # re-vectorize against the current vocabulary every retrain.
  #
  # Balance via min(n_spam, n_ham): RPROP minimises MSE across the full
  # batch, and on imbalanced data the optimal constant predictor sits at
  # the class prior (e.g. 1/3 for a 2:1 ham-heavy mix), well below
  # ham_threshold=0.4 -- so an unbalanced batch produces a ham-biased
  # classifier even when discriminative features are available. Downsampling
  # the majority restores the bias-free gradient.
  #
  # When one class is entirely absent from the buffer, no balanced batch
  # exists at all. Return undef so the caller can skip model creation
  # rather than fall back to a degenerate one-class fit.
  my $buf_ref = $vocabulary{_tbuf};
  unless (ref($buf_ref) eq 'HASH') {
    dbg("Batch retrain skipped: training buffer is not available");
    return;
  }
  my @spam_toks = map { $_->{tokens} } @{ $buf_ref->{spam} || [] };
  my @ham_toks  = map { $_->{tokens} } @{ $buf_ref->{ham}  || [] };
  my $n_spam = scalar @spam_toks;
  my $n_ham  = scalar @ham_toks;
  if ($n_spam == 0 || $n_ham == 0) {
    dbg("Batch retrain skipped: training buffer is one-sided " .
        "(spam=$n_spam, ham=$n_ham)");
    return;
  }

  my $n_pc = $n_spam < $n_ham ? $n_spam : $n_ham;
  my (@sub_spam, @sub_ham);
  if ($n_pc >= 2) {
    # Both classes have enough samples to balance cleanly; downsample the
    # majority to match the minority so RPROP's batch MSE has no class-prior
    # bias.
    Mail::SpamAssassin::Util::fisher_yates_shuffle(\@spam_toks);
    Mail::SpamAssassin::Util::fisher_yates_shuffle(\@ham_toks);
    @sub_spam = @spam_toks[0 .. $n_pc - 1];
    @sub_ham  = @ham_toks [0 .. $n_pc - 1];
  } else {
    # Minority has exactly 1 sample. Balancing to (1,1) leaves the network
    # underdetermined; keep all available samples instead. The imbalance
    # remaining is a 5:1 or 14:1 ratio at most, which biases the model but
    # less severely than training on a 1:1 batch of just 2 examples. The
    # imbalance self-corrects as the buffer fills and n_pc crosses 2.
    @sub_spam = @spam_toks;
    @sub_ham  = @ham_toks;
  }
  my $sub_n_spam = scalar @sub_spam;
  my $sub_n_ham  = scalar @sub_ham;
  my @batch_toks = (@sub_spam, @sub_ham);

  my ($batch_vecs) = _text_to_features(
    $self, $conf, $nn_data_dir, 2, undef, \@vocab_keys, @batch_toks);
  unless (ref($batch_vecs) eq 'ARRAY' && scalar(@$batch_vecs) == $sub_n_spam + $sub_n_ham) {
    dbg("Batch retrain skipped: vectorisation failed");
    return;
  }

  my @balanced_minibatch;
  for my $i (0 .. $#$batch_vecs) {
    push @balanced_minibatch, {
      vec   => $batch_vecs->[$i]{vec},
      label => ($i < $sub_n_spam) ? 1 : 0,
    };
  }
  dbg("Batch retrain: ${sub_n_spam} spam + ${sub_n_ham} ham " .
      "(buffered: $n_spam spam, $n_ham ham; balanced=" .
      ($n_pc >= 2 ? 'yes' : 'no, minority=1') . ")");

  # Append class-prototype vectors as additional anchor samples. The
  # prototypes are built from the vocabulary's full term-level spam/ham
  # statistics; they encode the LONG-TERM class signature.
  my ($spam_proto_ref, $ham_proto_ref) =
    _build_class_tfidf_vectors(\%vocabulary, \@vocab_keys);
  if ($spam_proto_ref && $ham_proto_ref) {
    my $spam_nonzero = scalar grep { $_ != 0 } @$spam_proto_ref;
    my $ham_nonzero  = scalar grep { $_ != 0 } @$ham_proto_ref;
    if ($spam_nonzero > 0 || $ham_nonzero > 0) {
      push @balanced_minibatch, { vec => $spam_proto_ref, label => 1 };
      push @balanced_minibatch, { vec => $ham_proto_ref,  label => 0 };
      dbg("Batch retrain: appended class-prototype anchors " .
          "(spam_proto nonzeros=$spam_nonzero, ham_proto nonzeros=$ham_nonzero)");
    }
  }

  # Two-layer hidden sizing: layer1 ~0.25*sqrt(vocab), layer2 half of layer1.
  my $num_hidden1 = int(sqrt($vocab_size) * 0.25 + 0.5);
  $num_hidden1 = 4 if $num_hidden1 < 4;
  my $num_hidden2 = int($num_hidden1 / 2);
  $num_hidden2 = 2 if $num_hidden2 < 2;
  my $network = AI::FANN->new_standard($vocab_size, $num_hidden1, $num_hidden2, 1);
  $network->learning_rate($learning_rate);
  $network->learning_momentum($momentum);

  # Always use full-batch RPROP for the retrain
  $network->training_algorithm(FANN_TRAIN_RPROP);
  $network->hidden_activation_function(FANN_SIGMOID);
  $network->output_activation_function(FANN_SIGMOID);
  $network->rprop_delta_max($conf->{neuralnetwork_rprop_delta_max});

  # Build training dataset from the balanced training-buffer batch.
  my (@td_inputs, @td_outputs);
  for my $entry (@balanced_minibatch) {
    push @td_inputs,  $entry->{vec};
    push @td_outputs, [$entry->{label}];
  }

  my $n_td = scalar @td_inputs;
  my $train_data = eval {
    my $td = AI::FANN::TrainData->new_empty($n_td, $vocab_size, 1);
    for my $i (0 .. $n_td - 1) {
      $td->data($i, $td_inputs[$i], $td_outputs[$i]);
    }
    $td;
  };
  if (!defined $train_data) {
    dbg("Failed to create TrainData for batch retrain: " . ($@ || 'unknown'));
    return ($network, \@vocab_keys);
  }

  # RPROP epoch budget. Early stopping at MSE < 0.05 prevents RPROP from
  # driving weights to extreme values on small training sets (saturation).
  # A model reaching MSE 0.05 produces outputs in the [0.2, 0.8] range,
  # well within the NN_SPAM (>0.6) and NN_HAM (<0.4) default detection thresholds.
  my $batch_epochs = $train_epochs * 10;
  $batch_epochs = 500 if $batch_epochs < 500;
  my $target_mse  = 0.05;
  my $actual_epochs = 0;
  my $final_mse;
  for my $e (1 .. $batch_epochs) {
    my $mse = eval { $network->train_epoch($train_data) };
    if (!defined $mse) {
      dbg("Batch retrain epoch $e failed: " . ($@ || 'unknown'));
      next;
    }
    $actual_epochs = $e;
    $final_mse     = $mse;
    last if $mse < $target_mse;
  }
  dbg("Batch retrain complete: $n_td sample(s), $actual_epochs epoch(s), " .
      "final MSE=" . (defined $final_mse ? sprintf("%.4f", $final_mse) : 'undef'));

  return ($network, \@vocab_keys);
}

# Rename $src to $dst atomically. Falls back to copy+unlink when rename(2)
# fails with EXDEV (src and dst on different filesystems).
sub _rename_or_copy {
  my ($src, $dst) = @_;
  return 1 if rename($src, $dst);
  return 0 unless $! == EXDEV;
  dbg("rename cross-device ($src -> $dst); falling back to copy+unlink");
  return copy($src, $dst) && unlink($src);
}

# Returns indices of inputs whose L2 norm of outgoing weights to hidden-1
# meets or exceeds $threshold. Reads weights via a temp FANN save file since
# AI::FANN does not expose a direct weight-access API.
sub _prune_inputs_by_weight_norm {
  my ($network, $num_input, $num_hidden1, $threshold) = @_;

  my ($tmpfile, $fh) = Mail::SpamAssassin::Util::secure_tmpfile();
  unless (defined $tmpfile) {
    dbg("_prune_inputs_by_weight_norm: could not create temp file");
    return 0 .. $num_input - 1;
  }
  close $fh;
  my $save_ok = eval { $network->save($tmpfile); 1 };
  unless ($save_ok) {
    dbg("_prune_inputs_by_weight_norm: save failed: " . ($@ || 'unknown'));
    unlink $tmpfile;
    return 0 .. $num_input - 1;
  }

  my $conn_line;
  open(my $rfh, '<', $tmpfile) or do {
    dbg("_prune_inputs_by_weight_norm: open failed: $!");
    unlink $tmpfile;
    return 0 .. $num_input - 1;
  };
  while (<$rfh>) { if (/^connections/) { $conn_line = $_; last } }
  close $rfh;
  unlink $tmpfile;

  unless (defined $conn_line) {
    dbg("_prune_inputs_by_weight_norm: no connections line in saved model");
    return 0 .. $num_input - 1;
  }

  my @weights = ($conn_line =~ /\([^,]+,\s*([-+eE\d.]+)\)/g);
  # Connections are grouped by destination hidden-1 neuron.
  # Group h occupies positions h*(num_input+1) .. (h+1)*(num_input+1)-1.
  # Position i within each group is weight from input i.
  my @norms;
  for my $i (0 .. $num_input - 1) {
    my $sq = 0;
    for my $h (0 .. $num_hidden1 - 1) {
      my $w = $weights[$h * ($num_input + 1) + $i] // 0;
      $sq += $w * $w;
    }
    $norms[$i] = sqrt($sq);
  }

  return grep { $norms[$_] >= $threshold } 0 .. $num_input - 1;
}

sub _check_neuralnetwork {
  my ($self, $pms) = @_;

  my $conf = $self->{main}->{conf};
  return unless $conf->{use_neuralnetwork};
  return 0 if (!$self->{main}->{conf}->{use_learner});
  
  my $msg = $pms->{msg};

  if(exists $pms->{neuralnetwork_prediction}) {
    return;
  }

  $self->_init_sql_connection($conf) if defined $conf->{neuralnetwork_dsn};
  my $min_text_len = $conf->{neuralnetwork_min_text_len};
  my $spam_threshold = $conf->{neuralnetwork_spam_threshold};
  my $ham_threshold  = $conf->{neuralnetwork_ham_threshold};

  my $vis_text = $self->_get_visible_text($msg);
  if (length($vis_text) < $min_text_len) {
    $pms->{neuralnetwork_prediction} = undef;
    dbg("Too short email text");
    return;
  }
  my $tokens_ref = $self->_extract_features_from_message($pms, $conf, $msg);

  my $nn_data_dir = $self->{main}->{conf}->{neuralnetwork_data_dir};
  $nn_data_dir = Mail::SpamAssassin::Util::untaint_file_path($nn_data_dir);
  if (not -d $nn_data_dir) {
    $pms->{neuralnetwork_prediction} = undef;
    info("Invalid neuralnetwork_data_dir path");
    return;
  }

  my $dataset_path = Mail::SpamAssassin::Util::untaint_file_path($self->_model_path($nn_data_dir));
  if(not -f $dataset_path) {
    $pms->{neuralnetwork_prediction} = undef;
    dbg("Can't predict without a trained model, $dataset_path cannot be read");
    return;
  }

  # Reload model if it has expired or the file has changed since last load
  my $ttl = $conf->{neuralnetwork_cache_ttl} || 0;
  my $model_age = defined $self->{_neural_model_load_time} ? time() - $self->{_neural_model_load_time} : undef;
  my $model_expired = defined $model_age && $ttl > 0 && $model_age >= $ttl;
  my $model_mtime   = (stat($dataset_path))[9] // 0;
  my $model_changed = $model_mtime > ($self->{_neural_model_load_time} // 0);

  my $locker = $self->{main}->{locker};
  my $network;

  if (!defined $self->{neural_model} || $model_expired || $model_changed) {
    if ($model_expired) {
      dbg("Model cache expired (age: ${model_age}s, ttl: ${ttl}s), reloading");
    } elsif ($model_changed) {
      dbg("Model file changed on disk, reloading");
    }

    my $file_mode = 0666 & ~umask();

    my $loaded = eval { AI::FANN->new_from_file($dataset_path) };
    if ($loaded && $loaded->num_outputs() == 1) {
      my $mtest = $self->_load_model_vocab($nn_data_dir);
      if (!defined $mtest || !@$mtest) {
        dbg("Model vocab absent in SQL/file; discarding loaded model to force rebuild");
        undef $loaded;
      } elsif (scalar(@$mtest) != $loaded->num_inputs()) {
        dbg("Model vocab size (" . scalar(@$mtest) . ") != model inputs (" .
            $loaded->num_inputs() . "); discarding stale model to force rebuild");
        undef $loaded;
      }
    }
    if ($loaded && $loaded->num_outputs() == 1) {
      $self->{neural_model}            = $loaded;
      $self->{_neural_model_load_time} = time();
      $network = $loaded;
    } else {
      my $err = $@ || 'unknown';
      if ($loaded) {
        dbg("Loaded model has wrong output count (" . $loaded->num_outputs() .
            "); discarding and rebuilding");
        undef $loaded;
      } else {
        my @stat = stat($dataset_path);
        my $fsize = @stat ? $stat[7] : 'N/A';
        dbg("Failed to load model for prediction: $err "
          . "(path=$dataset_path, size=${fsize}B), attempting vocabulary rebuild");
      }

      undef $self->{neural_model};

      # skip prediction if we cannot acquire the lock fast enough
      my $got_lock = 0;
      eval { $got_lock = $locker->safe_lock($dataset_path, 1); 1; };
      if (!$got_lock) {
        dbg("another worker is rebuilding the model; skipping prediction");
        return;
      }

      my ($rebuilt, $rebuilt_keys);
      eval {
        my $vref = $self->_load_model_vocab($nn_data_dir);
        my $vsz;
        my $vsz_from_model_pos = 0;
        if (defined $vref && @$vref) {
          $vsz = scalar(@$vref);
          $vsz_from_model_pos = 1;
        } else {
          my $cv    = $self->_load_vocabulary($conf, $nn_data_dir, 0);
          my $terms = (ref($cv) eq 'HASH') ? ($cv->{terms} || {}) : {};
          $vsz      = scalar keys %$terms;
          dbg("Model vocab absent; rebuilding from current vocabulary ($vsz terms)");
        }
        ($rebuilt, $rebuilt_keys) = $self->_retrain_from_vocabulary($conf, $nn_data_dir, $vsz) if $vsz > 0;
        # If the SQL vocabulary size has diverged from the stored model_position count
        # (e.g. tokens removed/added since the last model save), _retrain_from_vocabulary
        # returns undef because its size check fails. Retry with the actual current size.
        if (!defined $rebuilt && $vsz_from_model_pos) {
          my $cv    = $self->_load_vocabulary($conf, $nn_data_dir, 0);
          my $terms = (ref($cv) eq 'HASH') ? ($cv->{terms} || {}) : {};
          my $cur   = scalar keys %$terms;
          if ($cur > 0 && $cur != $vsz) {
            dbg("Retrying rebuild with current vocabulary size ($cur vs model_position $vsz)");
            ($rebuilt, $rebuilt_keys) = $self->_retrain_from_vocabulary($conf, $nn_data_dir, $cur);
          }
        }
        1;
      } or dbg("Vocabulary rebuild failed: " . ($@ || 'unknown'));

      # Release the rebuild lock before the FANN save.
      $locker->safe_unlock($dataset_path);

      if (!$rebuilt) {
        dbg("Vocabulary rebuild failed");
        return;
      }

      dbg("Vocabulary rebuild succeeded");
      $self->{neural_model}            = $rebuilt;
      $self->{_neural_model_load_time} = time();

      eval {
        my ($tmp_path, $tmp_fh) = Mail::SpamAssassin::Util::secure_tmpfile();
        die "could not create temp file" unless defined $tmp_path;
        close $tmp_fh;
        $tmp_path = Mail::SpamAssassin::Util::untaint_file_path($tmp_path);
        chmod($file_mode, $tmp_path) or info("chmod $file_mode on '$tmp_path' failed: $!");
        if ($rebuilt->save($tmp_path)) {
          _rename_or_copy($tmp_path, $dataset_path)
            or die "rename/copy failed: $!";
          delete $self->{_model_vocab_cache};
          delete $self->{_model_vocab_cache_t};
          my @rkeys = ($rebuilt_keys && @$rebuilt_keys)
              ? @$rebuilt_keys
              : do {
                  my $cv = $self->_load_vocabulary($conf, $nn_data_dir, 0);
                  sort keys %{ (ref($cv) eq 'HASH' ? ($cv->{terms} || {}) : {}) };
              };
          if (@rkeys) {
            if (defined $conf->{neuralnetwork_dsn} && $self->{dbh}) {
              $self->_save_model_vocab_to_sql(\@rkeys);
            } else {
              $self->_save_model_vocab(\@rkeys, $nn_data_dir);
            }
          }
          dbg("Persisted rebuilt model to '$dataset_path'");
        } else {
          unlink $tmp_path;
        }
        1;
      } or dbg("Could not persist rebuilt model: " . ($@ || 'unknown'));

      $network = $rebuilt;
    }
  } else {
    $network = $self->{neural_model};
  }

  my $stored_vocab_ref = $self->_load_model_vocab($nn_data_dir);

  # Guard: model out of sync with SQL model_position (race condition or stale
  # state from a rebuild that saved model_position with a different count).
  # For long-running daemons: invalidate the in-memory cache so the next
  # request reloads cleanly.  For one-shot invocations (spamassassin(1)):
  # fall back to an undef stored_vocab_ref so _text_to_features uses the
  # current SQL vocabulary; any remaining size difference is handled by
  # _adjust_vector_size and we still produce a prediction.
  if ($network && defined $stored_vocab_ref && @$stored_vocab_ref
      && scalar(@$stored_vocab_ref) != $network->num_inputs()) {
    dbg("Model/vocab inconsistency (vocab=" . scalar(@$stored_vocab_ref) .
        ", model=" . $network->num_inputs() . "); invalidating model cache, using SQL vocabulary for this prediction");
    undef $self->{neural_model};
    undef $self->{_neural_model_load_time};
    undef $stored_vocab_ref;
  }

  # Do not update the vocabulary
  my $update_vocab = 0;

  # Convert email to feature vector using the model's vocabulary
  my ($feature_vectors, $vocab_size) = _text_to_features($self, $conf, $nn_data_dir, $update_vocab, undef, $stored_vocab_ref, $tokens_ref);
  unless ($feature_vectors && @$feature_vectors) {
    $pms->{neuralnetwork_prediction} = undef;
    dbg("Not enough tokens found");
    return;
  }

  my $min_hits = $conf->{neuralnetwork_min_vocab_hits};
  my $hits     = $feature_vectors->[0]{hits};
  if ($hits < $min_hits) {
    $pms->{neuralnetwork_prediction} = undef;
    dbg("Too few vocabulary hits ($hits < $min_hits), skipping prediction");
    return;
  }
  my $input_vector = $feature_vectors->[0]{vec};

  my $expected_size = $network->num_inputs();
  if (scalar(@$input_vector) != $expected_size) {
    # Fallback for models created before vocab tracking was introduced
    dbg("Input vector size mismatch (got ".scalar(@$input_vector).", model expects ".$expected_size."), adjusting");
    $input_vector = _adjust_vector_size($input_vector, $expected_size);
    unless (defined $input_vector && scalar(@$input_vector) == $expected_size) {
      $pms->{neuralnetwork_prediction} = undef;
      info("Adjusted vector invalid, skipping prediction");
      return;
    }
  }

  my $prediction = eval { $network->run($input_vector) } ;
  if ($@) {
    $pms->{neuralnetwork_prediction} = undef;
    dbg("Prediction failed: $@");
    return;
  }
  $prediction = ref($prediction) ? $prediction->[0] : $prediction;

  unless(defined $prediction) {
    dbg("No prediction available");
    $pms->{neuralnetwork_prediction} = undef;
    return;
  }

  if ($prediction > $spam_threshold) {
    $pms->{neuralnetwork_spam} = 1;
    dbg("Prediction for email : spam ($prediction)");
  } elsif ($prediction < $ham_threshold) {
    $pms->{neuralnetwork_ham} = 1;
    dbg("Prediction for email : ham ($prediction)");
  } else {
    dbg("Prediction for email : unknown ($prediction)");
  }
  $pms->{neuralnetwork_prediction} = $prediction;
  return;
}

sub _init_sql_connection {
  my ($self, $conf) = @_;

  # Reconnect in each child process to prevent SQL protocol state corruption
  if ($self->{dbh} && ($self->{_dbh_pid} || 0) != $$) {
    eval {
      local $SIG{PIPE} = 'IGNORE';
      $self->{dbh}->disconnect();
    };
    undef $self->{dbh};
  }

  return if $self->{dbh};
  return if !$conf->{neuralnetwork_dsn};

  my $dsn      = $conf->{neuralnetwork_dsn};
  my $username = $conf->{neuralnetwork_username} || '';
  my $password = $conf->{neuralnetwork_password} || '';

  eval {
    local $SIG{'__DIE__'};
    require DBI;
    my %attrs = (RaiseError => 1, PrintError => 0, InactiveDestroy => 1, AutoCommit => 1);
    # Enable 4-byte UTF-8 on MySQL/MariaDB so tokens with emoji or other
    # multi-byte codepoints insert cleanly into the utf8mb4 schema columns.
    if ($dsn =~ /^dbi:mysql/i) {
      $attrs{mysql_enable_utf8mb4} = 1;
    }
    $self->{dbh} = DBI->connect($dsn, $username, $password, \%attrs);
    # use SET NAMES in case the DSN or server default differs.
    if ($dsn =~ /^dbi:(?:mysql)/i) {
      eval { $self->{dbh}->do("SET NAMES 'utf8mb4'") };
    }
    $self->{_dbh_pid} = $$;
    $self->_create_vocabulary_table();
    dbg("SQL connection initialized for vocabulary storage (pid $$)");
    1;
  } or do {
    my $err = $@ || 'unknown';
    warn "NeuralNetwork: SQL connection failed: $err\n";
    undef $self->{dbh};
  };
}

sub _create_vocabulary_table {
  my ($self) = @_;
  return if !$self->{dbh};

  eval {
    if ($self->{dbh}->{Driver}->{Name} eq 'SQLite') {
      $self->{dbh}->do("
        CREATE TABLE IF NOT EXISTS neural_vocabulary (
          username VARCHAR(200) NOT NULL DEFAULT '',
          keyword VARCHAR(256) NOT NULL DEFAULT '',
          total_count INTEGER NOT NULL DEFAULT 0,
          docs_count INTEGER NOT NULL DEFAULT 0,
          spam_count INTEGER NOT NULL DEFAULT 0,
          ham_count INTEGER NOT NULL DEFAULT 0,
          model_position INTEGER DEFAULT NULL,
          UNIQUE (username, keyword)
        )
      ");
      $self->{dbh}->do("
        CREATE TABLE IF NOT EXISTS neural_seen (
          username VARCHAR(200) NOT NULL DEFAULT 'default',
          msgid VARCHAR(200) NOT NULL DEFAULT '',
          flag CHAR(1) NOT NULL DEFAULT '',
          UNIQUE (username, msgid)
        )
      ");
      $self->{dbh}->do("
        CREATE TABLE IF NOT EXISTS neural_vars (
          username VARCHAR(200) NOT NULL DEFAULT '',
          variable VARCHAR(30)  NOT NULL DEFAULT '',
          value    VARCHAR(200) NOT NULL DEFAULT '',
          PRIMARY KEY (username, variable)
        )
      ");
      $self->{dbh}->do("
        CREATE TABLE IF NOT EXISTS neural_training_buffer (
          username VARCHAR(200) NOT NULL DEFAULT '',
          class    VARCHAR(4)   NOT NULL CHECK (class IN ('spam', 'ham')),
          slot     INTEGER      NOT NULL DEFAULT 0,
          ts       INTEGER      NOT NULL DEFAULT 0,
          token    VARCHAR(256) NOT NULL DEFAULT '',
          count    INTEGER      NOT NULL DEFAULT 1,
          PRIMARY KEY (username, class, slot, token)
        )
      ");
      dbg("Vocabulary tables created or already exist");
    }
    1;
  } or do {
    my $err = $@ || 'unknown';
    dbg("Failed to create vocabulary tables: $err");
  };
}

sub _save_msgid_to_neural_seen {
  my ($self, $msgid, $isspam) = @_;
  return unless defined $msgid && length($msgid) > 0;

  # XXX Save to file-based neural_seen if no SQL configured
  if (!defined $self->{main}->{conf}->{neuralnetwork_dsn} || !$self->{dbh}) {
    return;
  }

  eval {
    # Flag: 'S' for spam, 'H' for ham
    my $flag = $isspam ? 'S' : 'H';
    my $username = lc($self->{main}->{username}) || 'default';

    my $insert_sql;

    if ($self->{main}->{conf}->{neuralnetwork_dsn} =~ /^dbi:(?:mysql|MariaDB)/i) {
      # MySQL
      $insert_sql = "
        INSERT IGNORE INTO neural_seen (username, msgid, flag)
        VALUES (?, ?, ?)
      ";
    } elsif ($self->{main}->{conf}->{neuralnetwork_dsn} =~ /^dbi:SQLite/i) {
      # SQLite
      $insert_sql = "
        INSERT OR IGNORE INTO neural_seen (username, msgid, flag)
        VALUES (?, ?, ?)
      ";
    } else {
      # PostgreSQL
      $insert_sql = "
        INSERT INTO neural_seen (username, msgid, flag)
        VALUES (?, ?, ?)
        ON CONFLICT (username, msgid) DO NOTHING
      ";
    }

    my $sth = $self->{dbh}->prepare($insert_sql);
    if(not $sth->execute($username, $msgid, $flag)) {
      info("Error learning from message $msgid");
      return;
    }

    dbg("Recorded learned message: $msgid");
    1;
  } or do {
    my $err = $@ || 'unknown';
    dbg("Failed to save message ID to neural_seen: $err");
  };
}

sub _is_msgid_in_neural_seen {
  my ($self, $msgid) = @_;
  return unless defined $msgid && length($msgid) > 0;

  # XXX Save to file-based neural_seen if no SQL configured
  if (!defined $self->{main}->{conf}->{neuralnetwork_dsn} || !$self->{dbh}) {
    return;
  }

  my $type;
  eval {
    my $username = lc($self->{main}->{username}) || 'default';

    my $select_sql = "
        SELECT flag FROM neural_seen WHERE username=? AND msgid=?
      ";
    my $sth = $self->{dbh}->prepare($select_sql);
    $sth->execute($username, $msgid);
    my $row = $sth->fetchrow_arrayref();

    $type = $row->[0] if $row;
    1;
  } or do {
    if($@) {
      dbg("Failed to find message ID on neural_seen: $@");
    }
  };
  return $type;
}

sub _save_vocabulary_to_sql {
  my ($self, $term_deltas, $username) = @_;
  return unless $self->{dbh} && defined $term_deltas && ref($term_deltas) eq 'HASH';

  $username //= $self->{main}->{username};

  eval {
    return unless scalar keys %{$term_deltas};

    my $upsert_sql;

    if ($self->{main}->{conf}->{neuralnetwork_dsn} =~ /^dbi:(?:mysql|MariaDB)/i) {
      $upsert_sql = "
        INSERT INTO neural_vocabulary (username, keyword, total_count, docs_count, spam_count, ham_count)
        VALUES (?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
          total_count = total_count + VALUES(total_count),
          docs_count  = docs_count  + VALUES(docs_count),
          spam_count  = spam_count  + VALUES(spam_count),
          ham_count   = ham_count   + VALUES(ham_count)
      ";
    } else {
      $upsert_sql = "
        INSERT INTO neural_vocabulary (username, keyword, total_count, docs_count, spam_count, ham_count)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT (username, keyword) DO UPDATE SET
          total_count = neural_vocabulary.total_count + excluded.total_count,
          docs_count  = neural_vocabulary.docs_count  + excluded.docs_count,
          spam_count  = neural_vocabulary.spam_count  + excluded.spam_count,
          ham_count   = neural_vocabulary.ham_count   + excluded.ham_count
      ";
    }

    my $sth_upsert = $self->{dbh}->prepare($upsert_sql);
    my $count = 0;

    $self->{dbh}->begin_work();
    foreach my $keyword (sort keys %{$term_deltas}) {
      my $delta = $term_deltas->{$keyword};
      $sth_upsert->execute(
        lc($username),
        $keyword,
        $delta->{total} || 0,
        $delta->{docs}  || 0,
        $delta->{spam}  || 0,
        $delta->{ham}   || 0
      );
      $count++;
    }
    $self->{dbh}->commit();

    dbg("Applied $count vocabulary term deltas to SQL for user: $username");

    # Invalidate cache for this user
    if (defined $self->{_vocab_cache}) {
      delete $self->{_vocab_cache}{$username};
      delete $self->{_vocab_cache_time}{$username};
    }
    1;
  } or do {
    my $err = $@ || 'unknown';
    eval { $self->{dbh}->rollback() if !$self->{dbh}{AutoCommit} };
    dbg("Failed to save vocabulary to SQL: $err");
  };
}

# Aggregates training-buffer slot token arrays into vocabulary delta counts and
# persists them via _save_vocabulary_to_sql. Does NOT delete SQL training-buffer
# rows, rows will be deleted by the caller.
sub _merge_slots_to_vocabulary {
  my ($self, $slots_ref, $class) = @_;
  return unless $self->{dbh} && ref($slots_ref) eq 'ARRAY' && @$slots_ref;
  my %deltas;
  for my $slot (@$slots_ref) {
    my %seen;
    for my $tok (@{ $slot->{tokens} || [] }) {
      $deltas{$tok}{total} = ($deltas{$tok}{total} || 0) + 1;
      $deltas{$tok}{docs}  = ($deltas{$tok}{docs}  || 0) + 1 unless $seen{$tok}++;
      if ($class eq 'spam') { $deltas{$tok}{spam} = ($deltas{$tok}{spam} || 0) + 1 }
      else                  { $deltas{$tok}{ham}  = ($deltas{$tok}{ham}  || 0) + 1 }
    }
  }
  $self->_save_vocabulary_to_sql(\%deltas, $self->{main}->{username}) if %deltas;
}

# Merges both spam and ham training-buffer slots into neural_vocabulary.
sub _flush_training_buffer {
  my ($self, $tbuf) = @_;
  return unless $self->{dbh} && ref($tbuf) eq 'HASH';
  for my $class (qw(spam ham)) {
    my $slots = $tbuf->{$class} || [];
    $self->_merge_slots_to_vocabulary($slots, $class) if @$slots;
  }
}

# Returns true if the SQL training buffer has enough staged tokens to warrant
# a retrain (vocab_cap threshold reached).
sub _training_buffer_flush_needed {
  my ($self, $conf, $buf_state) = @_;
  return 0 unless $self->{dbh};

  my $vocab_cap = $conf->{neuralnetwork_vocab_cap};
  my $distinct  = 0;
  eval {
    my $sth = $self->{dbh}->prepare(
      "SELECT COUNT(DISTINCT token) FROM neural_training_buffer WHERE username=?"
    );
    $sth->execute(lc($self->{main}->{username}));
    ($distinct) = $sth->fetchrow_array();
    1;
  } or dbg("Failed to count distinct training buffer tokens: " . ($@ || 'unknown'));
  return 1 if $distinct >= $vocab_cap;

  return 0;
}

# Header whitelist used by _extract_features_from_message
my %_NN_HEADER_PREFIX = (
  'Subject'      => 'H*sub:',
  'From'         => 'H*frm:',
  'Reply-To'     => 'H*rpt:',
  'Return-Path'  => 'H*rpa:',
  'To'           => 'H*to:',
  'Cc'           => 'H*cc:',
);

sub _tokenize_header_value {
  my ($prefix, $value) = @_;
  return () unless defined $value && length $value;

  $value = lc $value;
  $value =~ s/[\r\n]+/ /g;
  $value =~ s/"//g;
  # Keep alphanumerics, dots, @ and dashes inside tokens
  $value =~ s/[^\p{L}\p{N}\.\@\-_]+/ /g;

  my @out;
  for my $p (split /\s+/, $value) {
    my $len = length $p;
    next if $len < 2 || $len > 80;
    next if $p =~ /^\-/;
    push @out, $prefix . $p;
  }
  return @out;
}

sub _tokenize_uri {
  my ($uri) = @_;
  return () unless defined $uri && length $uri;

  $uri = lc $uri;
  my @out;
  my $capped = length($uri) > 80 ? substr($uri, 0, 80) : $uri;
  push @out, 'U*:' . $capped;

  if ($uri =~ m{(?:[a-z][a-z0-9+\-.]*:)?//([^/\s\?\#]+)}) {
    my $host = $1;
    $host =~ s/^[^\@]*\@//;  # strip user-info
    $host =~ s/:\d+$//;       # strip port
    if (length $host) {
      push @out, 'D*:' . $host;
      if ($host =~ /([^.]+\.[^.]+)$/) {
        push @out, 'D*:' . $1;
      }
    }
  }
  return @out;
}

sub _extract_uris_from_msg {
  my ($pms) = @_;

  return () unless defined $pms;

  my @uris;
  my $uris = $pms->get_uri_detail_list();
  my %huris = %{$uris};
  foreach my $uri (keys %huris) {
    push(@uris, $uri);
  }
  return @uris;
}

# Build a flat list of prefixed tokens drawn from the visible body, the
# invisible (HTML-hidden) body, a small whitelist of headers, the URIs in
# the message, and the MIME-part digests.
sub _extract_features_from_message {
  my ($self, $pms, $conf, $msg) = @_;
  my @tokens;
  return \@tokens unless defined $msg;

  my $vis_arr = $msg->get_visible_rendered_body_text_array();
  if (ref $vis_arr eq 'ARRAY' && @$vis_arr) {
    push @tokens, $self->_tokenize_text($conf, join("\n", @$vis_arr));
  }

  my $inv_arr = eval { $msg->get_invisible_rendered_body_text_array() };
  if (ref $inv_arr eq 'ARRAY' && @$inv_arr) {
    my @inv_tok = $self->_tokenize_text($conf, join("\n", @$inv_arr));
    push @tokens, map { 'I*:' . $_ } @inv_tok;
  }

  for my $h (sort keys %_NN_HEADER_PREFIX) {
    my $val = eval { $msg->get_pristine_header($h) };
    next unless defined $val;
    push @tokens, _tokenize_header_value($_NN_HEADER_PREFIX{$h}, $val);
  }

  for my $u (_extract_uris_from_msg($pms)) {
    push @tokens, _tokenize_uri($u);
  }

  my $mp = eval { $msg->get_mimepart_digests() };
  if (ref $mp eq 'ARRAY') {
    for my $d (@$mp) {
      next unless defined $d && length $d;
      my $t = lc $d;
      $t = substr($t, 0, 80) if length $t > 80;
      push @tokens, 'M*:' . $t;
    }
  }

  @tokens = grep { defined } map { _sanitize_token($_) } @tokens;
  return \@tokens;
}

# Canonicalize a token so its identity is stable across token sources and
# survives a round-trip through a SQL keyword index.
sub _sanitize_token {
  my ($t) = @_;
  return undef unless defined $t;
  if (!utf8::is_utf8($t) && $t =~ /[^\x00-\x7f]/) {
    require Encode;
    $t = Encode::decode('UTF-8', $t, Encode::FB_DEFAULT());
  }
  $t =~ s/[\s\p{Cc}\p{Cf}\p{Zs}\p{Zl}\p{Zp}]//g;
  return length($t) ? $t : undef;
}

my %_HTML_ENTITIES = (
  # core XML/HTML escapes
  amp   => '&',   lt    => '<',   gt    => '>',
  quot  => '"',   apos  => "'",   nbsp  => ' ',
  # symbols
  euro  => 'eur', pound => 'gbp', yen   => 'jpy',
  cent  => 'cent', curren => ' ',
  # dashes and quotation marks
  mdash => '-',   ndash => '-',   minus => '-',   horbar => '-',
  laquo => ' ',   raquo => ' ',
  ldquo => '"',   rdquo => '"',   bdquo => '"',
  lsquo => "'",   rsquo => "'",   sbquo => "'",
  # other punctuation / typography
  hellip => '...',
  # accented letters
  agrave => 'a',  aacute => 'a',  acirc  => 'a',  atilde => 'a',
  auml   => 'a',  aring  => 'a',  aelig  => 'ae',
  egrave => 'e',  eacute => 'e',  ecirc  => 'e',  euml   => 'e',
  igrave => 'i',  iacute => 'i',  icirc  => 'i',  iuml   => 'i',
  ograve => 'o',  oacute => 'o',  ocirc  => 'o',  otilde => 'o',
  ouml   => 'o',  oslash => 'o',  oelig  => 'oe',
  ugrave => 'u',  uacute => 'u',  ucirc  => 'u',  uuml   => 'u',
  yacute => 'y',  yuml   => 'y',
  ntilde => 'n',  ccedil => 'c',  szlig  => 'ss',
  eth    => 'd',  thorn  => 'th',
);

sub _tokenize_text {
  my ($self, $conf, $text) = @_;
  return () unless defined $text;

  my $min_word_len = $conf->{neuralnetwork_min_word_len};
  my $max_word_len = $conf->{neuralnetwork_max_word_len};
  my %stopwords = map { lc($_) => 1 } split /\s+/, $conf->{neuralnetwork_stopwords};

  $text = lc $text;
  # Strip subject prefixes, enhances results
  $text =~ s/^(?:[a-z]{2,12}:\s*){1,10}//i;
  # Strip anything that looks like url or email, enhances results
  $text =~ s/https?(?:\:\/\/|:&#x2F;&#x2F;|%3A%2F%2F)\S{1,1024}/ /gs;
  $text =~ s/\S{1,64}?\@[a-zA-Z]\S{1,128}/ /gs;
  $text =~ s/\bwww\.\S{1,128}/ /gs;
  # Remove extra chars
  $text =~ s/\-{2,}//g;
  # Remove tokens that could be a date
  $text =~ s/\b\d+(?:\-|\/)\d+(?:\-|\/)\d+\b//g;
  # Decode HTML entities to their text equivalents, then strip residue
  $text =~ s/&([a-zA-Z]+);/exists $_HTML_ENTITIES{lc $1} ? $_HTML_ENTITIES{lc $1} : ' '/ge;
  $text =~ s/&#x([0-9a-fA-F]{1,6});/chr(hex($1))/ge;
  $text =~ s/&#([0-9]{1,7});/chr($1)/ge;
  $text =~ s/&/ /g;
  $text =~ s{[^\p{L}\p{N}\-]}{ }g;
  my @tokens = grep { length($_) >= $min_word_len && length($_) <= $max_word_len } split /\s+/, $text;
  @tokens = grep { $_ !~ /^\d+$/ } @tokens;         # drop pure numbers
  @tokens = grep { !$stopwords{$_} } @tokens;        # drop stopwords
  return @tokens;
}

sub _load_vocabulary_from_sql {
  my ($self, $username) = @_;
  return {} unless $self->{dbh};

  $username //= $self->{main}->{username};
  # normalize the username to lowercase
  $username = lc($username) if defined $username;

  # Check cache first to avoid repeated database queries
  if (!defined $self->{_vocab_cache}) {
    $self->{_vocab_cache} = {};
  }

  my $ttl = $self->{main}->{conf}->{neuralnetwork_cache_ttl} || 0;
  if ($ttl > 0 && exists $self->{_vocab_cache}{$username}) {
    my $age = time() - ($self->{_vocab_cache_time}{$username} || 0);
    if ($age < $ttl) {
      dbg("Using cached vocabulary for user: $username (age: ${age}s, ttl: ${ttl}s)");
      return $self->{_vocab_cache}{$username};
    }
    dbg("Vocabulary cache expired for user: $username (age: ${age}s, ttl: ${ttl}s)");
    delete $self->{_vocab_cache}{$username};
    delete $self->{_vocab_cache_time}{$username};
  }

  my %vocabulary = (
    terms => {},
    _doc_count => 0,
    _spam_count => 0,
    _ham_count => 0
  );

  eval {
    my $meta_sth = $self->{dbh}->prepare(
      "SELECT COUNT(*),
              SUM(CASE WHEN flag = 'S' THEN 1 ELSE 0 END),
              SUM(CASE WHEN flag = 'H' THEN 1 ELSE 0 END)
       FROM neural_seen WHERE username = ?"
    );
    $meta_sth->execute($username);
    my $meta = $meta_sth->fetchrow_arrayref();
    if ($meta) {
      $vocabulary{_doc_count}  = $meta->[0] || 0;
      $vocabulary{_spam_count} = $meta->[1] || 0;
      $vocabulary{_ham_count}  = $meta->[2] || 0;
    }
    1;
  } or do {
    dbg("Pre-check query failed: " . ($@ || 'unknown'));
    undef $self->{dbh};
  };

  my $conf     = $self->{main}->{conf};
  my $min_spam = $conf->{neuralnetwork_min_spam_count};
  my $min_ham  = $conf->{neuralnetwork_min_ham_count};

  if ($vocabulary{_spam_count} < $min_spam || $vocabulary{_ham_count} < $min_ham) {
    dbg("Pre-check: insufficient training data " .
        "(spam=$vocabulary{_spam_count}/$min_spam, ham=$vocabulary{_ham_count}/$min_ham)" .
        ", skipping full vocabulary load");
    $self->{_vocab_cache}{$username}      = \%vocabulary;
    $self->{_vocab_cache_time}{$username} = time();
    return \%vocabulary;
  }

  eval {
    my $sth = $self->{dbh}->prepare("
      SELECT keyword, total_count, docs_count, spam_count, ham_count
      FROM neural_vocabulary
      WHERE username = ?
    ");
    $sth->execute($username);

    my $rows = $sth->fetchall_arrayref();
    my $count = 0;

    foreach my $row (@{$rows}) {
      my ($keyword, $total, $docs, $spam, $ham) = @{$row};
      $vocabulary{terms}{$keyword} = {
        total => $total,
        docs  => $docs,
        spam  => $spam,
        ham   => $ham
      };
      $count++;
    }

    dbg("Loaded $count vocabulary terms from SQL for user: $username " .
        "(spam_docs=$vocabulary{_spam_count}, ham_docs=$vocabulary{_ham_count})");
    1;
  } or do {
    my $err = $@ || 'unknown';
    dbg("Failed to load vocabulary from SQL: $err");
    undef $self->{dbh};
  };

  # Cache the vocabulary with timestamp
  $self->{_vocab_cache}{$username} = \%vocabulary;
  $self->{_vocab_cache_time}{$username} = time();
  return \%vocabulary;
}

sub _save_model_vocab_to_sql {
  my ($self, $vocab_keys_ref, $username) = @_;
  return unless $self->{dbh} && defined $vocab_keys_ref;

  $username //= $self->{main}->{username};

  eval {
    $self->{dbh}->begin_work();
    $self->{dbh}->do(
      "UPDATE neural_vocabulary SET model_position = NULL WHERE username = ?",
      undef, lc($username)
    );
    my $upsert_sql;
    if ($self->{main}->{conf}->{neuralnetwork_dsn} =~ /^dbi:(?:mysql|MariaDB)/i) {
      $upsert_sql = "INSERT INTO neural_vocabulary (username, keyword, model_position)
                     VALUES (?, ?, ?)
                     ON DUPLICATE KEY UPDATE model_position = VALUES(model_position)";
    } else {
      $upsert_sql = "INSERT INTO neural_vocabulary (username, keyword, model_position)
                     VALUES (?, ?, ?)
                     ON CONFLICT (username, keyword) DO UPDATE SET model_position = excluded.model_position";
    }
    my $sth = $self->{dbh}->prepare($upsert_sql);
    for my $i (0 .. $#$vocab_keys_ref) {
      my $kw = $vocab_keys_ref->[$i];
      # Strip NUL bytes and truncate to the column's VARCHAR(255) limit so
      # MySQL does not silently mangle the keyword and collide with another row.
      $kw =~ s/\x00//g;
      $kw = substr($kw, 0, 255) if length($kw) > 255;
      $sth->execute(lc($username), $kw, $i);
    }
    # Reap rows that forget_message / _prune_vocabulary left behind because
    # they were still in the previous model. Now that we've rebuilt the
    # model vocab, anything with model_position still NULL and all-zero
    # counts is a true orphan.
    my $reap_sth = $self->{dbh}->prepare(
      "DELETE FROM neural_vocabulary
       WHERE username = ?
         AND model_position IS NULL
         AND total_count = 0 AND docs_count = 0
         AND spam_count = 0 AND ham_count = 0"
    );
    $reap_sth->execute(lc($username));
    my $reaped = $reap_sth->rows();
    $reaped = 0 if !defined $reaped || $reaped < 0;
    $self->{dbh}->commit();
    dbg("Saved model vocabulary (" . scalar(@$vocab_keys_ref) . " terms) to SQL for user: $username" .
        ($reaped ? " (reaped $reaped orphan terms)" : ""));
    1;
  } or do {
    my $err = $@ || 'unknown';
    eval { $self->{dbh}->rollback() if !$self->{dbh}{AutoCommit} };
    dbg("Failed to save model vocabulary to SQL: $err");
  };
}

sub _load_model_vocab_from_sql {
  my ($self, $username) = @_;
  return undef unless $self->{dbh};

  $username //= $self->{main}->{username};

  my $vocab_ref;
  eval {
    my $sth = $self->{dbh}->prepare(
      "SELECT keyword FROM neural_vocabulary
       WHERE username = ? AND model_position IS NOT NULL
       ORDER BY model_position"
    );
    $sth->execute(lc($username));
    my $rows = $sth->fetchall_arrayref();
    $vocab_ref = [ map { $_->[0] } @$rows ] if @$rows;
    1;
  } or do {
    dbg("Failed to load model vocabulary from SQL: " . ($@ || 'unknown'));
    undef $self->{dbh};
  };
  return $vocab_ref;
}

sub _model_vocab_path {
  my ($self, $nn_data_dir) = @_;
  return File::Spec->catfile($nn_data_dir, 'model-vocab-' . lc($self->{main}->{username}) . '.data');
}

sub _model_path {
  my ($self, $nn_data_dir) = @_;
  return File::Spec->catfile($nn_data_dir, 'fann-' . lc($self->{main}->{username}) . '.model');
}

sub _get_visible_text {
  my ($self, $msg) = @_;
  my $arr = $msg->get_visible_rendered_body_text_array();
  return (ref $arr eq 'ARRAY') ? join("\n", @$arr)
       : (defined $arr ? $arr : '');
}

# Returns { _learns_since_retrain => N, _tbuf => { spam=>[], ham=>[] } }
sub _load_meta {
  my ($self, $conf) = @_;
  if (defined $conf->{neuralnetwork_dsn} && $self->{dbh}) {
    my $username = lc($self->{main}->{username});
    my $counter  = 0;
    my %buf      = (spam => [], ham => []);
    eval {
      my $sth = $self->{dbh}->prepare(
        "SELECT value FROM neural_vars WHERE username=? AND variable=?"
      );
      $sth->execute($username, 'learns_since_retrain');
      my $row = $sth->fetchrow_arrayref();
      $counter = int($row->[0] // 0) if $row;

      $sth = $self->{dbh}->prepare(
        "SELECT class, slot, ts, token, count FROM neural_training_buffer WHERE username=? ORDER BY class, slot"
      );
      $sth->execute($username);
      my %slots;
      while (my ($class, $slot, $ts, $token, $count) = $sth->fetchrow_array()) {
        $slots{$class}{$slot}{ts} //= $ts;
        push @{ $slots{$class}{$slot}{tokens} }, ($token) x ($count // 1);
      }
      for my $class (qw(spam ham)) {
        for my $slot (sort { $a <=> $b } keys %{ $slots{$class} || {} }) {
          push @{ $buf{$class} },
               { tokens => $slots{$class}{$slot}{tokens},
                 ts     => $slots{$class}{$slot}{ts} };
        }
      }
      1;
    } or dbg("Failed to load SQL meta: " . ($@ || 'unknown'));
    return { _learns_since_retrain => $counter, _tbuf => \%buf };
  } else {
    my $vocab = $self->{_last_train_vocab} // {};
    my $tb = ref($vocab->{_tbuf}) eq 'HASH'
      ? $vocab->{_tbuf} : { spam => [], ham => [] };
    return { _learns_since_retrain => $vocab->{_learns_since_retrain} || 0,
             _tbuf                 => $tb };
  }
}

# Persists counter and training buffer to the appropriate backend store.
sub _save_meta {
  my ($self, $conf, $nn_data_dir, $counter, $tbuf) = @_;
  $tbuf ||= { spam => [], ham => [] };
  if (defined $conf->{neuralnetwork_dsn} && $self->{dbh}) {
    my $username = lc($self->{main}->{username});
    eval {
      $self->{dbh}->begin_work();
      my $driver = $self->{dbh}{Driver}{Name} // '';
      if ($driver eq 'SQLite') {
        $self->{dbh}->do(
          "INSERT OR REPLACE INTO neural_vars (username, variable, value) VALUES (?,?,?)",
          undef, $username, 'learns_since_retrain', "$counter"
        );
      } elsif ($driver =~ /^(mysql|MariaDB)/i) {
        $self->{dbh}->do(
          "REPLACE INTO neural_vars (username, variable, value) VALUES (?,?,?)",
          undef, $username, 'learns_since_retrain', "$counter"
        );
      } else {
        $self->{dbh}->do(
          "INSERT INTO neural_vars (username, variable, value) VALUES (?,?,?)
           ON CONFLICT (username, variable) DO UPDATE SET value=EXCLUDED.value",
          undef, $username, 'learns_since_retrain', "$counter"
        );
      }
      $self->{dbh}->do(
        "DELETE FROM neural_training_buffer WHERE username=?", undef, $username
      );
      my $ins = $self->{dbh}->prepare(
        "INSERT INTO neural_training_buffer (username, class, slot, ts, token, count) VALUES (?,?,?,?,?,?)"
      );
      for my $class (qw(spam ham)) {
        my $slots = $tbuf->{$class} || [];
        for my $i (0 .. $#$slots) {
          my $entry = $slots->[$i];
          my %counts;
          $counts{$_}++ for @{ $entry->{tokens} || [] };
          for my $tok (keys %counts) {
            $ins->execute($username, $class, $i, $entry->{ts} // 0, $tok, $counts{$tok});
          }
        }
      }
      $self->{dbh}->commit();
      dbg("SQL metadata persisted: learns_since_retrain=$counter " .
          "tbuf_spam=" . scalar(@{ $tbuf->{spam} || [] }) .
          " tbuf_ham=" . scalar(@{ $tbuf->{ham} || [] }));
      1;
    } or do {
      my $err = $@ || 'unknown';
      eval { $self->{dbh}->rollback() if !$self->{dbh}{AutoCommit} };
      dbg("Failed to persist SQL metadata: $err");
    };
  } else {
    eval {
      my $username   = lc($self->{main}->{username});
      my $vocab_path = File::Spec->catfile($nn_data_dir, 'vocabulary-' . $username . '.data');
      $vocab_path    = Mail::SpamAssassin::Util::untaint_file_path($vocab_path);
      if (-f $vocab_path) {
        my $ref = retrieve($vocab_path);
        if (ref $ref eq 'HASH') {
          $ref->{_learns_since_retrain} = $counter;
          $ref->{_tbuf} = $tbuf if ref($tbuf) eq 'HASH';
          store($ref, $vocab_path) or die "store failed";
          my $ttl = $conf->{neuralnetwork_cache_ttl} || 0;
          if ($ttl > 0) {
            $self->{_file_vocab_cache}{$username}      = $ref;
            $self->{_file_vocab_cache_time}{$username} = time();
          }
        }
      }
      1;
    } or dbg("Failed to persist learn counter / training buffer: " . ($@ || 'unknown'));
  }
}

# Loads the training vocabulary from SQL or the file-backed store (with cache).
# Returns a hashref with all default fields pre-populated.
sub _load_vocabulary {
  my ($self, $conf, $nn_data_dir, $train) = @_;
  my %vocabulary;

  if (defined $conf->{neuralnetwork_dsn} && $self && $self->{dbh}) {
    my $vocab_ref = $self->_load_vocabulary_from_sql($self->{main}->{username});
    if (ref($vocab_ref) eq 'HASH') {
      if (scalar keys %{$vocab_ref->{terms} || {}}) {
        %vocabulary = %{$vocab_ref};
      } else {
        # Insufficient terms but still capture class-count metadata.
        $vocabulary{_spam_count} = $vocab_ref->{_spam_count} || 0;
        $vocabulary{_ham_count}  = $vocab_ref->{_ham_count}  || 0;
        $vocabulary{_doc_count}  = $vocab_ref->{_doc_count}  || 0;
      }
    }
  }

  if (!keys %{$vocabulary{terms} || {}}) {
    my $username = lc($self->{main}->{username});
    my $ttl      = $conf->{neuralnetwork_cache_ttl} || 0;

    if (!$train && $ttl > 0 && defined $self->{_file_vocab_cache}{$username}) {
      my $age = time() - ($self->{_file_vocab_cache_time}{$username} || 0);
      if ($age < $ttl) {
        dbg("Using cached file vocabulary for user: $username (age: ${age}s, ttl: ${ttl}s)");
        %vocabulary = %{$self->{_file_vocab_cache}{$username}};
      } else {
        dbg("File vocabulary cache expired for user: $username (age: ${age}s, ttl: ${ttl}s)");
        delete $self->{_file_vocab_cache}{$username};
        delete $self->{_file_vocab_cache_time}{$username};
      }
    }

    if (!keys %{$vocabulary{terms} || {}}) {
      my $vocab_path = File::Spec->catfile($nn_data_dir, 'vocabulary-' . $username . '.data');
      if (-f $vocab_path) {
        eval {
          my $ref = retrieve($vocab_path);
          %vocabulary = %{$ref} if ref $ref eq 'HASH';
          1;
        } or warn("Failed to retrieve vocabulary from $vocab_path: " . ($@ || 'unknown'));
      }
      if (!$train && $ttl > 0 && keys %{$vocabulary{terms} || {}}) {
        $self->{_file_vocab_cache}{$username}      = \%vocabulary;
        $self->{_file_vocab_cache_time}{$username} = time();
      }
    }
  }

  $vocabulary{terms}                ||= {};
  $vocabulary{_doc_count}           ||= 0;
  $vocabulary{_spam_count}          ||= 0;
  $vocabulary{_ham_count}           ||= 0;
  $vocabulary{_learns_since_retrain} ||= 0;
  $vocabulary{_tbuf}         ||= { spam => [], ham => [] };
  $vocabulary{_tbuf}{spam}   ||= [];
  $vocabulary{_tbuf}{ham}    ||= [];
  return \%vocabulary;
}

sub _save_model_atomic {
  my ($self, $network, $dataset_path, $lock1_mtime,
      $locked_vocab_keys_ref, $locked_num_input, $nn_data_dir, $locker) = @_;

  my $tmp_path;
  my $file_mode   = 0666 & ~umask();
  my $prestage_ok = eval {
    ($tmp_path, my $tmp_fh) = Mail::SpamAssassin::Util::secure_tmpfile();
    die "could not create temp file" unless defined $tmp_path;
    close $tmp_fh;
    $tmp_path = Mail::SpamAssassin::Util::untaint_file_path($tmp_path);
    chmod($file_mode, $tmp_path) or info("chmod $file_mode on '$tmp_path' failed: $!");
    $network->save($tmp_path) or die "model save to temp '$tmp_path' failed";
    1;
  };
  if (!$prestage_ok) {
    my $err = $@ || 'unknown';
    info("Cannot pre-stage model save to '$dataset_path' ($err)");
    if (defined $tmp_path && -f $tmp_path) {
      unlink($tmp_path) or info("Cannot remove temp model file '$tmp_path': $!");
    }
    $locker->safe_unlock($dataset_path);
    return 0;
  }

  my $current_mtime = (stat($dataset_path))[9] // 0;
  info("on-disk model changed during training; overwriting")
    if defined $lock1_mtime && $current_mtime > $lock1_mtime;

  my $model_saved = 0;
  eval {
    delete $self->{_model_vocab_cache};
    delete $self->{_model_vocab_cache_t};
    _rename_or_copy($tmp_path, $dataset_path)
      or die "atomic rename/copy '$tmp_path' -> '$dataset_path' failed: $!";
    $tmp_path = undef;
    if (!defined $locked_vocab_keys_ref || scalar(@$locked_vocab_keys_ref) != $locked_num_input) {
      dbg("Skipping model vocab save: key count (" .
          (defined $locked_vocab_keys_ref ? scalar(@$locked_vocab_keys_ref) : 'undef') .
          ") != num_input ($locked_num_input)");
    } elsif (defined $self->{main}->{conf}->{neuralnetwork_dsn} && $self->{dbh}) {
      $self->_save_model_vocab_to_sql($locked_vocab_keys_ref)
        or info("WARNING: model saved but vocab SQL write failed; " .
                "model/vocab are now inconsistent and a full rebuild will " .
                "occur on the next learn call");
    } else {
      $self->_save_model_vocab($locked_vocab_keys_ref, $nn_data_dir);
      my $vocab_path = $self->_model_vocab_path($nn_data_dir);
      unless (-f $vocab_path) {
        info("WARNING: model saved but vocab file '$vocab_path' is missing; " .
             "model/vocab are now inconsistent and a full rebuild will " .
             "occur on the next learn call");
      }
    }
    $model_saved = 1;
    1;
  } or do {
    my $err = $@ || 'unknown';
    info("Cannot save model to '$dataset_path' ($err)");
    if (defined $tmp_path && -f $tmp_path) {
      unlink($tmp_path) or info("Cannot remove temp model file '$tmp_path': $!");
    }
  };
  $locker->safe_unlock($dataset_path);
  return $model_saved;
}

sub _periodic_retrain_if_needed {
  my ($self, $conf, $nn_data_dir, $network, $learns_since_retrain,
      $locked_num_input, $locked_vocab_keys_ref, $force) = @_;

  my $learn_count      = ($learns_since_retrain || 0) + 1;
  my $retrain_interval = $conf->{neuralnetwork_retrain_interval};

  if (!$force && ($retrain_interval <= 0 || $learn_count < $retrain_interval)) {
    return ($network, $locked_num_input, $locked_vocab_keys_ref, $learn_count);
  }

  my $username           = lc($self->{main}->{username});
  my $current_vocab_size = 0;
  my @current_vocab_keys;
  if (defined $conf->{neuralnetwork_dsn} && $self->{dbh}) {
    # Flush training buffer into vocabulary so the retrain sees complete token stats.
    # Buffer rows are kept intact for use as the training batch inside
    # _retrain_from_vocabulary; they are deleted after all retrains complete.
    my $meta = $self->_load_meta($conf);
    $self->_flush_training_buffer($meta->{_tbuf})
      if ref($meta->{_tbuf}) eq 'HASH';
    my $vref = $self->_load_vocabulary_from_sql($username);
    my $terms = ref($vref) eq 'HASH' ? ($vref->{terms} || {}) : {};
    @current_vocab_keys = sort keys %$terms;
    $current_vocab_size = scalar @current_vocab_keys;
  } else {
    my $vocab_path = File::Spec->catfile($nn_data_dir, 'vocabulary-' . $username . '.data');
    $vocab_path    = Mail::SpamAssassin::Util::untaint_file_path($vocab_path);
    if (-f $vocab_path) {
      my $ref = eval { retrieve($vocab_path) };
      if (ref($ref) eq 'HASH' && ref($ref->{terms}) eq 'HASH') {
        @current_vocab_keys = sort keys %{$ref->{terms}};
        $current_vocab_size = scalar @current_vocab_keys;
      }
    }
  }

  dbg("Periodic retrain triggered after $learn_count learn(s) " .
      "(interval=$retrain_interval, current_vocab_size=$current_vocab_size)");

  if ($current_vocab_size > 0) {
    my ($fresh, $fresh_keys) = $self->_retrain_from_vocabulary($conf, $nn_data_dir, $current_vocab_size);
    if (defined $fresh) {
      my @actual_keys = ($fresh_keys && @$fresh_keys) ? @$fresh_keys : @current_vocab_keys;
      my $actual_size = scalar @actual_keys;

      my $prune_factor = $conf->{neuralnetwork_weight_prune_factor};
      if ($prune_factor > 0) {
        my $nh1 = int(sqrt($current_vocab_size) + 0.5);
        $nh1 = 8 if $nh1 < 8;
        my $init_norm    = sqrt($nh1 / $current_vocab_size);
        my $prune_thresh = $prune_factor * $init_norm;
        my @keep_idx     = _prune_inputs_by_weight_norm($fresh, $current_vocab_size, $nh1, $prune_thresh);
        my $pruned       = $current_vocab_size - scalar @keep_idx;
        dbg(sprintf("Periodic retrain weight-norm prune: thresh=%.4f pruned=%d/%d",
            $prune_thresh, $pruned, $current_vocab_size));
        if ($pruned > 0 && $pruned < $current_vocab_size) {
          my @pruned_keys        = @current_vocab_keys[@keep_idx];
          my ($pruned_fresh, $pruned_fresh_keys) = $self->_retrain_from_vocabulary(
              $conf, $nn_data_dir, scalar @pruned_keys, \@pruned_keys);
          if (defined $pruned_fresh) {
            $fresh       = $pruned_fresh;
            @actual_keys = ($pruned_fresh_keys && @$pruned_fresh_keys)
                               ? @$pruned_fresh_keys : @pruned_keys;
            $actual_size = scalar @actual_keys;
            dbg("Pruned retrain complete: vocab=$actual_size (was $current_vocab_size)");
          }
        }
      }

      dbg("Periodic retrain succeeded: replaced online-trained network with batch retrain");
      # Return an empty buffer so _save_meta starts a fresh training buffer;
      # token data has been merged into vocabulary and used for training.
      return ($fresh, $actual_size, \@actual_keys, 0, { spam => [], ham => [] });
    }
  }
  dbg("Periodic retrain skipped: _retrain_from_vocabulary returned undef; " .
      "counter not reset, will retry on next learn");
  return ($network, $locked_num_input, $locked_vocab_keys_ref, $learn_count);
}

sub _run_balanced_replay {
  my ($self, $network, $conf, $nn_data_dir, $feature_vectors,
      $tbuf, $locked_vocab_keys_ref, $locked_num_input,
      $weighted_epochs, $network_rebuilt, $train_algorithm) = @_;

  $tbuf        ||= { spam => [], ham => [] };
  $tbuf->{spam} ||= [];
  $tbuf->{ham}  ||= [];

  if ($train_algorithm == FANN_TRAIN_RPROP) {
    $network->training_algorithm(FANN_TRAIN_INCREMENTAL);
  }

  my @replay_set;
  if (defined $locked_vocab_keys_ref
      && scalar(@$locked_vocab_keys_ref) == $locked_num_input) {
    my @spam_buf_toks = map { $_->{tokens} } @{ $tbuf->{spam} };
    my @ham_buf_toks  = map { $_->{tokens} } @{ $tbuf->{ham}  };
    my $n_spam = scalar @spam_buf_toks;
    my $n_ham  = scalar @ham_buf_toks;
    if ($n_spam + $n_ham > 0) {
      my ($buf_vecs) = _text_to_features(
        $self, $conf, $nn_data_dir, 2, undef,
        $locked_vocab_keys_ref, @spam_buf_toks, @ham_buf_toks);
      if (ref($buf_vecs) eq 'ARRAY' && scalar(@$buf_vecs) == $n_spam + $n_ham) {
        for my $i (0 .. $#$buf_vecs) {
          push @replay_set, {
            vec   => $buf_vecs->[$i]{vec},
            label => ($i < $n_spam) ? 1 : 0,
          };
        }
      }
    }
  }

  my @spam_set    = grep { $_->{label} == 1 } @replay_set;
  my @ham_set     = grep { $_->{label} == 0 } @replay_set;
  my $n_per_class = scalar(@spam_set) < scalar(@ham_set)
                    ? scalar(@spam_set) : scalar(@ham_set);

  if ($network_rebuilt) {
    dbg("Skipping SGD replay: network was rebuilt this learn (vocab grew); " .
        "RPROP retrain already trained on training buffer (spam=" .
        scalar(@spam_set) . ", ham=" . scalar(@ham_set) . ")");
  } elsif ($n_per_class >= (int(($conf->{neuralnetwork_min_spam_count}) / 10) || 1)) {
    my $K = $weighted_epochs < 1 ? 1 : $weighted_epochs;
    for my $e (1 .. $K) {
      Mail::SpamAssassin::Util::fisher_yates_shuffle(\@spam_set);
      Mail::SpamAssassin::Util::fisher_yates_shuffle(\@ham_set);
      my @epoch = (@spam_set[0 .. $n_per_class - 1],
                   @ham_set [0 .. $n_per_class - 1]);
      Mail::SpamAssassin::Util::fisher_yates_shuffle(\@epoch);
      for my $entry (@epoch) {
        eval { $network->train($entry->{vec}, [$entry->{label}]); 1 }
          or dbg("Replay training step failed: " . ($@ || 'unknown'));
      }
    }
    dbg("Balanced experience replay: $K epoch(s) of ${n_per_class}x2 sample(s) " .
        "(buffer spam=" . scalar(@spam_set) . ", ham=" . scalar(@ham_set) . ")");
  } else {
    my $replay_min = int(($conf->{neuralnetwork_min_spam_count}) / 10) || 1;
    dbg("Skipping SGD replay: training buffer too small or one-sided " .
        "(spam=" . scalar(@spam_set) . ", ham=" . scalar(@ham_set) .
        ", need>=$replay_min per class)");
  }

  if (scalar(@$feature_vectors) == 1) {
    my $pred_after = eval { $network->run($feature_vectors->[0]{vec}) };
    $pred_after = ref($pred_after) ? $pred_after->[0] : $pred_after;
    dbg("Prediction after learning: " . (defined $pred_after ? $pred_after : 'undef'));
  }
}

sub _get_or_create_network {
  my ($self, $conf, $nn_data_dir, $dataset_path,
      $num_input, $num_hidden1, $num_hidden2, $num_output_neurons,
      $buffer_spam_count, $buffer_ham_count, $train_algorithm) = @_;

  if (defined $self->{neural_model}
      && $self->{neural_model}->num_inputs()  == $num_input
      && $self->{neural_model}->num_outputs() == $num_output_neurons) {
    return ($self->{neural_model}, 0);
  }

  my $existing_network = $self->{neural_model};
  if (!defined $existing_network && -f $dataset_path) {
    eval {
      $existing_network = AI::FANN->new_from_file($dataset_path);
      1;
    } or dbg("Failed to load existing model for size check: " . ($@ || 'unknown'));
  }
  if (defined $existing_network) {
    my $model_size    = $existing_network->num_inputs();
    my $model_outputs = $existing_network->num_outputs();
    if ($model_outputs != $num_output_neurons) {
      dbg("Model output size mismatch (got $model_outputs, expected $num_output_neurons); " .
          "discarding stale model");
      undef $existing_network;
    } elsif ($model_size != $num_input) {
      dbg("Vocabulary size changed ($num_input vs model $model_size); " .
          "discarding stale model so ring-buffer retrain uses the full vocabulary");
      undef $existing_network;
    } else {
      # Saturation check: if the model outputs an identical value for an all-zeros
      # and an all-ones input, all hidden units have saturated and the model is dead.
      # Discard it so _retrain_from_vocabulary rebuilds with MSE early stopping.
      my $zero_in = [(0) x $num_input];
      my $ones_in = [(1) x $num_input];
      my $r_zero  = eval { $existing_network->run($zero_in) } // [0.5];
      my $r_ones  = eval { $existing_network->run($ones_in) } // [0.5];
      my $diff    = abs(($r_zero->[0] // 0.5) - ($r_ones->[0] // 0.5));
      if ($diff < 0.001) {
        dbg("Model is saturated (output=" . ($r_zero->[0] // '?') .
            " for zeros, " . ($r_ones->[0] // '?') . " for ones, diff=$diff); " .
            "discarding and rebuilding");
        undef $existing_network;
      }
    }
  }

  my $network;
  my $vocab    = $self->{_last_train_vocab} // {};
  my $sc       = $vocab->{_spam_count} || 0;
  my $hc       = $vocab->{_ham_count}  || 0;
  my $min_spam = $conf->{neuralnetwork_min_spam_count};
  my $min_ham  = $conf->{neuralnetwork_min_ham_count};
  if ($sc >= $min_spam && $hc >= $min_ham) {
    ($network) = $self->_retrain_from_vocabulary($conf, $nn_data_dir, $num_input);
  }
  if (!defined $network && $buffer_spam_count > 0 && $buffer_ham_count > 0) {
    # Blank-network fallback: logistic regression (no hidden layers) so that
    # the model cannot collapse to constant output before vocab data accumulates.
    my @layers = ($num_input, $num_output_neurons);
    $network = AI::FANN->new_standard(@layers);
    $network->output_activation_function(FANN_SIGMOID);
  }
  return ($network, 1);
}

sub _push_to_training_buffer {
  my ($self, $conf, $nn_data_dir, $email_token_lists, $labels) = @_;

  my $existing         = $self->_load_meta($conf);
  my $existing_buf     = $existing->{_tbuf};
  my $existing_counter = $existing->{_learns_since_retrain};

  my %buf_state = (
    spam => [ @{ $existing_buf->{spam} || [] } ],
    ham  => [ @{ $existing_buf->{ham}  || [] } ],
  );
  for my $i (0 .. $#$email_token_lists) {
    next unless ref($email_token_lists->[$i]) eq 'ARRAY' && @{$email_token_lists->[$i]};
    my $key = $labels->[$i] ? 'spam' : 'ham';
    push @{ $buf_state{$key} }, { tokens => [ @{$email_token_lists->[$i]} ], ts => time() };
  }

  $self->_save_meta($conf, $nn_data_dir, $existing_counter, \%buf_state);

  # Keep the in-memory snapshot current so the delete below sees the new buffer.
  $self->{_last_train_vocab}{_tbuf} = \%buf_state
    if ref $self->{_last_train_vocab} eq 'HASH';

  my $needs_retrain = $self->_training_buffer_flush_needed($conf, \%buf_state);
  return (scalar @{ $buf_state{spam} }, scalar @{ $buf_state{ham} }, $needs_retrain);
}

sub _save_model_vocab {
  my ($self, $vocab_keys_ref, $nn_data_dir) = @_;
  return unless defined $vocab_keys_ref;
  my $vocab_path = $self->_model_vocab_path($nn_data_dir);
  $vocab_path = Mail::SpamAssassin::Util::untaint_file_path($vocab_path);
  eval {
    store($vocab_keys_ref, $vocab_path) or die "store failed";
    1;
  } or do {
    dbg("Failed to save model vocabulary to file: " . ($@ || 'unknown'));
  };
}

sub _load_model_vocab {
  my ($self, $nn_data_dir) = @_;

  my $ttl = $self->{main}->{conf}->{neuralnetwork_cache_ttl} || 0;
  if ($ttl > 0 && defined $self->{_model_vocab_cache}) {
    my $age = time() - ($self->{_model_vocab_cache_t} || 0);
    return $self->{_model_vocab_cache} if $age < $ttl;
  }

  my $vocab_ref;
  if (defined $self->{main}->{conf}->{neuralnetwork_dsn} && $self->{dbh}) {
    $vocab_ref = $self->_load_model_vocab_from_sql();
  } else {
    my $vocab_path = $self->_model_vocab_path($nn_data_dir);
    $vocab_path = Mail::SpamAssassin::Util::untaint_file_path($vocab_path);
    if (-f $vocab_path) {
      eval {
        $vocab_ref = retrieve($vocab_path);
        1;
      } or do {
        dbg("Failed to load model vocabulary from file: " . ($@ || 'unknown'));
      };
    }
  }

  $self->{_model_vocab_cache}   = $vocab_ref;
  $self->{_model_vocab_cache_t} = time();
  return $vocab_ref;
}

1;
