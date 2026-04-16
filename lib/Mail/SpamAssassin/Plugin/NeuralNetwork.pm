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

my $VERSION = 0.7.3;

use AI::FANN qw(:all);
use Storable qw(store retrieve);
use File::Spec;
use File::Temp ();

use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Util qw(untaint_file_path);

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg { my $msg = shift; Mail::SpamAssassin::Logger::dbg("NeuralNetwork: $msg", @_); }
sub info { my $msg = shift; Mail::SpamAssassin::Logger::info("NeuralNetwork: $msg", @_); }

sub finish {
  my $self = shift;

  if ($self->{dbh}) {
    if (($self->{_dbh_pid} || 0) == $$) {
      $self->{dbh}->disconnect();
    } else {
      $self->{dbh}->{InactiveDestroy} = 1;
    }
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

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

=over 4

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

=item neuralnetwork_spam_threshold f (default: 0.8)

Prediction values above this threshold are considered spam.

=item neuralnetwork_ham_threshold f (default: 0.2)

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

=item neuralnetwork_stopwords words (default: "the and for with that this from there their have be not but you your")

Space-separated list of stopwords to ignore when tokenizing text.

=item neuralnetwork_autolearn 0|1 (default 0)

When SpamAssassin declares a message a clear spam or ham during the message
scan, and launches the auto-learn process, message is autolearned as spam/ham
in the same way as during the manual learning.
Value 0 at this option disables the auto-learn process for this plugin.

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

=cut

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
    default => 0.8,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  push(@cmds, {
    setting => 'neuralnetwork_ham_threshold',
    is_admin => 1,
    default => 0.2,
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

  my $dataset_path = File::Spec->catfile($nn_data_dir, 'fann-' . lc($self->{main}->{username}) . '.model');
  $dataset_path = Mail::SpamAssassin::Util::untaint_file_path($dataset_path);
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

# Converts a list of raw text strings into a list of
# numerical feature vectors (dense arrays), suitable for Neural Networks training.
sub _text_to_features {
    my ($self, $conf, $nn_data_dir, $train, $label, $target_vocab_ref, @emails) = @_;

    my $min_word_len = $conf->{neuralnetwork_min_word_len};
    my $max_word_len = $conf->{neuralnetwork_max_word_len};
    my $vocab_cap    = $conf->{neuralnetwork_vocab_cap};
    my %stopwords    = map { lc($_) => 1 } split /\s+/, $conf->{neuralnetwork_stopwords};
    my $stopwords_ref = \%stopwords;

    return unless defined $nn_data_dir;
    $nn_data_dir = Mail::SpamAssassin::Util::untaint_file_path($nn_data_dir);

    if( not -d $nn_data_dir) {
      info("Cannot access directory $nn_data_dir");
      return;
    }

    # Read the vocabulary (format: { terms => {word => {total=>n,docs=>m,spam=>s,ham=>h}}, _doc_count => N, _spam_count => S, _ham_count => H })
    my %vocabulary;

    # Try loading from SQL first if configured
    if (defined $conf->{neuralnetwork_dsn} && $self && $self->{dbh}) {
      my $vocab_ref = $self->_load_vocabulary_from_sql($self->{main}->{username});
      if (ref($vocab_ref) eq 'HASH' && scalar keys %{$vocab_ref->{terms} || {}}) {
        %vocabulary = %{$vocab_ref};
      }
    }

    # If not loaded from SQL, try loading from file
    if (!keys %{$vocabulary{terms} || {}}) {
      my $username = lc($self->{main}->{username});
      my $ttl = $conf->{neuralnetwork_cache_ttl} || 0;

      # Check file-based vocabulary cache
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

      # Load from file if not cached
      if (!keys %{$vocabulary{terms} || {}}) {
        my $vocab_path = File::Spec->catfile($nn_data_dir, 'vocabulary-' . $username . '.data');
        if(-f $vocab_path) {
          eval {
            my $ref = retrieve($vocab_path);
            if (ref $ref eq 'HASH') {
              %vocabulary = %{$ref};
            }
            1;
          } or do {
            warn("Failed to retrieve vocabulary from $vocab_path: " . ($@ || 'unknown'));
          };
        }
        # Populate cache after successful load
        if (!$train && $ttl > 0 && keys %{$vocabulary{terms} || {}}) {
          $self->{_file_vocab_cache}{$username} = \%vocabulary;
          $self->{_file_vocab_cache_time}{$username} = time();
        }
      }
    }

    $vocabulary{terms} ||= {};
    $vocabulary{_doc_count} ||= 0;
    $vocabulary{_spam_count} ||= 0;
    $vocabulary{_ham_count} ||= 0;

    # Ensure we have enough spam and ham examples in the vocabulary
    my $min_spam = $conf->{neuralnetwork_min_spam_count};
    my $min_ham  = $conf->{neuralnetwork_min_ham_count};
    if ($train == 0) {
      if ( ($vocabulary{_spam_count} < $min_spam) || ($vocabulary{_ham_count} < $min_ham) ) {
        dbg("Insufficient spam/ham data for prediction: spam=".$vocabulary{_spam_count}.", ham=".$vocabulary{_ham_count});
        return ([], 0);
      }
    }

    # tokenize helper
    my $tokenize = sub {
      my ($text) = @_;
      return $self->_tokenize_text($conf, $text);
    };

    # When training, build per-document term sets to update doc counts
    my $local_doc_increment = 0;
    if ($train == 1) {
      foreach my $email_text (@emails) {
        next unless defined $email_text;
        my @tokens = $tokenize->($email_text);
        next unless @tokens;
        $local_doc_increment++;

        # count doc-level presence once per unique token
        my %seen;
        foreach my $t (@tokens) {
          $vocabulary{terms}{$t}{total} = ($vocabulary{terms}{$t}{total} || 0) + 1;
          $seen{$t} = 1;
        }
        foreach my $t (keys %seen) {
          $vocabulary{terms}{$t}{docs} = ($vocabulary{terms}{$t}{docs} || 0) + 1;
          # Track spam/ham sources
          if (defined $label && $label == 1) {
            $vocabulary{terms}{$t}{spam} = ($vocabulary{terms}{$t}{spam} || 0) + 1;
          } elsif (defined $label && $label == 0) {
            $vocabulary{terms}{$t}{ham} = ($vocabulary{terms}{$t}{ham} || 0) + 1;
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

      # Prune vocabulary if needed
      $self->_prune_vocabulary(\%vocabulary, $vocab_cap);

      my $vocab_path;
      if (defined $conf->{neuralnetwork_dsn} && $self && $self->{dbh}) {
        $self->_save_vocabulary_to_sql(\%vocabulary, $self->{main}->{username});
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
          my $username = lc($self->{main}->{username});
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
    foreach my $email_text (@emails) {
      next unless defined $email_text;
      my @tokens = $tokenize->($email_text);
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

  my $msgid = $msg->get_msgid();
  $msgid //= $msg->generate_msgid();

  if ($autolearn && !$conf->{neuralnetwork_autolearn}) {
    dbg("autolearning disabled, quitting");
    return 0;
  }

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
    my $text =  $msg->get_visible_rendered_body_text_array();
    $text = join("\n", @{$text});
    if (!defined $text || length($text) < $min_text_len) {
      dbg("Not enough text, skipping neural network processing");
      return;
    }
    push(@training_data, { label => $isspam, text => $text } );
  }

  my $dataset_path = File::Spec->catfile($nn_data_dir, 'fann-' . lc($self->{main}->{username}) . '.model');
  $dataset_path = Mail::SpamAssassin::Util::untaint_file_path($dataset_path);

  my $locker = $self->{main}->{locker};
  unless ($locker->safe_lock($dataset_path, $conf->{neuralnetwork_lock_timeout})) {
    dbg("Cannot acquire lock on '$dataset_path', skipping learning");
    return;
  }

  # Extract the text and labels
  my @email_texts = map { $_->{text} } @training_data;
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
    my $username = $self->{main}->{username};
    delete $self->{_vocab_cache}{$username};
    delete $self->{_vocab_cache_time}{$username};
  }

  # Update the vocabulary
  my $update_vocab = 1;

  # Convert email text to numerical feature vectors
  my ($feature_vectors, $vocab_size, $vocab_keys_ref) = _text_to_features($self, $self->{main}->{conf}, $nn_data_dir, $update_vocab, $isspam, undef, @email_texts);

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
  my $num_hidden_neurons = int(sqrt($num_input)) || 1;
  my $num_output_neurons = 1;

  my $network;
  if(defined $self->{neural_model} && $self->{neural_model}->num_inputs() == $num_input) {
    $network = $self->{neural_model};
  } else {
    # Try to load the existing model from disk if not already in memory
    my $existing_network = $self->{neural_model};
    if (!defined $existing_network && -f $dataset_path) {
      eval {
        $existing_network = AI::FANN->new_from_file($dataset_path);
        1;
      } or do {
        dbg("Failed to load existing model for size check: " . ($@ || 'unknown'));
      };
    }

    if (defined $existing_network) {
      # Vocabulary grew: rebuild training vectors using the model's original word -> index mapping
      my $model_size = $existing_network->num_inputs();
      dbg("Vocabulary size changed ($num_input vs model $model_size), rebuilding training vectors with model vocabulary");
      my $stored_vocab_ref = $self->_load_model_vocab($nn_data_dir);
      if (defined $stored_vocab_ref && scalar(@$stored_vocab_ref) == $model_size) {
        ($feature_vectors, undef) = _text_to_features($self, $self->{main}->{conf}, $nn_data_dir, 2, undef, $stored_vocab_ref, @email_texts);
        $vocab_keys_ref = $stored_vocab_ref;
      } else {
        dbg("Model vocabulary file not found or mismatched, falling back to vector adjustment");
        $feature_vectors = [ map { my $v = _adjust_vector_size($_->{vec}, $model_size); { vec => $v, hits => scalar grep { $_ != 0 } @$v } } @$feature_vectors ];
        $vocab_keys_ref = undef;
      }
      $num_input = $model_size;
      $network = $existing_network;
    } else {
      # No existing model: create a baseline from vocabulary statistics
      $network = $self->_retrain_from_vocabulary($self->{main}->{conf}, $nn_data_dir, $num_input);
      if (!defined $network) {
        # No vocabulary stats available yet, create a fresh network
        $network = AI::FANN->new_standard($num_input, $num_hidden_neurons, $num_output_neurons);
        $network->hidden_activation_function(FANN_SIGMOID_STEPWISE);
        $network->output_activation_function(FANN_SIGMOID_STEPWISE);
      }
    }
  }
  $network->learning_rate($learning_rate);
  $network->learning_momentum($momentum);
  $network->training_algorithm($train_algorithm);
  if ($train_algorithm == FANN_TRAIN_RPROP) {
    $network->rprop_delta_max($conf->{neuralnetwork_rprop_delta_max});
  }

  # Load the current corpus counts so we can compute how skewed the training
  # history is.
  my %vocab_for_balance;
  if (ref $self->{_last_train_vocab} eq 'HASH') {
    %vocab_for_balance = %{delete $self->{_last_train_vocab}};
  } elsif (defined $conf->{neuralnetwork_dsn} && $self->{dbh}) {
    my $vocab_ref = $self->_load_vocabulary_from_sql($self->{main}->{username});
    %vocab_for_balance = %{$vocab_ref} if ref($vocab_ref) eq 'HASH';
  }
  if (!keys %{$vocab_for_balance{terms} || {}}) {
    my $vocab_path = File::Spec->catfile($nn_data_dir, 'vocabulary-' . lc($self->{main}->{username}) . '.data');
    $vocab_path = Mail::SpamAssassin::Util::untaint_file_path($vocab_path);
    if (-f $vocab_path) {
      eval {
        my $ref = retrieve($vocab_path);
        %vocab_for_balance = %{$ref} if ref $ref eq 'HASH';
        1;
      } or do {
        dbg("Could not load vocabulary for balance check: " . ($@ || 'unknown'));
      };
    }
  }
  my $spam_docs = $vocab_for_balance{_spam_count} || 1;
  my $ham_docs  = $vocab_for_balance{_ham_count}  || 1;

  # class_weight > 1 means this message belongs to the minority class and
  # should be trained harder; < 1 means it belongs to the majority class.
  my $class_weight;
  if ($isspam) {
    $class_weight = $ham_docs / $spam_docs;   # < 1 when spam dominates
  } else {
    $class_weight = $spam_docs / $ham_docs;   # < 1 when ham dominates
  }
  $class_weight = 0.5 if $class_weight < 0.5;
  $class_weight = 2.0 if $class_weight > 2.0;

  my $weighted_epochs = int($train_epochs * $class_weight) || 1;
  # Scale epochs down for large vocabularies to keep per-message training time
  # roughly constant.
  if ($num_input > 1000) {
    $weighted_epochs = int($weighted_epochs * 1000 / $num_input) || 1;
  }
  dbg("Incremental training: weighted_epochs=$weighted_epochs " .
      "(base=$train_epochs, class_weight=$class_weight, " .
      "spam_docs=$spam_docs, ham_docs=$ham_docs, isspam=$isspam, num_input=$num_input)");

  for my $e (1 .. $weighted_epochs) {
    for my $i (0 .. $#$feature_vectors) {
      my $input  = $feature_vectors->[$i]{vec};
      my $output = [$labels[$i] ? 1 : 0];
      eval { $network->train($input, $output); 1 } or dbg("Training step failed: " . ($@ || 'unknown'));
    }
  }

  # Dynamic replay algorithm
  if (   $train_algorithm == FANN_TRAIN_RPROP
      && defined $vocab_keys_ref
      && scalar(@$vocab_keys_ref) == $num_input
      && $spam_docs > 1 && $ham_docs > 1) {

    my ($svec, $hvec) = _build_class_tfidf_vectors(\%vocab_for_balance, $vocab_keys_ref);

    if ($svec && $hvec) {
      # Use grep in scalar context: returns count of non-zero elements.
      my $svec_ok = grep { $_ != 0 } @$svec;
      my $hvec_ok = grep { $_ != 0 } @$hvec;

      if ($svec_ok && $hvec_ok) {
        my $replay_cycles = int(sqrt($weighted_epochs / 10.0) + 0.5) || 1;
        $replay_cycles = 6 if $replay_cycles > 6;

        if ($isspam) {
          for (1 .. $replay_cycles) {
            eval { $network->train($hvec, [0]); 1 } or dbg("Replay ham step failed: "  . ($@ || 'unknown'));
            eval { $network->train($svec, [1]); 1 } or dbg("Replay spam step failed: " . ($@ || 'unknown'));
          }
        } else {
          for (1 .. $replay_cycles) {
            eval { $network->train($svec, [1]); 1 } or dbg("Replay spam step failed: " . ($@ || 'unknown'));
            eval { $network->train($hvec, [0]); 1 } or dbg("Replay ham step failed: "  . ($@ || 'unknown'));
          }
        }
        dbg("RPROP replay: $replay_cycles cycle(s) after $weighted_epochs epoch(s) " .
            "(isspam=$isspam, spam_docs=$spam_docs, ham_docs=$ham_docs)");
      } else {
        dbg("Skipping RPROP replay: degenerate vectors (svec_ok=$svec_ok, hvec_ok=$hvec_ok)");
      }
    }
  } elsif ($train_algorithm == FANN_TRAIN_RPROP && !defined $vocab_keys_ref) {
    dbg("Skipping RPROP replay: vocab_keys unavailable");
  }

  if (scalar(@$feature_vectors) == 1) {
    my $pred_after = eval { $network->run($feature_vectors->[0]{vec}) };
    $pred_after = ref($pred_after) ? $pred_after->[0] : $pred_after;
    dbg("Prediction after learning: " . (defined $pred_after ? $pred_after : 'undef'));
  }

  # Save the model atomically
  my $model_saved = 0;
  my $tmp_path;
  eval {
    my ($vol, $dir, undef) = File::Spec->splitpath($dataset_path);
    my $tmp_dir = File::Spec->catpath($vol, $dir, '');
    (undef, $tmp_path) = File::Temp::tempfile(
      'fann-XXXXXX',
      DIR    => $tmp_dir,
      SUFFIX => '.tmp',
      UNLINK => 0,
    );
    $network->save($tmp_path) or die "model save to temp '$tmp_path' failed";
    rename($tmp_path, $dataset_path)
      or die "atomic rename '$tmp_path' -> '$dataset_path' failed: $!";
    $tmp_path = undef;
    $model_saved = 1;
    1;
  } or do {
    my $err = $@ || 'unknown';
    info("Cannot save model to '$dataset_path' ($err)");
    if (defined $tmp_path && -f $tmp_path) {
      unlink($tmp_path)
        or info("Cannot remove temp model file '$tmp_path': $!");
    }
  };
  $locker->safe_unlock($dataset_path);

  if ($model_saved) {
    dbg("Model saved to '$dataset_path' (input:$num_input)");
    $self->{neural_model} = $network;
    $self->{_neural_model_load_time} = time();

    if (defined $self->{main}->{conf}->{neuralnetwork_dsn} && $self->{dbh}) {
      $self->_save_model_vocab_to_sql($vocab_keys_ref);
    } else {
      $self->_save_model_vocab($vocab_keys_ref, $nn_data_dir);
    }

    # Record message as learned to prevent re-learning.
    if (defined $msg && defined $msgid && length($msgid) > 0) {
      $self->_save_msgid_to_neural_seen($msgid, $isspam);
    }
  }
  return $model_saved;
}

sub forget_message {
  my ($self, $params) = @_;
  my $conf = $self->{main}->{conf};
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
    my $text = $msg->get_visible_rendered_body_text_array();
    $text = join("\n", @{$text}) if defined $text;

    if (defined $text && length($text) > 0) {
      my @tokens = $self->_tokenize_text($conf, $text);
      if (@tokens) {
        my %token_total;
        foreach my $t (@tokens) {
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

          # Remove unused terms
          my $cleanup_sql = "
            DELETE FROM neural_vocabulary
            WHERE username = ?
              AND total_count = 0 AND docs_count = 0
              AND spam_count = 0 AND ham_count = 0
          ";
          my $sth_cleanup = $self->{dbh}->prepare($cleanup_sql);
          $sth_cleanup->execute(lc($username));

          $self->{dbh}->commit();
          dbg("Decremented vocabulary counts for message $msgid");
          1;
        } or do {
          my $err = $@ || 'unknown';
          eval { $self->{dbh}->rollback() if !$self->{dbh}{AutoCommit} };
          dbg("Failed to decrement vocabulary during forget: $err");
        };
      }
    }

    my $del_sql = "
      DELETE FROM neural_seen
      WHERE username = ? AND msgid = ?
    ";
    my $sth = $self->{dbh}->prepare($del_sql);
    if (not $sth->execute($username, $msgid)) {
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

# Prune vocabulary to keep only the top $vocab_cap terms, balanced between
# spam and ham terms.
sub _prune_vocabulary {
  my ($self, $vocabulary, $vocab_cap) = @_;

  my $terms = $vocabulary->{terms} || {};
  my $terms_count = scalar keys %{$terms};
  return () unless $terms_count > $vocab_cap;

  # Prune to 90% of cap so the vocabulary has room to grow before the next
  # prune is triggered.
  my $prune_target = int($vocab_cap * 0.9) || 1;
  my $half = int($prune_target / 2);

  my %kept;
  for my $w (sort { ($terms->{$b}{spam}||0) <=> ($terms->{$a}{spam}||0) } keys %{$terms}) {
    last if scalar keys %kept >= $half;
    $kept{$w} = $terms->{$w};
  }
  for my $w (sort { ($terms->{$b}{ham}||0) <=> ($terms->{$a}{ham}||0) } keys %{$terms}) {
    last if scalar keys %kept >= $prune_target;
    $kept{$w} = $terms->{$w};
  }
  # Fill any remaining slots
  for my $w (sort { ($terms->{$b}{total}||0) <=> ($terms->{$a}{total}||0) } keys %{$terms}) {
    last if scalar keys %kept >= $prune_target;
    $kept{$w} = $terms->{$w};
  }
  my @pruned = grep { !exists $kept{$_} } keys %{$terms};
  $vocabulary->{terms} = \%kept;

  if (@pruned && defined $self->{main}->{conf}->{neuralnetwork_dsn} && ($self->{main}->{conf}->{neuralnetwork_dsn} =~ /^dbi:/i)) {
    eval {
      my $user = $self->{main}->{username};
      my $placeholders = join(',', ('?') x scalar(@pruned));
      my $del_sql = "DELETE FROM neural_vocabulary WHERE username = ? AND keyword IN ($placeholders)";
      my $sth_del = $self->{dbh}->prepare($del_sql);
      $sth_del->execute($user, @pruned);
      dbg("Deleted " . scalar(@pruned) . " terms for user: $user");
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
  my ($self, $conf, $nn_data_dir, $vocab_size) = @_;

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

  my @vocab_keys = sort keys %{$terms};
  my $actual_size = scalar @vocab_keys;
  return unless $actual_size == $vocab_size;

  my $spam_docs = $vocabulary{_spam_count} || 1;
  my $ham_docs  = $vocabulary{_ham_count}  || 1;

  my ($spam_vec_ref, $ham_vec_ref) = _build_class_tfidf_vectors(\%vocabulary, \@vocab_keys);
  return unless $spam_vec_ref;
  my @spam_vec = @$spam_vec_ref;
  my @ham_vec  = @$ham_vec_ref;

  my $spam_reps = 1;
  my $ham_reps  = 1;
  if ($spam_docs > $ham_docs) {
    $ham_reps = int($spam_docs / $ham_docs + 0.5) || 1;
    $ham_reps = 10 if $ham_reps > 10;
  } elsif ($ham_docs > $spam_docs) {
    $spam_reps = int($ham_docs / $spam_docs + 0.5) || 1;
    $spam_reps = 10 if $spam_reps > 10;
  }
  dbg("Retraining from vocabulary: spam_docs=$spam_docs, ham_docs=$ham_docs, " .
      "spam_reps=$spam_reps, ham_reps=$ham_reps, epochs=$train_epochs");

  # Create and train new network
  my $num_hidden = int(sqrt($vocab_size)) || 1;
  my $network = AI::FANN->new_standard($vocab_size, $num_hidden, 1);
  $network->hidden_activation_function(FANN_SIGMOID_STEPWISE);
  $network->output_activation_function(FANN_SIGMOID_STEPWISE);
  $network->learning_rate($learning_rate);
  $network->learning_momentum($momentum);
  $network->training_algorithm($train_algorithm);
  if ($train_algorithm == FANN_TRAIN_RPROP) {
    $network->rprop_delta_max($conf->{neuralnetwork_rprop_delta_max});
  }

  for my $e (1 .. $train_epochs) {
    if ($spam_docs >= $ham_docs) {
      # Spam-dominant: ham first, spam last so RPROP state ends spam-biased
      eval { $network->train(\@ham_vec,  [0]); 1 } or dbg("Retrain ham step failed: "  . ($@ || 'unknown')) for (1 .. $ham_reps);
      eval { $network->train(\@spam_vec, [1]); 1 } or dbg("Retrain spam step failed: " . ($@ || 'unknown')) for (1 .. $spam_reps);
    } else {
      # Ham-dominant: spam first, ham last so RPROP state ends ham-biased
      eval { $network->train(\@spam_vec, [1]); 1 } or dbg("Retrain spam step failed: " . ($@ || 'unknown')) for (1 .. $spam_reps);
      eval { $network->train(\@ham_vec,  [0]); 1 } or dbg("Retrain ham step failed: "  . ($@ || 'unknown')) for (1 .. $ham_reps);
    }
  }

  return $network;
}

sub _check_neuralnetwork {
  my ($self, $pms) = @_;

  return 0 if (!$self->{main}->{conf}->{use_learner});
  my $msg = $pms->{msg};

  if(exists $pms->{neuralnetwork_prediction}) {
    return;
  }

  my $conf = $self->{main}->{conf};
  $self->_init_sql_connection($conf) if defined $conf->{neuralnetwork_dsn};
  my $min_text_len = $conf->{neuralnetwork_min_text_len};
  my $spam_threshold = $conf->{neuralnetwork_spam_threshold};
  my $ham_threshold  = $conf->{neuralnetwork_ham_threshold};

  my $email_to_predict = $msg->get_visible_rendered_body_text_array();
  $email_to_predict = join("\n", @{$email_to_predict});
  if(!defined $email_to_predict || length($email_to_predict) < $min_text_len) {
    $pms->{neuralnetwork_prediction} = undef;
    dbg("Too short email text $email_to_predict");
    return;
  }

  my $nn_data_dir = $self->{main}->{conf}->{neuralnetwork_data_dir};
  $nn_data_dir = Mail::SpamAssassin::Util::untaint_file_path($nn_data_dir);
  if (not -d $nn_data_dir) {
    $pms->{neuralnetwork_prediction} = undef;
    info("Invalid neuralnetwork_data_dir path");
    return;
  }

  my $dataset_path = File::Spec->catfile($nn_data_dir, 'fann-' . lc($self->{main}->{username}) . '.model');
  if(not -f $dataset_path) {
    $pms->{neuralnetwork_prediction} = undef;
    dbg("Can't predict without a trained model, $dataset_path cannot be read");
    return;
  }

  # Load the vocabulary the model was trained on so the feature vector dimensions
  # are always aligned with the model, regardless of subsequent vocabulary growth.
  my $stored_vocab_ref = $self->_load_model_vocab($nn_data_dir);

  # Do not update the vocabulary
  my $update_vocab = 0;

  # Convert email to feature vector using the model's vocabulary
  my ($feature_vectors, $vocab_size) = _text_to_features($self, $conf, $nn_data_dir, $update_vocab, undef, $stored_vocab_ref, $email_to_predict);
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

  my $ttl = $conf->{neuralnetwork_cache_ttl} || 0;
  my $model_age = defined $self->{_neural_model_load_time} ? time() - $self->{_neural_model_load_time} : undef;
  my $model_expired = defined $model_age && $ttl > 0 && $model_age >= $ttl;

  if (!defined $self->{neural_model} || $model_expired) {
    if ($model_expired) {
      dbg("Model cache expired (age: ${model_age}s, ttl: ${ttl}s), reloading");
    }
    eval {
      $self->{neural_model} = AI::FANN->new_from_file($dataset_path);
      $self->{_neural_model_load_time} = time();
      1;
    } or do {
      dbg("Failed to load model for prediction: " . ($@ || 'unknown'));
      return;
    };
  }
  my $network = $self->{neural_model};

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
    $self->{dbh}->{InactiveDestroy} = 1;
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
    $self->{dbh} = DBI->connect(
      $dsn,
      $username,
      $password,
      {RaiseError => 1, PrintError => 0, InactiveDestroy => 1, AutoCommit => 1}
    );
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

  # Save to file-based neural_seen if no SQL configured
  if (!defined $self->{main}->{conf}->{neuralnetwork_dsn} || !$self->{dbh}) {
    return; # File-based storage could be added here if needed
  }

  eval {
    # Flag: 'S' for spam, 'H' for ham
    my $flag = $isspam ? 'S' : 'H';
    my $username = lc($self->{main}->{username}) || 'default';

    # Use INSERT IGNORE to avoid duplicate key errors
    my $insert_sql;

    if ($self->{main}->{conf}->{neuralnetwork_dsn} =~ /^dbi:(?:mysql|MariaDB)/i) {
      # MySQL: INSERT IGNORE
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
  my ($self, $vocabulary, $username) = @_;
  return unless $self->{dbh} && defined $vocabulary && ref($vocabulary) eq 'HASH';

  $username //= $self->{main}->{username};

  eval {
    my $terms = $vocabulary->{terms} || {};
    return unless scalar keys %{$terms};

    # Use ON DUPLICATE KEY UPDATE for MySQL or ON CONFLICT for other databases
    my $upsert_sql;

    if ($self->{main}->{conf}->{neuralnetwork_dsn} =~ /^dbi:(?:mysql|MariaDB)/i) {
      $upsert_sql = "
        INSERT INTO neural_vocabulary (username, keyword, total_count, docs_count, spam_count, ham_count)
        VALUES (?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
          total_count = VALUES(total_count),
          docs_count = VALUES(docs_count),
          spam_count = VALUES(spam_count),
          ham_count = VALUES(ham_count)
      ";
    } else {
      $upsert_sql = "
        INSERT INTO neural_vocabulary (username, keyword, total_count, docs_count, spam_count, ham_count)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT (username, keyword) DO UPDATE SET
          total_count = excluded.total_count,
          docs_count = excluded.docs_count,
          spam_count = excluded.spam_count,
          ham_count = excluded.ham_count
      ";
    }

    my $sth_upsert = $self->{dbh}->prepare($upsert_sql);
    my $count = 0;

    $self->{dbh}->begin_work();
    foreach my $keyword (sort keys %{$terms}) {
      my $term_data = $terms->{$keyword};
      $sth_upsert->execute(
        lc($username),
        $keyword,
        $term_data->{total} || 0,
        $term_data->{docs}  || 0,
        $term_data->{spam}  || 0,
        $term_data->{ham}   || 0
      );
      $count++;
    }
    $self->{dbh}->commit();

    dbg("Saved $count vocabulary terms to SQL for user: $username");

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
  # replace HTML entities and punctuation with spaces
  $text =~ s/&[a-z#0-9]+;/ /g;
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

  my $conf = $self->{main}->{conf};
  my $vocab_cap = $conf->{neuralnetwork_vocab_cap};

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

    my $meta_sth = $self->{dbh}->prepare("
      SELECT COUNT(*),
             SUM(CASE WHEN flag = 'S' THEN 1 ELSE 0 END),
             SUM(CASE WHEN flag = 'H' THEN 1 ELSE 0 END)
      FROM neural_seen
      WHERE username = ?
    ");
    $meta_sth->execute($username);
    my $meta = $meta_sth->fetchrow_arrayref();
    if ($meta) {
      $vocabulary{_doc_count}  = $meta->[0] || 0;
      $vocabulary{_spam_count} = $meta->[1] || 0;
      $vocabulary{_ham_count}  = $meta->[2] || 0;
    }

    dbg("Loaded $count vocabulary terms from SQL for user: $username " .
        "(spam_docs=$vocabulary{_spam_count}, ham_docs=$vocabulary{_ham_count})");

    # Prune vocabulary if needed
    $self->_prune_vocabulary(\%vocabulary, $vocab_cap);
    1;
  } or do {
    my $err = $@ || 'unknown';
    dbg("Failed to load vocabulary from SQL: $err");
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
    my $sth = $self->{dbh}->prepare(
      "UPDATE neural_vocabulary SET model_position = ? WHERE username = ? AND keyword = ?"
    );
    for my $i (0 .. $#$vocab_keys_ref) {
      $sth->execute($i, lc($username), $vocab_keys_ref->[$i]);
    }
    $self->{dbh}->commit();
    dbg("Saved model vocabulary (" . scalar(@$vocab_keys_ref) . " terms) to SQL for user: $username");
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
  };
  return $vocab_ref;
}

sub _model_vocab_path {
  my ($self, $nn_data_dir) = @_;
  return File::Spec->catfile($nn_data_dir, 'model-vocab-' . lc($self->{main}->{username}) . '.data');
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

  my $model_t = $self->{_neural_model_load_time} || 0;
  if (defined $self->{_model_vocab_cache}
      && ($self->{_model_vocab_cache_t} || 0) >= $model_t) {
    return $self->{_model_vocab_cache};
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
