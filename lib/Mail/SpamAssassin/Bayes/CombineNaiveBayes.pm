# Naive-Bayesian-style probability combining and related constants.
#
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

use strict;  # make Test::Perl::Critic happy

# this package is a no-op; the real impl code is in another pkg.
package Mail::SpamAssassin::Bayes::CombineNaiveBayes; 1;

# Force into another package, so our symbols will appear in that namespace with
# no indirection, for speed.  Other combiners must do the same, since Bayes.pm
# uses this namespace directly. This means only one combiner can be loaded at
# any time.
package Mail::SpamAssassin::Bayes::Combine;

use strict;
use warnings;
use bytes;
use re 'taint';

###########################################################################

# Value for 'x' in Gary Robinson's f(w) equation.
# "Let x = the number used when n [hits] is 0."
our $FW_X_CONSTANT = 0.600;

# Value for 's' in the f(w) equation.  "We can see s as the "strength" (hence
# the use of "s") of an original assumed expectation ... relative to how
# strongly we want to consider our actual collected data."  Low 's' means
# trust collected data more strongly.
our $FW_S_CONSTANT = 0.160;

# (s . x) for the f(w) equation.
our $FW_S_DOT_X = ($FW_X_CONSTANT * $FW_S_CONSTANT);

# Should we ignore tokens with probs very close to the middle ground (.5)?
# tokens need to be outside the [ .5-MPS, .5+MPS ] range to be used.
our $MIN_PROB_STRENGTH = 0.430;

###########################################################################

# Combine probabilities using Gary Robinson's naive-Bayesian-style
# combiner
sub combine {
  my ($ns, $nn, $sortedref) = @_;

  my $wc = scalar @$sortedref;
  return unless $wc;

  my $P = 1;
  my $Q = 1;

  foreach my $pw (@$sortedref) {
    $P *= (1-$pw);
    $Q *= $pw;
  }
  $P = 1 - ($P ** (1 / $wc));
  $Q = 1 - ($Q ** (1 / $wc));
  return (1 + ($P - $Q) / ($P + $Q)) / 2.0;
}

1;
