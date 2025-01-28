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

package Mail::SpamAssassin::Header;
use strict;
use warnings FATAL => 'all';
use Exporter qw(import);

our @EXPORT = qw(_unfold_lines _remove_comments _replace_char);

=head1 NAME

    Mail::SpamAssassin::Header - base class for SpamAssassin headers

=head1 SYNOPSIS

    my $header = Mail::SpamAssassin::Header->new('raw header value');
    print $header->value;

=head1 DESCRIPTION

This class is used to represent a generic header in SpamAssassin. It is used as a base class
for more specific header types.

=head1 METHODS

=over 4

=item new($raw)

Creates a new instance of the class. Accepts the raw header value as a string.

=cut

sub new {
    my ($class,$raw) = @_;
    my $self = bless {
        raw => $raw,
    }, $class;
    return $self;
}

=item raw()

Returns the raw header value as a string.

=cut

sub raw { return $_[0]->{raw}; }

=item value()

Returns the header value as a string. For a generic header, this is the same as the raw value.
It is overridden in subclasses to provide more specific functionality.

=cut

sub value { return $_[0]->{raw}; }

sub _unfold_lines {
    $_[0] =~ s/(?:\r\n|[\r\n])\s+/ /g;
}

#
# Remove comments from string
# - Comments are enclosed in parentheses ()
# - Comments can be nested
# - Backslash escapes the next character
# - Ignore comments in quoted strings
#
sub _remove_comments {
    my $output = '';
    my $level = 0;
    my $removed = 0;
    for(my $i=0; $i<length($_[0]); $i++) {
        my $ch = substr($_[0],$i,1);
        if ($ch eq '\\') {
            $i++;
            $output .= substr($_[0],$i,1) if $level == 0;
            next;
        }
        if ($level == -1) {
            # Inside quoted string
            if ($ch eq '"') {
                $level = 0;
            }
        } elsif ($level == 0) {
            if ($ch eq '(') {
                $level = 1;
                $removed++;
                next;
            } elsif ($ch eq '"') {
                $level = -1;
            }
        } else {
            # Inside comment
            if ($ch eq '(') {
                $level++;
            } elsif ($ch eq ')') {
                $level--;
            }
            next;
        }
        $output .= $ch;
    }
    return 0 unless $removed;
    # Remove extra whitespace left over by removing comments
    $output =~ s/\s+/ /g;
    $output =~ s/^\s+|\s+$//g;
    $_[0] = $output;
    return $removed;
}

#
# Replace characters in a string, but ignore those in quoted strings
#
sub _replace_char {
    my ($find,$replace) = @_[1,2];
    my $state = 0;
    my $replacements = 0;
    for(my $i=0; $i<length($_[0]); $i++) {
        my $ch = substr($_[0],$i,1);
        if ($ch eq '\\') {
            $i++;
            next;
        }
        if ($state == 0) {
            if ($ch eq '"') {
                $state = 1;
            } elsif ( $ch eq $find ) {
                substr($_[0],$i,1) = $replace;
                $replacements++;
            }
        } elsif ($state == 1) {
            if ($ch eq '"') {
                $state = 0;
            }
        }
    }
    return $replacements;
}

=back

=cut

1;