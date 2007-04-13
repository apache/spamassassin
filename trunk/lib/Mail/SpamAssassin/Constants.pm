# Constants used in many parts of the SpamAssassin codebase.
#
# TODO! we need to reimplement parts of the RESERVED regexp!

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

package Mail::SpamAssassin::Constants;

use vars qw (
	@BAYES_VARS @IP_VARS @SA_VARS
);

use base qw( Exporter );

@IP_VARS = qw(
	IP_IN_RESERVED_RANGE IP_PRIVATE LOCALHOST IPV4_ADDRESS IP_ADDRESS
);
@BAYES_VARS = qw(
	DUMP_MAGIC DUMP_TOKEN DUMP_BACKUP 
);
# These are generic constants that may be used across several modules
@SA_VARS = qw(
	HARVEST_DNSBL_PRIORITY MBX_SEPARATOR
	MAX_BODY_LINE_LENGTH MAX_HEADER_KEY_LENGTH MAX_HEADER_VALUE_LENGTH
	MAX_HEADER_LENGTH ARITH_EXPRESSION_LEXER AI_TIME_UNKNOWN
	CHARSETS_LIKELY_TO_FP_AS_CAPS MAX_URI_LENGTH
);

%EXPORT_TAGS = (
	bayes => [ @BAYES_VARS ],
        ip => [ @IP_VARS ],
        sa => [ @SA_VARS ],
        all => [ @BAYES_VARS, @IP_VARS, @SA_VARS ],
);

@EXPORT_OK = ( @BAYES_VARS, @IP_VARS, @SA_VARS );

# BAYES_VARS
use constant DUMP_MAGIC  => 1;
use constant DUMP_TOKEN  => 2;
use constant DUMP_SEEN   => 4;
use constant DUMP_BACKUP => 8;

# IP_VARS
# ---------------------------------------------------------------------------
# Initialize a regexp for private IPs, i.e. ones that could be
# used inside a company and be the first or second relay hit by
# a message. Some companies use these internally and translate
# them using a NAT firewall. These are listed in the RBL as invalid
# originators -- which is true, if you receive the mail directly
# from them; however we do not, so we should ignore them.
# 
# sources:
#   IANA  = <http://www.iana.org/assignments/ipv4-address-space>,
#           <http://duxcw.com/faq/network/privip.htm>,
#   APIPA = <http://duxcw.com/faq/network/autoip.htm>,
#   3330  = <ftp://ftp.rfc-editor.org/in-notes/rfc3330.txt>
#   CYMRU = <http://www.cymru.com/Documents/bogon-list.html>
#
# Last update
#   2005-01-10 Daniel Quinlan - reduced to standard private IP addresses
#
use constant IP_PRIVATE => qr{^(?:
  10|				   # 10/8:             Private Use (3330)
  127|				   # 127/8:            Private Use (localhost)
  169\.254|			   # 169.254/16:       Private Use (APIPA)
  172\.(?:1[6-9]|2[0-9]|3[01])|	   # 172.16-172.31/16: Private Use (3330)
  192\.168			   # 192.168/16:       Private Use (3330)
)\.}ox;

# backward compatibility
use constant IP_IN_RESERVED_RANGE => IP_PRIVATE;

# ---------------------------------------------------------------------------
# match the various ways of saying "localhost".
# 
use constant LOCALHOST => qr/
		    (?:
		      # as a string
		      localhost(?:\.localdomain)?
		    |
		      \b(?<!:)	# ensure no "::" IPv4 marker before this one
		      # plain IPv4
		      127\.0\.0\.1 \b
		    |
		      # IPv6 addresses
		      # don't use \b here, it hits on :'s
		      (?:IPv6:    # with optional prefix
                        | (?<![a-f0-9:])
                      )
		      (?:
			# IPv4 mapped in IPv6
			# note the colon after the 12th byte in each here
			(?:
			  # first 6 (12 bytes) non-zero
			  (?:0{1,4}:){5}		ffff:
			  |
			  # leading zeros omitted (note {0,5} not {1,5})
			  ::(?:0{1,4}:){0,4}		ffff:
			  |
			  # trailing zeros (in the first 6) omitted
			  (?:0{1,4}:){1,4}:		ffff:
			  |
			  # 0000 in second up to (including) fifth omitted
			  0{1,4}::(?:0{1,4}:){1,3}	ffff:
			  |
			  # 0000 in third up to (including) fifth omitted
			  (?:0{1,4}:){2}:0{1,2}:	ffff:
			  |
			  # 0000 in fourth up to (including) fifth omitted
			  (?:0{1,4}:){3}:0:		ffff:
			  |
			  # 0000 in fifth omitted
			  (?:0{1,4}:){4}:		ffff:
			)
			# and the IPv4 address appended to all of the 12 bytes above
			127\.0\.0\.1	# no \b, we check later

			| # or (separately) a pure IPv6 address

			# all 8 (16 bytes) of them present
			(?:0{1,4}:){7}			0{0,3}1
			|
			# leading zeros omitted
			:(?::0{1,4}){0,6}:		0{0,3}1
			|
			# 0000 in second up to (including) seventh omitted
			0{1,4}:(?::0{1,4}){0,5}:	0{0,3}1
			|
			# 0000 in third up to (including) seventh omitted
			(?:0{1,4}:){2}(?::0{1,4}){0,4}:	0{0,3}1
			|
			# 0000 in fouth up to (including) seventh omiited
			(?:0{1,4}:){3}(?::0{1,4}){0,3}:	0{0,3}1
			|
			# 0000 in fifth up to (including) seventh omitted
			(?:0{1,4}:){4}(?::0{1,4}){0,2}:	0{0,3}1
			|
			# 0000 in sixth up to (including) seventh omitted
			(?:0{1,4}:){5}(?::0{1,4}){0,1}:	0{0,3}1
			|
			# 0000 in seventh omitted
			(?:0{1,4}:){6}:			0{0,3}1
		      )
		      (?![a-f0-9:])
		    )
		  /oxi;

# ---------------------------------------------------------------------------
# an IP address, in IPv4 format only.
#
use constant IPV4_ADDRESS => qr/\b
		    (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
                    (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
                    (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
                    (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)
                  \b/ox;

# ---------------------------------------------------------------------------
# an IP address, in IPv4, IPv4-mapped-in-IPv6, or IPv6 format.  NOTE: cannot
# just refer to $IPV4_ADDRESS, due to perl bug reported in nesting qr//s. :(
#
use constant IP_ADDRESS => qr/
		    (?:
		      \b(?<!:)	# ensure no "::" IPv4 marker before this one
		      # plain IPv4, as above
		      (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
		      (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
		      (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
		      (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\b
		    |
		      # IPv6 addresses
		      # don't use \b here, it hits on :'s
		      (?:IPv6:    # with optional prefix
                        | (?<![a-f0-9:])
                      )
		      (?:
			# IPv4 mapped in IPv6
			# note the colon after the 12th byte in each here
			(?:
			  # first 6 (12 bytes) non-zero
			  (?:[a-f0-9]{1,4}:){6}
			  |
			  # leading zeros omitted (note {0,5} not {1,5})
			  ::(?:[a-f0-9]{1,4}:){0,5}
			  |
			  # trailing zeros (in the first 6) omitted
			  (?:[a-f0-9]{1,4}:){1,5}:
			  |
			  # 0000 in second up to (including) fifth omitted
			  [a-f0-9]{1,4}::(?:[a-f0-9]{1,4}:){1,4}
			  |
			  # 0000 in third up to (including) fifth omitted
			  (?:[a-f0-9]{1,4}:){2}:(?:[a-f0-9]{1,4}:){1,3}
			  |
			  # 0000 in fourth up to (including) fifth omitted
			  (?:[a-f0-9]{1,4}:){3}:(?:[a-f0-9]{1,4}:){1,2}
			  |
			  # 0000 in fifth omitted
			  (?:[a-f0-9]{1,4}:){4}:[a-f0-9]{1,4}:
			)
			# and the IPv4 address appended to all of the 12 bytes above
			(?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
			(?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
			(?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
			(?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)   # no \b, we check later

			| # or (separately) a pure IPv6 address

			# all 8 (16 bytes) of them present
			(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}
			|
			# leading zeros omitted
			:(?::[a-f0-9]{1,4}){1,7}
			|
			# trailing zeros omitted
			(?:[a-f0-9]{1,4}:){1,7}:
			|
			# 0000 in second up to (including) seventh omitted
			[a-f0-9]{1,4}:(?::[a-f0-9]{1,4}){1,6}
			|
			# 0000 in third up to (including) seventh omitted
			(?:[a-f0-9]{1,4}:){2}(?::[a-f0-9]{1,4}){1,5}
			|
			# 0000 in fouth up to (including) seventh omiited
			(?:[a-f0-9]{1,4}:){3}(?::[a-f0-9]{1,4}){1,4}
			|
			# 0000 in fifth up to (including) seventh omitted
			(?:[a-f0-9]{1,4}:){4}(?::[a-f0-9]{1,4}){1,3}
			|
			# 0000 in sixth up to (including) seventh omitted
			(?:[a-f0-9]{1,4}:){5}(?::[a-f0-9]{1,4}){1,2}
			|
			# 0000 in seventh omitted
			(?:[a-f0-9]{1,4}:){6}:[a-f0-9]{1,4}
			|
			# :: (the unspecified addreess 0:0:0:0:0:0:0:0)
			# dos: I don't expect to see this address in a header, and
			# it may cause non-address strings to match, but we'll
			# include it for now since it is valid
			::
		      )
		      (?![a-f0-9:])
		    )
		  /oxi;

# ---------------------------------------------------------------------------

use constant HARVEST_DNSBL_PRIORITY =>  500;

# regular expression that matches message separators in The University of
# Washington's MBX mailbox format
use constant MBX_SEPARATOR => qr/^([\s|\d]\d-[a-zA-Z]{3}-\d{4}\s\d{2}:\d{2}:\d{2}.*),(\d+);([\da-f]{12})-(\w{8})\r?$/;
# $1 = datestamp (str)
# $2 = size of message in bytes (int)
# $3 = message status - binary (hex)
# $4 = message ID (hex)

# ---------------------------------------------------------------------------
# values used for internal message representations

# maximum byte length of lines in the body
use constant MAX_BODY_LINE_LENGTH => 2048;
# maximum byte length of a header key
use constant MAX_HEADER_KEY_LENGTH => 256;
# maximum byte length of a header value including continued lines
use constant MAX_HEADER_VALUE_LENGTH => 8192;
# maximum byte length of entire header
use constant MAX_HEADER_LENGTH => 65536;

# maximum byte length of any given URI
use constant MAX_URI_LENGTH => 8192;

# used for meta rules and "if" conditionals in Conf::Parser
use constant ARITH_EXPRESSION_LEXER => qr/(?:
        [\-\+\d\.]+|                            # A Number
        \w[\w\:]*|                              # Rule or Class Name
        [\(\)]|                                 # Parens
        \|\||                                   # Boolean OR
        \&\&|                                   # Boolean AND
        \^|                                     # Boolean XOR
        !(?!=)|                                 # Boolean NOT
        >=?|                                    # GT or EQ
        <=?|                                    # LT or EQ
        ==|                                     # EQ
        !=|                                     # NEQ
        [\+\-\*\/]|                             # Mathematical Operator
        [\?:]                                   # ? : Operator
      )/ox;

# ArchiveIterator

# if AI doesn't read in the message in the first pass to see if the received
# date makes the message useful or not, we need to mark it so that in the
# second pass (when the message is actually read + processed) the received
# date is calculated.  this value signifies "unknown" from the first pass.
use constant AI_TIME_UNKNOWN => 0;

# Charsets which use capital letters heavily in their encoded representation.
use constant CHARSETS_LIKELY_TO_FP_AS_CAPS => qr{[-_a-z0-9]*(?:
	  koi|jp|jis|euc|gb|big5|isoir|cp1251|georgianps|pt154|tis
	)[-_a-z0-9]*}ix;

1;
