# Constants used in many parts of the SpamAssassin codebase.
#
# TODO! we need to reimplement parts of the RESERVED regexp!

# <@LICENSE>
# Copyright 2004 Apache Software Foundation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
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
	@BAYES_VARS @IP_VARS
);

use base qw( Exporter );

@IP_VARS = qw(
	IP_IN_RESERVED_RANGE LOCALHOST IPV4_ADDRESS IP_ADDRESS
);
@BAYES_VARS = qw(
	DUMP_MAGIC DUMP_TOKEN DUMP_BACKUP 
);

%EXPORT_TAGS = (
	bayes => [ @BAYES_VARS ],
        ip => [ @IP_VARS ],
        all => [ @BAYES_VARS, @IP_VARS ],
);

@EXPORT_OK = ( @BAYES_VARS, @IP_VARS );

# BAYES_VARS
use constant DUMP_MAGIC  => 1;
use constant DUMP_TOKEN  => 2;
use constant DUMP_SEEN   => 4;
use constant DUMP_BACKUP => 8;

# IP_VARS
# ---------------------------------------------------------------------------
# Initialize a regexp for reserved IPs, i.e. ones that could be
# used inside a company and be the first or second relay hit by
# a message. Some companies use these internally and translate
# them using a NAT firewall. These are listed in the RBL as invalid
# originators -- which is true, if you receive the mail directly
# from them; however we do not, so we should ignore them.
# cf. <http://www.iana.org/assignments/ipv4-address-space>,
#     <http://duxcw.com/faq/network/privip.htm>,
#     <http://duxcw.com/faq/network/autoip.htm>,
#     <ftp://ftp.rfc-editor.org/in-notes/rfc3330.txt>
#
# Last update
#   2003-11-07 bug 1784 changes removed due to relicensing
#   2003-04-15 Updated - bug 1784
#   2003-04-07 Justin Mason - removed some now-assigned nets
#   2002-08-24 Malte S. Stretz - added 172.16/12, 169.254/16
#   2002-08-23 Justin Mason - added 192.168/16
#   2002-08-12 Matt Kettler - mail to SpamAssassin-devel
#              msgid:<5.1.0.14.0.20020812211512.00a33cc0@192.168.50.2>
#
# **REIMPLEMENT**: This needs to be extended to re-include the ranges
# from the RFCs and documents above.
#
use constant IP_IN_RESERVED_RANGE => qr{^(?:
  192\.168|                        # 192.168/16:       Private Use
  10|                              # 10/8:             Private Use
  172\.(?:1[6-9]|2[0-9]|3[01])|    # 172.16-172.31/16: Private Use
  169\.254|                        # 169.254/16:       Private Use (APIPA)
  127|                             # 127/8:            Private Use (localhost)
  [01257]|                         # 000-002/8, 005/8, 007/8: Reserved
  2[37]|                           # 023/8, 027/8:     Reserved
  3[179]|                          # 031/8, 037/8, 039/8: Reserved
  4[12]|                           # 041/8, 042/8:     Reserved
  5[89]|                           # 058/8, 059/8:     Reserved
  60|                              # 060/8:            Reserved
  7[0-9]|                          # 070-079/8:        Reserved
  9[0-9]|                          #  -
  1[01][0-9]|                      #  -
  12[0-6]|                         # 126/8:            Reserved
  197|                             # 197/8:            Reserved
  22[23]|                          # 222/8, 223/8:     Reserved
  24[0-9]|                         # 240-
  25[0-5]			   # 255/8:            Reserved
)\.}ox;

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
		      # IPv4 mapped in IPv6
		      0{0,4} : (?:0{0,4}\:){1,2} ffff: 
		      127\.0\.0\.1 \b
		    |
		      # pure-IPv6 address
		      (?<!:)
		      (?:0{0,4}\:){0,7} 1 
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
		      # IPv4 mapped in IPv6
		      \:\: (?:[a-f0-9]{0,4}\:){0,4}
		      (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
		      (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
		      (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
		      (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\b
		    |
		      # a pure-IPv6 address
		      # don't use \b here, it hits on :'s
		      (?<!:)
		      (?:[a-f0-9]{0,4}\:){0,7} [a-f0-9]{0,4}
		    )
		  /oxi;

# ---------------------------------------------------------------------------

1;
