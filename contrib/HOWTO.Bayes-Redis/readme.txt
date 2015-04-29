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
###########################################################################


# Updated: 2014-09-04 (axb@apache.org)

What's so cool about Bayes/Redis

- speed, speed, speed
- zero maintenance
- cheap to run  - all it needs is cheap memory - the more the better.
- Hint: feed spam from trap box with longer expiration times than production traffic


------------------------------------------
Get Redis "Stable" from

http://redis.io/download

Follow steps in "Installation"

Redis docs: http://redis.io/documentation

run "redis-cli info" to get an idea of what's going on.

see Redis cli commands
http://redis.io/commands

If you need help, pls use the SA user's mailing list
If you're a Redis/Bayes user please post some feedback in the SA user's mailing list


Resources usage to give you an idea how much memory you may need on a biggish system
with a token TTL of 10 days.

sa-learn --dump magic
0.000          0          3          0  non-token data: bayes db version
0.000          0   30125835          0  non-token data: nspam
0.000          0   13887519          0  non-token data: nham

30 MILLION! use:

# Memory
used_memory:5787709376
used_memory_human:5.39G
used_memory_rss:5909553152
used_memory_peak:5808814272
used_memory_peak_human:5.41G
used_memory_lua:104448
mem_fragmentation_ratio:1.02
mem_allocator:jemalloc-3.2.0
