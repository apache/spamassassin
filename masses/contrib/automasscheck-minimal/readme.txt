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


# WORK IN PROGRESS - axb-2012-09
# Feel free to edit/add/ or even remove this file

A minimalistic version for Warren Togami's (CLA) "auto-mass-check" routine

More documentation see:
http://wiki.apache.org/spamassassin/NightlyMassCheck

# Usage··

cp automasscheck-minimal.cf.dist ~/.automasscheck.cf

edit ~/.automasscheck.cf

cp automasscheck-minimal.sh ~/bin/automasscheck-minimal.sh

if required edit ~/bin/automasscheck-minimal.sh to configure
"JOBS"

setup a cron job to run "automasscheck-minimal.sh", everyday after 9AM UTC


