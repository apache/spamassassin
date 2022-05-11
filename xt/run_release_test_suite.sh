#!/bin/sh

# This runs all tests, overriding the default selection used by make test
# There are some tests disabled for even this run for various reasons
# Those tests will show up in the output as being skipped
# This script is intended to be run by the developers of SpamAssassin before
# a release. It might also be useful to downstream package maintainers.
# These tests include the spamd stress test which will attempt to kill running spamd processes
# so this script should not be run on a production server that is running spamd.
# Note that some tests require certain Perl modules to be installed or else they are skipped.
# Install all optional modules on a release build/test machine so all feasable tests are run.
# The root* tests will be skipped because this script will not run as root
# Use sudo make test TEST_FILES="t/root*.t" to run just those tests separately

# All command line arguments passed to this script are pasased to the call to prove

if [ "$(id -u)" -eq 0 ]; then echo Do ont run this as root; exit 1; fi

# Remove -T option from user, because this script always adds it
# Check for a verbose option and pass it to t.rules/run
for a; do
    shift
    case $a in
	-T) taint="$a";;
	-v) verbose="$a";;
	--verbose) verbose="$a";;
	*) set -- "$@" "$a";;
    esac
done

# Be lenient if the script was started while in its own directory
if [ -d "../t" ]; then cd ..; fi

if [ ! -f "t/test_dir" ]; then
    echo "This must be run from the source tree root directory"
    exit 1
fi

if ! command -v prove >/dev/null 2>&1 ; then
    echo "Can't find 'prove' command which is usually installed as part of perl"
    exit 1
fi

overrideflags="run_long_tests:run_net_tests:run_dcc_tests:run_sql_pref_tests:run_spamd_prefork_stress_test"
overridevalues="1:1:1:1:1"

# force -T on the tests, don't leave it up to the user
prove -T $verbose "$@" t/*.t xt/20_saw_ampersand.t :: --override $overrideflags $overridevalues

# t.rules/run script takes a --verbose option but it is too verbose when used with prove -v
# If you need to see more output from a rule test use   t.rules/run --verbose --tests RULENAME 
prove -T $verbose t.rules/run
