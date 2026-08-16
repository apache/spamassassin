#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_randomize_hosts");
use Test::More;

use File::Temp qw(tempdir);
use Config;
use Cwd qw(abs_path);

# ---------------------------------------------------------------------------
# Regression test for the spamc -H (SPAMC_RANDOMIZE_HOSTS) host/IP shuffle
# in spamc/libspamc.c.
# ---------------------------------------------------------------------------

unless (-f "../spamc/config.h") {
  plan skip_all => "../spamc/config.h not found; run spamc's configure first";
  exit;
}

my $cc = untaint_var($Config{cc} || 'cc');

plan tests => 4;

my $workdir = tempdir("spamc_randomize_hosts.XXXXXX", DIR => "log");
my $src = "$workdir/randomize_hosts_test.c";
my $bin = "$workdir/randomize_hosts_test";

my $libspamc_c = untaint_var(abs_path("../spamc/libspamc.c"));

open(my $fh, '>', $src) or die "cannot write $src: $!";
print $fh qq{#include "$libspamc_c"\n};
print $fh <<'EOC';
#include <stdio.h>
#include <string.h>

static struct addrinfo *make_chain(int n, int tag_base) {
    struct addrinfo *head = NULL, *tail = NULL;
    int i;
    for (i = 0; i < n; i++) {
        struct addrinfo *a = calloc(1, sizeof(*a));
        a->ai_addrlen = tag_base + i; /* identity tag, unused otherwise */
        a->ai_next = NULL;
        if (!head) head = tail = a;
        else { tail->ai_next = a; tail = a; }
    }
    return head;
}

static int chain_len(struct addrinfo *a) {
    int n = 0;
    while (a) { n++; a = a->ai_next; }
    return n;
}

static void chain_tags(struct addrinfo *a, int *out) {
    int i = 0;
    while (a) { out[i++] = (int) a->ai_addrlen; a = a->ai_next; }
}

int main(void) {
    struct transport tp;
    int i, trial;
    int perm_codes[6];
    int nperm_codes = 0;
    int chain_order_seen = 0;
    int orig_tags[3], cur_tags[3];
    int nhosts_ok = 1, chainlen_ok = 1;

    memset(&tp, 0, sizeof(tp));
    tp.nhosts = 3;
    for (i = 0; i < 3; i++)
        tp.hosts[i] = make_chain(3, i * 10);

    {
        struct addrinfo *fresh = make_chain(3, 0);
        chain_tags(fresh, orig_tags);
    }

    for (trial = 0; trial < 20000; trial++) {
        int idx[3], code, k, slot;

        _randomize_hosts(&tp);

        if (tp.nhosts != 3)
            nhosts_ok = 0;

        for (i = 0; i < 3; i++) {
            if (chain_len(tp.hosts[i]) != 3) {
                chainlen_ok = 0;
            }
        }

        for (i = 0; i < 3; i++) {
            idx[i] = ((int) tp.hosts[i]->ai_addrlen) / 10;
        }

        code = idx[0]*9 + idx[1]*3 + idx[2];
        slot = -1;
        for (k = 0; k < nperm_codes; k++) {
            if (perm_codes[k] == code) {
                slot = k;
                break;
            }
        }
        if (slot == -1 && nperm_codes < 6) {
            perm_codes[nperm_codes++] = code;
        }

        for (i = 0; i < 3; i++) {
            if (idx[i] == 0) {
                chain_tags(tp.hosts[i], cur_tags);
                if (memcmp(cur_tags, orig_tags, sizeof(orig_tags)) != 0) {
                    chain_order_seen = 1;
                }
                break;
            }
        }
    }

    printf("nhosts_unchanged=%d\n", nhosts_ok);
    printf("chainlen_unchanged=%d\n", chainlen_ok);
    printf("distinct_permutations=%d\n", nperm_codes);
    printf("chain_order_varied=%d\n", chain_order_seen);

    return 0;
}
EOC
close $fh;

my $build_status = untaint_system($cc, '-I', '../spamc', '-DHAVE_CONFIG_H',
                                   '-o', $bin, $src, '../spamc/utils.c', '-lz');

ok(($build_status == 0), "compile randomize_hosts test harness")
  or diag("build of $src failed (status=$build_status)");

SKIP: {
  skip "harness did not build", 3 if $build_status != 0;

  my $out = untaint_cmd($bin);
  my %v;
  while ($out =~ /^(\w+)=(\d+)$/mg) {
    $v{$1} = $2;
  }

  ok(($v{nhosts_unchanged} && $v{chainlen_unchanged}),
     "shuffle does not lose or duplicate hosts/IPs")
    or diag("harness output:\n$out");

  is($v{distinct_permutations}, 6,
     "all 3! top-level host orderings are reachable (not just a rotation)")
    or diag("harness output:\n$out");

  ok($v{chain_order_varied},
     "IPs within a single hostname's addrinfo chain are also randomized")
    or diag("harness output:\n$out");
}
