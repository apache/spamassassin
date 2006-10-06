#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

/* see http://www.eecs.harvard.edu/~ellard/Courses/sq98_root.pdf , pp 73-80
 * for the Rabin-Karp algorithm definition
 */
#define fast_b  ((long) 257)
#define fast_m  ((long) 1024)
#define ksize   4


static void av_push_all (AV *to, AV *from)
{
  int i, len;
  SV **svptr;

  len = av_len(from);
  for (i = 0; i <= len; i++) {
    svptr = av_fetch(from, i, 0);
    if (svptr == NULL) {
      continue;     /* this can happen, it seems */
    }

    //SvREFCNT_inc(*svptr);
    av_push (to, *svptr);
  }
}

static void add_rk_hit (AV *results, HV *keys, SV **keysv)
{
  AV *rulesav;
  int i, len;

  /* add rule names to results AV */
  rulesav = (AV *) SvRV(*keysv);

  len = av_len(rulesav);
  for (i = 0; i <= len; i++) {
    SV **svptr = av_fetch(rulesav, i, 0);
    if (svptr == NULL) {
      continue;     /* this can happen, it seems */
    }

    //SvREFCNT_inc(*svptr);
    av_push (results, *svptr);
  }
}

static char *
get_flut_str (HV *keys)
{
  SV **mapptr;
  char buf[(int) fast_m];
  SV *newmap;
  char *flut_str;
  STRLEN maplen;

  mapptr = hv_fetch (keys, "*BITMAP", 7, 0);

  /* create the map if it doesn't exist */
  if (mapptr == NULL || *mapptr == NULL)
  {
    Zero((void *) buf, (int) fast_m, char);
    newmap = newSVpvn(buf, (int) fast_m);       /* will take a copy */
    hv_store (keys, "*BITMAP", 7, newmap, 0);
    mapptr = &newmap;
  }

  flut_str = (char *) SvPV(*mapptr, maplen);
  if (maplen != (int) fast_m) {
    die ("oops! maplen shrunk to %d", maplen);
  }

  return flut_str;
}

static void
set_in_flut (HV *keys, int P_hash)
{
  char *flut_str;

  if (P_hash >= (int) fast_m) {
    die ("oops! P_hash %d > maplen %d", P_hash, (int) fast_m);
  }
  flut_str = get_flut_str(keys);
  flut_str[P_hash] = (char) 1;
}


static unsigned long
rk_exp_mod (unsigned long x, unsigned long n, unsigned long m)
{
  unsigned long square, exp;

  if (n == 0) {
    return 1;
  }
  else if (n == 1) {
    return (x % m);
  }
  else {
    square = (x * x) % m;
    exp = rk_exp_mod (square, n / 2, m);
    if (n % 2 == 0) {
      return (exp % m);
    } else {
      return ((exp * x) % m);
    }
  }
}

static long
rk_hash (unsigned char *str, long len, long b, long m)
{
  long i;
  long value = 0;
  long power = 1;

  for (i = len - 1; i >= 0; i--) {
    value += (power * str [i]);
    value %= m;
    power *= b;
    power %= m;
  }
  return (value);
}

static void
rk_search (AV *results, HV *keys, unsigned char *T, long T_len)
{
  long top_one;
  long T_hash;
  long i;
  SV *hashkey;
  char *hashkeystr;
  STRLEN len;
  SV **keysv;
  char *flut_str;

  flut_str = get_flut_str(keys);
  top_one = rk_exp_mod (fast_b, ksize, fast_m);
  T_hash = rk_hash (T, ksize, fast_b, fast_m);

  for (i = 0; i <= T_len - ksize; i++) {
    /* do we have a hash hit? */
    if (flut_str[(int) T_hash] != (char) 0) {
      hashkey = sv_2mortal(newSVpvf("%d", (int) T_hash));
      hashkeystr = SvPV(hashkey, len);
      if ((keysv = hv_fetch (keys, hashkeystr, len, 0)) != NULL)
      {
        /* copy the rule name SV ptrs to the results AV */
        add_rk_hit(results, keys, keysv);
      }
    }

    /* the bit-shifting Karp-Rabin sliding hash -- bit-shifts are fast */
    T_hash *= fast_b;
    T_hash -= ((T[i] * top_one) & (fast_m - 1));
    T_hash += T[i + ksize];
    T_hash &= (fast_m - 1);
    if (T_hash < 0) { T_hash += fast_m; }
  }
}



MODULE = RabinKarpAccel		PACKAGE = RabinKarpAccel		

PROTOTYPES: DISABLE

void
add_bitvec(bvhash, str, rulesary)
        SV* bvhash
        SV* str
        SV* rulesary

  PREINIT:
        unsigned char *pstart;
        unsigned char *pend;
        STRLEN plen;
        HV *bvhv;
        SV *hashkey;
        char *hashkeystr;
        STRLEN len;
        long P_hash;
        SV **svptr;

  CODE:
        if (!SvROK(bvhash) || (SvTYPE(SvRV(bvhash)) != SVt_PVHV)) {
          die("bad type for bvhash");
        }
        bvhv = (HV *) SvRV(bvhash);

        if (!SvROK(rulesary) || (SvTYPE(SvRV(rulesary)) != SVt_PVAV)) {
          die("bad type for rulesary");
        }

        pstart = (unsigned char *) SvPVutf8(str, plen);
        pend = pstart + plen;

        P_hash = rk_hash (pstart, ksize, fast_b, fast_m);

        /* add the contents of @{$rulesary} to the bvhv hash under 
         * the key "P_hash" */
        hashkey = newSVpvf("%d", (int) P_hash);
        hashkeystr = SvPV(hashkey, len);
        svptr = hv_fetch (bvhv, hashkeystr, len, 1);

        if (svptr == NULL || *svptr == NULL ||
          !SvROK(*svptr) ||
          (SvTYPE(SvRV(*svptr)) != SVt_PVAV))
        {
          SvREFCNT_inc(rulesary);
          hv_store (bvhv, hashkeystr, len, rulesary, 0);
        } else {
          av_push_all ((AV *) SvRV(*svptr), (AV *) SvRV(rulesary));
        }

        /* ensure we set the flag char in the fast lookup table, too */
        set_in_flut(bvhv, (int) P_hash);

SV *
scan_string(bvhash, psv)
        SV* bvhash
        SV* psv

  PREINIT:
        unsigned char *pstart;
        unsigned char *pend;
        STRLEN plen;
        AV *results;
        HV *bvhv;

  CODE:
        if (!SvROK(bvhash) || (SvTYPE(SvRV(bvhash)) != SVt_PVHV)) {
          die("bad type for bvhash");
        }
        bvhv = (HV *) SvRV(bvhash);

        pstart = (unsigned char *) SvPVutf8(psv, plen);
        pend = pstart + plen;
        results = (AV *) sv_2mortal((SV *) newAV());

        rk_search (results, bvhv, pstart, plen);

        RETVAL = newRV((SV *) results);
    OUTPUT:
        RETVAL


