#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("if_else");
use Test::More tests => 21;

# ---------------------------------------------------------------------------

%patterns = (

  q{ 1000 GTUBE }, '',
  q{ 1.0 SHOULD_BE_CALLED01 }, '',
  q{ 1.0 SHOULD_BE_CALLED02 }, '',
  q{ 1.0 SHOULD_BE_CALLED03 }, '',
  q{ 1.0 SHOULD_BE_CALLED04 }, '',
  q{ 1.0 SHOULD_BE_CALLED05 }, '',
  q{ 1.0 SHOULD_BE_CALLED06 }, '',
  q{ 1.0 SHOULD_BE_CALLED07 }, '',

);
%anti_patterns = (

  q{ SHOULD_NOT_BE_CALLED01 }, '',
  q{ SHOULD_NOT_BE_CALLED02 }, '',
  q{ SHOULD_NOT_BE_CALLED03 }, '',
  q{ SHOULD_NOT_BE_CALLED04 }, '',
  q{ SHOULD_NOT_BE_CALLED05 }, '',
  q{ SHOULD_NOT_BE_CALLED06 }, '',
  q{ SHOULD_NOT_BE_CALLED07 }, '',
  q{ SHOULD_NOT_BE_CALLED08 }, '',
  q{ SHOULD_NOT_BE_CALLED09 }, '',
  q{ SHOULD_NOT_BE_CALLED10 }, '',
  q{ SHOULD_NOT_BE_CALLED11 }, '',
  q{ SHOULD_NOT_BE_CALLED12 }, '',

);

tstlocalrules (q{

  if (0)
    body SHOULD_NOT_BE_CALLED01 /./
  endif

  if (1)
    body SHOULD_BE_CALLED01 /./
  endif

  if (0)
    body SHOULD_NOT_BE_CALLED02 /./
  else
    body SHOULD_BE_CALLED02 /./
  endif

  if (1)
    body SHOULD_BE_CALLED03 /./
  else
    body SHOULD_NOT_BE_CALLED03 /./
  endif

  if (1)
    if (1)
      body SHOULD_BE_CALLED04 /./
    else
      body SHOULD_NOT_BE_CALLED04 /./
    endif
  else
    body SHOULD_NOT_BE_CALLED05 /./
  endif

  if (0)
    if (0)
      body SHOULD_NOT_BE_CALLED06 /./
    else
      # Bug 7848
      body SHOULD_NOT_BE_CALLED07 /./
    endif
  else
    body SHOULD_BE_CALLED05 /./
  endif

  if (0)
    if (1)
      body SHOULD_NOT_BE_CALLED08 /./
    else
      if (1)
        # Bug 7848
        body SHOULD_NOT_BE_CALLED09 /./
      endif
    endif
  else
    body SHOULD_BE_CALLED06 /./
  endif

  if (1)
    if (0)
      body SHOULD_NOT_BE_CALLED10 /./
    else
      if (0)
        body SHOULD_NOT_BE_CALLED11 /./
      else
        if (0)
          body SHOULD_NOT_BE_CALLED12 /./
        else
          body SHOULD_BE_CALLED07 /./
        endif
      endif
    endif
  endif

});

ok (sarun ("-L -t < data/spam/gtube.eml", \&patterns_run_cb));
ok_all_patterns();

