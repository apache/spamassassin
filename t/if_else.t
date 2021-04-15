#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("if_else");
use Test::More tests => 21;

# ---------------------------------------------------------------------------

%patterns = (

  q{ GTUBE }, 'gtube',
  q{ SHOULD_BE_CALLED01 }, 'should_be_called01',
  q{ SHOULD_BE_CALLED02 }, 'should_be_called02',
  q{ SHOULD_BE_CALLED03 }, 'should_be_called03',
  q{ SHOULD_BE_CALLED04 }, 'should_be_called04',
  q{ SHOULD_BE_CALLED05 }, 'should_be_called05',
  q{ SHOULD_BE_CALLED06 }, 'should_be_called06',
  q{ SHOULD_BE_CALLED07 }, 'should_be_called07',

);
%anti_patterns = (

  q{ SHOULD_NOT_BE_CALLED01 }, 'should_not_be_called01',
  q{ SHOULD_NOT_BE_CALLED02 }, 'should_not_be_called02',
  q{ SHOULD_NOT_BE_CALLED03 }, 'should_not_be_called03',
  q{ SHOULD_NOT_BE_CALLED04 }, 'should_not_be_called04',
  q{ SHOULD_NOT_BE_CALLED05 }, 'should_not_be_called05',
  q{ SHOULD_NOT_BE_CALLED06 }, 'should_not_be_called06',
  q{ SHOULD_NOT_BE_CALLED07 }, 'should_not_be_called07',
  q{ SHOULD_NOT_BE_CALLED08 }, 'should_not_be_called08',
  q{ SHOULD_NOT_BE_CALLED09 }, 'should_not_be_called09',
  q{ SHOULD_NOT_BE_CALLED10 }, 'should_not_be_called10',
  q{ SHOULD_NOT_BE_CALLED11 }, 'should_not_be_called11',
  q{ SHOULD_NOT_BE_CALLED12 }, 'should_not_be_called12',

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

