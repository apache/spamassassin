#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("decodeshorturl");

use Test::More;

plan skip_all => "Net tests disabled"                unless conf_bool('run_net_tests');
plan tests => 2;

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::DecodeShortURLs
");

tstprefs("
dns_query_restriction allow bit.ly
dns_query_restriction allow tinyurl.com

url_shortener bit.ly
url_shortener tinyurl.com

ifplugin Mail::SpamAssassin::Plugin::DecodeShortURLs
  body HAS_SHORT_URL              eval:short_url()
  describe HAS_SHORT_URL          Message contains one or more shortened URLs

  body SHORT_URL_CHAINED          eval:short_url_chained()
  describe SHORT_URL_CHAINED      Message has shortened URL chained to other shorteners
endif
");

%patterns_url = (
   q{ HAS_SHORT_URL } => 'Message contains one or more shortened URLs',
            );

%patterns_url_chain = (
   q{ SHORT_URL_CHAINED } => 'Message has shortened URL chained to other shorteners',
            );

%patterns = %patterns_url;
sarun ("-t < data/spam/decodeshorturl/base.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = %patterns_url_chain;
sarun ("-t < data/spam/decodeshorturl/chain.eml", \&patterns_run_cb);
ok_all_patterns();
