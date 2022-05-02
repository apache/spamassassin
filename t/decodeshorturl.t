#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("decodeshorturl");

use Test::More;

use constant HAS_DBI => eval { require DBI; };
use constant HAS_DBD_SQLITE => eval { require DBD::SQLite; };

use constant SQLITE => (HAS_DBI && HAS_DBD_SQLITE);

plan skip_all => "Net tests disabled"                unless conf_bool('run_net_tests');
my $tests = 3;
$tests += 2 if (SQLITE);
plan tests => $tests;

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::DecodeShortURLs
");

tstprefs("
dns_query_restriction allow bit.ly
dns_query_restriction allow tinyurl.com

url_shortener bit.ly
url_shortener tinyurl.com

body HAS_SHORT_URL              eval:short_url()
describe HAS_SHORT_URL          Message contains one or more shortened URLs

body SHORT_URL_CHAINED          eval:short_url_chained()
describe SHORT_URL_CHAINED      Message has shortened URL chained to other shorteners

body SHORT_URL_404		eval:short_url_404()
describe SHORT_URL_404		Short URL is invalid
");

%patterns_url = (
   q{ 1.0 HAS_SHORT_URL } => 'Message contains one or more shortened URLs',
   q{ 1.0 HAS_SHORT_404 } => 'Message contains one or more shortened URLs',
            );

%patterns_url_chain = (
   q{ 1.0 SHORT_URL_CHAINED } => 'Message has shortened URL chained to other shorteners',
            );

%patterns = %patterns_url;
sarun ("-t < data/spam/decodeshorturl/base.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = %patterns_url_chain;
sarun ("-t < data/spam/decodeshorturl/chain.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

if (SQLITE) {

tstprefs("
dns_query_restriction allow bit.ly
dns_query_restriction allow tinyurl.com

url_shortener bit.ly
url_shortener tinyurl.com

url_shortener_cache_type dbi
url_shortener_cache_dsn dbi:SQLite:dbname=$workdir/DecodeShortURLs.db

body HAS_SHORT_URL              eval:short_url()
describe HAS_SHORT_URL          Message contains one or more shortened URLs
");

%patterns_url = (
   q{ 1.0 HAS_SHORT_URL } => 'Message contains one or more shortened URLs',
            );

%patterns = %patterns_url;
sarun ("-t < data/spam/decodeshorturl/base.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

my $dbh = DBI->connect("dbi:SQLite:dbname=$workdir/DecodeShortURLs.db","","");
my @row = $dbh->selectrow_array("SELECT decoded_url FROM short_url_cache WHERE short_url = 'http://bit.ly/30yH6WK'");
is($row[0], 'http://spamassassin.apache.org/');
}
