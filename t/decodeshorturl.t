#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("decodeshorturl");

use Test::More;

use constant HAS_DBI => eval { require DBI; };
use constant HAS_DBD_SQLITE => eval { require DBD::SQLite; DBD::SQLite->VERSION(1.59_01); };

use constant SQLITE => (HAS_DBI && HAS_DBD_SQLITE);

plan skip_all => "Net tests disabled"                unless conf_bool('run_net_tests');
my $tests = 8;
$tests += 4 if (SQLITE);
plan tests => $tests;

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::DecodeShortURLs
");

tstprefs(q{
dns_query_restriction allow bit.ly
dns_query_restriction allow tinyurl.com

clear_url_shortener
url_shortener tinyurl.com
url_shortener .page.link
url_shortener_get bit.ly

body HAS_SHORT_URL              eval:short_url()
body HAS_SHORT_REDIR            eval:short_url_redir()
body SHORT_URL_CHAINED          eval:short_url_chained()
body SHORT_URL_404		eval:short_url_404()
body SHORT_URL_C404		eval:short_url_code('404')
uri URI_BITLY_BLOCKED		m,^https://bitly\.com/a/blocked,
uri URI_PAGE_LINK		m,^https://spamassassin\.apache\.org/news\.html,
});

###
### Basic functions, no caching
###

%patterns = (
   q{ 1.0 HAS_SHORT_URL } => '',
   q{ 1.0 HAS_SHORT_REDIR } => '',
   q{ 1.0 SHORT_URL_404 } => '',
   q{ 1.0 SHORT_URL_C404 } => '',
   q{ 1.0 URI_BITLY_BLOCKED } => '',
   q{ 1.0 URI_PAGE_LINK } => '',
);
sarun ("-t < data/spam/decodeshorturl/base.eml", \&patterns_run_cb);
ok_all_patterns();

%patterns = (
   q{ 1.0 SHORT_URL_CHAINED } => '',
);
sarun ("-t < data/spam/decodeshorturl/chain.eml", \&patterns_run_cb);
ok_all_patterns();


###
### short_url() should hit even without network enabled
###

%patterns = (
   q{ 1.0 HAS_SHORT_URL } => '',
);
sarun ("-t -L < data/spam/decodeshorturl/base.eml", \&patterns_run_cb);
ok_all_patterns();

###
### With SQLITE caching
###

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

%patterns = (
   q{ 1.0 HAS_SHORT_URL } => '',
);
sarun ("-t < data/spam/decodeshorturl/base.eml", \&patterns_run_cb);
ok_all_patterns();

my $dbh = DBI->connect("dbi:SQLite:dbname=$workdir/DecodeShortURLs.db","","");
my @row = $dbh->selectrow_array("SELECT decoded_url FROM short_url_cache WHERE short_url = 'http://bit.ly/30yH6WK'");
is($row[0], 'http://spamassassin.apache.org/');

# Check another email to cleanup old entries from database
sarun ("-t < data/spam/decodeshorturl/base2.eml", \&patterns_run_cb);
ok_all_patterns();

$dbh = DBI->connect("dbi:SQLite:dbname=$workdir/DecodeShortURLs.db","","");
@row = $dbh->selectrow_array("SELECT decoded_url FROM short_url_cache WHERE short_url = 'http://bit.ly/30yH6WK'");
isnt($row[0], 'https://spamassassin.apache.org/');

}

