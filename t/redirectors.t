#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("redirectors");

use Test::More;

use constant HAS_LWP_USERAGENT => eval { require LWP::UserAgent; require LWP::Protocol::https; };
use constant HAS_DBI => eval { require DBI; };
use constant HAS_DBD_SQLITE => eval { require DBD::SQLite; DBD::SQLite->VERSION(1.59_01); };

# The Selenium::Remote::Driver module being installed doesn't mean a
# WebDriver server is actually reachable; probe the default
# url_redirector_selenium_host/port so this section is skipped cleanly
# in environments without one running, instead of failing.
use constant HAS_SELENIUM => eval { require Selenium::Remote::Driver } && eval {
  require IO::Socket::INET;
  my $sock = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1', PeerPort => 4444,
    Proto => 'tcp', Timeout => 2,
  );
  my $ok = defined $sock;
  $sock->close if $ok;
  $ok;
};

use constant SQLITE => (HAS_DBI && HAS_DBD_SQLITE);

plan skip_all => "Net tests disabled"                unless conf_bool('run_net_tests');
plan skip_all => "LWP::Protocol::https required to run this test" unless HAS_LWP_USERAGENT;
my $tests = 4;
$tests += 4 if (SQLITE);
$tests += 2 if (HAS_SELENIUM);
plan tests => $tests;

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::Redirectors
");

tstprefs(q{
dns_query_restriction allow apache.org

clear_url_redirector
url_redirector_get spamassassin.apache.org
url_redirector_get community.apache.org

body HAS_REDIR_URL              eval:redir_url()
body REDIR_URL_404              eval:redir_url_404()
body REDIR_URL_C404             eval:redir_url_code('404')
uri URI_PAGE_LINK		m,^https://spamassassin\.apache\.org/full/4\.0\.x/$,
});

###
### Basic functions, no caching
###

%patterns = (
   q{ 1.0 HAS_REDIR_URL } => '',
   q{ 1.0 REDIR_URL_404 } => '',
   q{ 1.0 REDIR_URL_C404 } => '',
   q{ 1.0 URI_PAGE_LINK } => '',
);
sarun ("-t < data/spam/redirectors/base.eml", \&patterns_run_cb);
ok_all_patterns();

###
### With SQLITE caching
###

if (SQLITE) {

tstprefs("
clear_url_redirector
url_redirector_get spamassassin.apache.org

url_redirector_cache_type dbi
url_redirector_cache_dsn dbi:SQLite:dbname=$workdir/Redirectors.db

body HAS_REDIR_URL              eval:redir_url()
describe HAS_REDIR_URL          Message contains one or more redirected URLs
");

%patterns = (
   q{ 1.0 HAS_REDIR_URL } => '',
);
sarun ("-t < data/spam/redirectors/base.eml", \&patterns_run_cb);
ok_all_patterns();

my $dbh = DBI->connect("dbi:SQLite:dbname=$workdir/Redirectors.db","","");
my @row = $dbh->selectrow_array("SELECT target_url FROM redir_url_cache WHERE redir_url = 'https://spamassassin.apache.org/full/4.0.x'");
is($row[0], 'https://spamassassin.apache.org/full/4.0.x/');

# Check another email to cleanup old entries from database
sarun ("-t < data/spam/redirectors/base2.eml", \&patterns_run_cb);
ok_all_patterns();

$dbh = DBI->connect("dbi:SQLite:dbname=$workdir/Redirectors.db","","");
@row = $dbh->selectrow_array("SELECT target_url FROM redir_url_cache WHERE redir_url = 'https://spamassassin.apache.org/full/4.0.x'");
isnt($row[0], 'https://spamassassin.apache.org/full/');

}

if(HAS_SELENIUM) {
tstprefs(q{
dns_query_restriction allow apache.org

clear_url_redirector
url_redirector_selenium spamassassin.apache.org
url_redirector_use_selenium 1

body HAS_REDIR_URL              eval:redir_url()
uri URI_PAGE_LINK		m,^https://spamassassin\.apache\.org/full/4\.0\.x/$,
});
%patterns = (
   q{ 1.0 HAS_REDIR_URL } => '',
   q{ 1.0 URI_PAGE_LINK } => '',
);
sarun ("-t < data/spam/redirectors/base.eml", \&patterns_run_cb);
ok_all_patterns();
}
