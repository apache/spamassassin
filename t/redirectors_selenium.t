#!/usr/bin/perl -T
#

use lib '.'; use lib 't';
use SATest; sa_t_init("redirectors_selenium");

use strict;
use warnings;
use vars qw(%patterns %anti_patterns);
use Test::More;
use IO::Socket::IP;
use JSON::PP ();
use MIME::Base64 ();
use POSIX ();
use Time::HiRes ();

use constant HAS_SELENIUM => eval { require Selenium::Chrome; };

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::Redirectors
");

# tier 1

my @accepted = (
  [ 'http://proxy.example.com:3128',  'http://proxy.example.com:3128',  'http, hostname' ],
  [ 'https://proxy.example.com:3128', 'https://proxy.example.com:3128', 'https' ],
  [ 'socks5://proxy.example.com:1080', 'socks5://proxy.example.com:1080', 'socks5' ],
  [ 'HTTP://proxy.example.com:3128',  'http://proxy.example.com:3128',  'scheme in upper case, stored in lower case' ],
  [ 'Socks5://proxy.example.com:1080', 'socks5://proxy.example.com:1080', 'scheme in mixed case, stored in lower case' ],
  [ 'http://192.0.2.1:3128',          'http://192.0.2.1:3128',          'IPv4 literal' ],
  [ 'http://127.0.0.1:3128',          'http://127.0.0.1:3128',          'loopback proxy' ],
  [ 'http://[::1]:3128',              'http://[::1]:3128',              'bracketed IPv6 literal' ],
  [ 'http://[2001:db8::1]:3128',      'http://[2001:db8::1]:3128',      'bracketed IPv6 literal, global form' ],
  [ 'http://[::ffff:192.0.2.1]:3128', 'http://[::ffff:192.0.2.1]:3128', 'bracketed IPv4-mapped IPv6 literal' ],
  [ 'http://proxy.example.com:1',     'http://proxy.example.com:1',     'lowest port' ],
  [ 'http://proxy.example.com:65535', 'http://proxy.example.com:65535', 'highest port' ],
);
my @rejected = (
  [ 'socks4://proxy.example.com:1080',  'socks4, which resolves hostnames locally' ],
  [ 'ftp://proxy.example.com:21',       'a scheme the browser cannot use as a proxy' ],
  [ 'proxy.example.com:3128',           'no scheme' ],
  [ 'http://proxy.example.com',         'no port' ],
  [ 'http://proxy.example.com:0',       'port 0' ],
  [ 'http://proxy.example.com:65536',   'port above 65535' ],
  [ 'http://proxy.example.com:3128/',   'a path after the port' ],
  [ 'http://::1:3128',                  'unbracketed IPv6 literal' ],
  [ 'http://[1.2.3.4]:3128',            'bracketed IPv4 literal' ],
  [ 'http://[fe80::1%eth0]:3128',       'IPv6 literal with a zone identifier' ],
  [ 'http://[IPv6:::1]:3128',           'IPv6 literal with the SMTP "IPv6:" prefix' ],
  [ 'http://1.2.3:3128',                'IPv4 literal with three parts' ],
  [ 'http://999.999.999.999:3128',      'IPv4 literal out of range' ],
  [ 'http://0.0.0.0:3128',              'unspecified IPv4 address' ],
  [ 'http://[::]:3128',                 'unspecified IPv6 address' ],
  [ 'http://[0:0:0:0:0:0:0:0]:3128',    'unspecified IPv6 address written in full' ],
  [ 'http://[::ffff:0.0.0.0]:3128',     'unspecified address in IPv4-mapped form' ],
  [ 'direct://',                        'bare direct://' ],
  [ 'DIRECT://',                        'bare direct:// in upper case' ],
  [ 'http://a.example:3128;direct://',  'a proxy list ending in direct://' ],
  [ 'http://a.example:3128,http://b.example:3128', 'a comma-separated proxy list' ],
  [ 'http=proxy.example.com:3128',      'the per-scheme map form' ],
  [ 'http://a.example:3128 http://b.example:3128', 'two values separated by whitespace' ],
);

sub parse_proxy {
  my ($line) = @_;
  tstprefs(defined $line ? "url_redirector_selenium_proxy $line\n" : "\n");
  my @lint;
  my $sa = create_saobj({ lint_callback => sub {
    my %a = @_;
    push @lint, $a{msg} if $a{msg} =~ /url_redirector_selenium_proxy/;
  } });
  $sa->init(1);
  my $stored = $sa->{conf}->{url_redirector_selenium_proxy};
  $sa->finish;
  return ($stored, @lint);
}

{
  my ($stored, @lint) = parse_proxy(undef);
  is($stored, '', 'proxy: unset by default');
}
for my $case (@accepted) {
  my ($value, $want, $why) = @$case;
  my ($stored, @lint) = parse_proxy($value);
  is($stored, $want, "proxy accepted ($why): $value");
  is_deeply(\@lint, [], "proxy accepted ($why): no lint error");
}
for my $case (@rejected) {
  my ($value, $why) = @$case;
  my ($stored, @lint) = parse_proxy($value);
  is($stored, '', "proxy rejected ($why): $value leaves the setting unset");
  ok(grep({ /invalid 'url_redirector_selenium_proxy' value/ } @lint),
     "proxy rejected ($why): reported as a lint error");
}

unless (HAS_SELENIUM) {
  SKIP: { skip "Selenium::Remote::Driver required for the remaining sections", 1; }
  done_testing();
  exit;
}

use constant REDIR_URL   => 'http://192.0.2.10/r';
use constant REDIR_URL2  => 'http://192.0.2.10/s';
use constant LANDING_URL => 'http://192.0.2.20/landed';
use constant PROXY       => 'http://192.0.2.30:3128';

my $json = JSON::PP->new->canonical;

# tier 2

my $fake_log = "$workdir/fake_webdriver.log";
my ($fake_pid, $fake_port);

sub start_fake_webdriver {
  my (%opt) = @_;
  stop_fake_webdriver();
  open(my $clr, '>', $fake_log) or die "open $fake_log: $!";
  close $clr;

  my $listen = IO::Socket::IP->new(LocalHost => '127.0.0.1', LocalPort => 0,
                                    Listen => 5, ReuseAddr => 1)
    or die "fake WebDriver: cannot listen: $@";
  $fake_port = $listen->sockport;

  my $pid = fork();
  die "fork: $!" unless defined $pid;
  if ($pid) {
    $fake_pid = $pid;
    $listen->close;
    return;
  }

  my ($sessions, $current, $pending_log) = (0, 'about:blank', []);
  my (%live, %gone, %count, $stalled);
  local $SIG{USR1} = sub {
    $gone{$_} = 1 for keys %live;
    %live = ();
    fake_log_line({ event => 'sessions expired' });
  };
  while (1) {
    my $c = $listen->accept;
    unless ($c) { next if $!{EINTR}; last; }
    my $req = read_request($c);
    next unless $req;
    my ($method, $path) = @$req{qw(method path)};
    my $body = length $req->{body}
      ? eval { $json->decode($req->{body}) } : undef;
    fake_log_line({ method => $method, path => $path, body => $body });
    if ($opt{hang}) { sleep 3600 while 1; }
    if ($opt{stall} && !$stalled) {
      my $kind = $path =~ m{/url$} ? ($method eq 'POST' ? 'navigate' : 'get_url')
               : $path =~ m{/(log|timeouts)$} ? $1 : 'other';
      if ($opt{stall}->($kind, ++$count{$kind}, $body)) {
        $stalled = 1;
        fake_log_line({ event => "stalled $kind" });
        sleep $opt{stall_secs};
      }
    }

    my $sid = $path =~ m{^/session/([^/]+)} ? $1 : undef;
    my ($code, $value) = (200, undef);
    if (defined $sid && $gone{$sid}) {
      ($code, $value) = (404, { error => 'invalid session id',
                                message => 'invalid session id',
                                stacktrace => '' });
    } elsif ($method eq 'GET' && $path eq '/status') {
      $value = { ready => JSON::PP::true, message => 'fake WebDriver' };
    } elsif ($method eq 'POST' && $path eq '/session') {
      if ($opt{refuse_session}) {
        ($code, $value) = (500, { error => 'session not created',
                                  message => 'session not created: fake WebDriver refuses',
                                  stacktrace => '' });
      } else {
        $sessions++;
        $live{"fake-$sessions"} = 1;
        $current = 'about:blank';
        $value = { sessionId => "fake-$sessions",
                   capabilities => { browserName => 'chrome' } };
      }
    } elsif ($path =~ m{^/session/[^/]+/url$}) {
      if ($method eq 'POST') {
        my $to = ref $body eq 'HASH' ? $body->{url} : undef;
        $to = '' unless defined $to;
        $pending_log = $opt{perf_log}{$to} || [];
        $current = exists $opt{landing}{$to} ? $opt{landing}{$to} : $to;
        if ($to =~ m{^http://127\.0\.0\.\d+/\z} && !$opt{probe_loads}) {
          # The plugin's host-list check: a browser that applies the list
          # cannot resolve the address.
          ($code, $value) = (500, { error => 'unknown error',
                                    message => 'unknown error: net::ERR_NAME_NOT_RESOLVED',
                                    stacktrace => '' });
        }
        if (exists $opt{fail}{$to}) {
          ($code, $value) = (500, { error => 'unknown error',
                                    message => "unknown error: $opt{fail}{$to}",
                                    stacktrace => '' });
        }
      } else {
        $value = $current;
      }
    } elsif ($method eq 'POST' && $path =~ m{^/session/[^/]+/log$}) {
      $value = $pending_log;
      $pending_log = [];
    } elsif ($method eq 'POST' && $path =~ m{^/session/[^/]+/timeouts$}) {
      # Accepted and ignored.
    } elsif ($method eq 'DELETE' && $path =~ m{^/session/[^/]+$}) {
      delete $live{$sid};
      $gone{$sid} = 1;
    } else {
      ($code, $value) = (404, { error => 'unknown command',
                                message => "fake WebDriver: no route for $method $path",
                                stacktrace => '' });
    }
    my $out = $json->encode({ value => $value });
    my %reason = (200 => 'OK', 404 => 'Not Found', 500 => 'Internal Server Error');
    print $c "HTTP/1.1 $code $reason{$code}\r\n"
           . "Content-Type: application/json; charset=utf-8\r\n"
           . "Content-Length: " . length($out) . "\r\n"
           . "Connection: close\r\n\r\n" . $out;
    close $c;
  }
  POSIX::_exit(0);
}

sub fake_log_line {
  my ($entry) = @_;
  open(my $lf, '>>', $fake_log) or return;
  print $lf $json->encode($entry), "\n";
  close $lf;
}

# One HTTP request from $c: its method, path and body.
sub read_request {
  my ($c) = @_;
  my $line = <$c>;
  return unless defined $line
             && $line =~ m{^([A-Z]+) (\S+) HTTP/\d\.\d\r?\n\z};
  my ($method, $path) = ($1, $2);
  my $len = 0;
  while (my $h = <$c>) {
    last if $h =~ /^\r?\n\z/;
    $len = $1 if $h =~ /^Content-Length:\s*(\d+)/i;
  }
  my $body = '';
  while (length $body < $len) {
    my $n = read($c, $body, $len - length $body, length $body);
    last unless $n;
  }
  return { method => $method, path => $path, body => $body };
}

sub stop_fake_webdriver {
  return unless $fake_pid;
  kill 'TERM', $fake_pid;
  waitpid($fake_pid, 0);
  undef $fake_pid;
}
END { stop_fake_webdriver(); }

# What the fake has logged since it was started, in order.
sub fake_log_entries {
  my @r;
  open(my $fh, '<', $fake_log) or return @r;
  while (<$fh>) { push @r, $json->decode($_); }
  close $fh;
  return @r;
}

# Make the fake forget every session so far, and wait until it has.
sub expire_fake_sessions {
  kill 'USR1', $fake_pid;
  for (1 .. 50) {
    return 1 if grep { ($_->{event} || '') eq 'sessions expired' } fake_log_entries();
    Time::HiRes::sleep(0.1);
  }
  return 0;
}

# A performance log entry as chromedriver returns one: the DevTools event
# is itself a JSON string.
sub perf_entry {
  my ($method, $params) = @_;
  return { level => 'INFO', timestamp => 0,
           message => $json->encode({ message => { method => $method,
                                                   params => $params },
                                      webview => 'fake' }) };
}

# A stand-in for the user agent of url_redirector and url_redirector_get
# lookups: answers a listed URL with a 301 to where it leads, anything else
# with a 404, and logs each request as "METHOD URL".
{
  package FakeRedirectorUA;
  sub new { my ($class, %leads_to) = @_; return bless { leads_to => \%leads_to, log => [] }, $class; }
  sub agent { }
  sub head { return $_[0]->answer('HEAD', $_[1]); }
  sub get { return $_[0]->answer('GET', $_[1]); }
  sub answer {
    my ($self, $method, $url) = @_;
    push @{ $self->{log} }, "$method $url";
    my $to = $self->{leads_to}{$url};
    return defined $to ? HTTP::Response->new(301, 'Moved Permanently', [ Location => $to ])
                       : HTTP::Response->new(404, 'Not Found');
  }
}

sub msg_text {
  my ($n, @urls) = @_;
  return "From: sender\@example.com\nTo: recipient\@example.com\n"
       . "Subject: selenium $n\nMessage-Id: <selenium-$n\@example.com>\n"
       . "Date: Thu, 24 Sep 2026 12:00:00 +0000\n"
       . "MIME-Version: 1.0\nContent-Type: text/plain\n\n"
       . join('', map { "Visit $_ now.\n" } @urls);
}

sub scan {
  my (%opt) = @_;
  my $messages = $opt{messages} || [ [ REDIR_URL ] ];
  start_fake_webdriver(%{ $opt{fake} || {} });
  tstprefs (join("\n",
    "dns_available no",
    "use_bayes 0",
    ($opt{no_host} ? () : "url_redirector_selenium_host 127.0.0.1"),
    "url_redirector_selenium_port $fake_port",
    ($opt{clear} ? ("clear_url_redirector", "clear_url_redirector_selenium_resource") : ()),
    "url_redirector_selenium 192.0.2.10",
    ($opt{proxy} ? "url_redirector_selenium_proxy $opt{proxy}" : ()),
    @{ $opt{prefs} || [] },
    "uri SELENIUM_LANDED m{^" . quotemeta(LANDING_URL) . "\$}",
  ) . "\n");

  my (@landed, @hits, @recorded, @warnings);
  my $t0 = Time::HiRes::time();
  {
    local $SIG{__WARN__} = sub {
      push @warnings, $_[0] if $_[0] =~ /^Redirectors: /;
    };
    my $sa = create_saobj({ local_tests_only => 0 });
    $sa->init(1);
    my $n = 0;
    for my $urls (@$messages) {
      $opt{between}->($sa) if $n && $opt{between};
      my $mail = $sa->parse(msg_text(++$n, @$urls));
      my $status = Mail::SpamAssassin::PerMsgStatus->new($sa, $mail);
      # The plugin uses a user agent already on the message for its
      # url_redirector and url_redirector_get lookups.
      $status->{redir_lwp_ua} = $opt{lwp} if $opt{lwp};
      $status->check();
      push @landed, ($status->get_names_of_tests_hit =~ /\bSELENIUM_LANDED\b/ ? 1 : 0);
      push @hits, { map { $_ => 1 } split /,/, $status->get_names_of_tests_hit };
      # Where the message's URLs led, read from its URI list: after a
      # processing deadline no rule is evaluated, so a rule cannot show it.
      my $udl = $status->get_uri_detail_list();
      push @recorded, [ sort grep { $udl->{$_}{types}{redirect} } keys %$udl ];
      $status->finish;
      $mail->finish;
    }
    $sa->finish;
  }
  my $secs = Time::HiRes::time() - $t0;
  stop_fake_webdriver();
  my @log = fake_log_entries();
  note("fake WebDriver saw: "
       . join(', ', map { $_->{event} ? "[$_->{event}]" : "$_->{method} $_->{path}" } @log));
  note("plugin warned: $_") for @warnings;
  return (landed => \@landed, hits => \@hits, recorded => \@recorded, warnings => \@warnings,
          log => \@log, secs => $secs);
}

sub requests { return grep { !$_->{event} } @_; }

sub probes {
  return grep { $_->{method} eq 'POST' && $_->{path} =~ m{/url$} && ref $_->{body} eq 'HASH'
                && ($_->{body}{url} || '') =~ m{^http://127\.0\.0\.\d+/\z} } requests(@_);
}

sub new_sessions {
  return grep { $_->{method} eq 'POST' && $_->{path} eq '/session' } requests(@_);
}

sub navigations_to {
  my ($url, @log) = @_;
  return grep { $_->{method} eq 'POST' && $_->{path} =~ m{/url$}
                && ref $_->{body} eq 'HASH' && ($_->{body}{url} || '') eq $url }
         requests(@log);
}

# The W3C capabilities (alwaysMatch) of the first session the plugin asked
# for, which is what Selenium 4 and chromedriver honour.
sub session_caps {
  my ($new) = new_sessions(@_);
  my $caps = $new && eval { $new->{body}{capabilities}{alwaysMatch} };
  return ref $caps eq 'HASH' ? $caps : {};
}

sub chrome_switches {
  my $args = session_caps(@_)->{'goog:chromeOptions'}{args};
  return [ grep { /^--/ } @{ ref $args eq 'ARRAY' ? $args : [] } ];
}

{
  my %r = scan(proxy => PROXY, fake => { landing => { REDIR_URL() => LANDING_URL } });
  my @log = @{ $r{log} };
  ok($r{landed}[0], 'with a proxy: the plugin recorded the URL the fake reported');
  my @switches = @{ chrome_switches(@log) };
  my ($pac) = map { m{^--proxy-pac-url=data:application/x-ns-proxy-autoconfig;base64,(.+)$}
                      ? MIME::Base64::decode_base64($1) : () } @switches;
  ok(defined $pac && $pac =~ /"192\.0\.2\.10": 1/
       && $pac =~ /return "PROXY 192\.0\.2\.30:3128"/ && $pac =~ /return "DIRECT"; \}$/,
     'with a proxy: a PAC script sends the listed host to the proxy and everything else DIRECT');
  is_deeply([ grep { !/^--proxy-pac-url=/ } @switches ],
            [ '--host-resolver-rules=MAP 192.0.2.30:3128 192.0.2.30, MAP * ~NOTFOUND',
              '--webrtc-ip-handling-policy=disable_non_proxied_udp' ],
            "with a proxy: only the proxy's address and port resolve, so DIRECT fails, and the WebRTC switch is passed");
  is(scalar(@switches), 3, 'with a proxy: no other switches');
  is_deeply(session_caps(@log)->{'goog:loggingPrefs'}, { performance => 'ALL' },
            'the session asks for the browser performance log');
  my ($first) = requests(@log);
  is($first && "$first->{method} $first->{path}", 'GET /status',
     'the plugin talks to the server at its root path');
  is_deeply($r{warnings}, [], 'a successful lookup gives no warning');
}

# However the proxy is written, the browser may reach its host only at the
# proxy's port, and a proxy on 127.0.0.N is never the session check's probe.
for my $case (
  [ 'http://proxy.example.com:3128',   'proxy.example.com:3128 proxy.example.com', 'a host name' ],
  [ 'http://[2001:DB8:0:0::1]:3128',   '[2001:db8::1]:3128 [2001:db8::1]',         'an IPv6 literal' ],
  [ 'http://[::ffff:192.0.2.30]:3128', '[::ffff:c000:21e]:3128 [::ffff:c000:21e]', 'an IPv4-mapped literal' ],
  [ 'http://127.0.0.2:3128',           '127.0.0.2:3128 127.0.0.2',                 'a loopback address' ],
) {
  my ($proxy, $map, $why) = @$case;
  my %r = scan(proxy => $proxy);
  my @log = @{ $r{log} };
  my ($rules) = grep { /^--host-resolver-rules=/ } @{ chrome_switches(@log) };
  is($rules, "--host-resolver-rules=MAP $map, MAP * ~NOTFOUND",
     "proxy as $why: only its address and port resolve, written as Chrome writes them");
  if ($proxy =~ m{//127\.0\.0\.2:}) {
    my ($probe) = probes(@log);
    is($probe && $probe->{body}{url}, 'http://127.0.0.3/',
       "proxy as $why: the session check probes another loopback address");
  }
}

{
  my %r = scan(clear => 1, fake => { landing => { REDIR_URL() => LANDING_URL } });
  ok($r{landed}[0], 'without a proxy: the plugin recorded the URL the fake reported');
  is_deeply(chrome_switches(@{ $r{log} }),
            [ '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 192.0.2.10',
              '--webrtc-ip-handling-policy=disable_non_proxied_udp' ],
            'without a proxy: only the listed host resolves, and the WebRTC switch is passed');
}

{
  my %r = scan(clear => 1,
               prefs => [ 'url_redirector_selenium Bare.Example path.example/r/ .sub.example',
                          'url_redirector lwp.example' ],
               fake => { landing => { REDIR_URL() => LANDING_URL } });
  my ($rules) = map { /^--host-resolver-rules=(.*)$/ ? $1 : () }
                    @{ chrome_switches(@{ $r{log} }) };
  my @parts = split /, /, ($rules // '');
  is(shift(@parts), 'MAP * ~NOTFOUND', 'host list: every other host fails to resolve');
  is_deeply([ sort @parts ],
            [ sort map { "EXCLUDE $_" }
                qw(192.0.2.10 bare.example www.bare.example path.example
                   www.path.example *.sub.example) ],
            'host list: bare entries with their www. form, a leading-dot entry as its subdomains, no paths, no LWP-only host');
}

# url_redirector_selenium_resource hosts join the browser's host list as
# exact names, and are not looked up.
{
  my %r = scan(clear => 1,
               prefs => [ 'url_redirector_selenium_resource cdn.example Other.Example' ],
               fake => { landing => { REDIR_URL() => LANDING_URL } });
  is_deeply(chrome_switches(@{ $r{log} }),
            [ '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 192.0.2.10, EXCLUDE cdn.example, EXCLUDE other.example',
              '--webrtc-ip-handling-policy=disable_non_proxied_udp' ],
            'resource hosts without a proxy: each one resolves, without its www. form');
}

{
  my %r = scan(clear => 1, proxy => PROXY,
               prefs => [ 'url_redirector_selenium_resource cdn.example' ],
               fake => { landing => { REDIR_URL() => LANDING_URL } });
  my ($pac) = map { m{^--proxy-pac-url=data:application/x-ns-proxy-autoconfig;base64,(.+)$}
                      ? MIME::Base64::decode_base64($1) : () } @{ chrome_switches(@{ $r{log} }) };
  ok(defined $pac && $pac =~ /var exact = \{"192\.0\.2\.10": 1, "cdn\.example": 1\};/,
     'resource hosts with a proxy: the PAC sends them to the proxy as exact names');
}

{
  my %r = scan(prefs => [ 'url_redirector_selenium_resource cdn.example',
                          'body SELENIUM_REDIR eval:redir_url()' ],
               messages => [ [ 'http://cdn.example/lib.js' ] ]);
  is(scalar requests(@{ $r{log} }), 0,
     'a URL on a resource host: the plugin contacts no server');
  ok(!$r{hits}[0]{SELENIUM_REDIR}, 'a URL on a resource host: redir_url() does not fire');
}

{
  my %r = scan(no_host => 1, messages => [ [ REDIR_URL ], [ REDIR_URL ] ],
               prefs => [ 'body SELENIUM_REDIR eval:redir_url()' ]);
  is(scalar requests(@{ $r{log} }), 0,
     'with no url_redirector_selenium_host the plugin contacts no server');
  ok($r{hits}[0]{SELENIUM_REDIR} && $r{hits}[1]{SELENIUM_REDIR},
     'with no host: redir_url() still fires for a listed host');
  is_deeply($r{warnings}, [], 'with no host: no warning');
}

{
  my %r = scan(fake => { refuse_session => 1 },
               messages => [ [ REDIR_URL ], [ REDIR_URL ] ]);
  ok(!$r{landed}[0] && !$r{landed}[1], 'a refused session records nothing');
  is(scalar @{ $r{warnings} }, 1, 'a refused session: one warning for two messages');
  like($r{warnings}[0] || '', qr/a Selenium session could not be created at 127\.0\.0\.1:$fake_port/,
       'a refused session: the warning names the server');
}

{
  my %r = scan(fake => { landing => { REDIR_URL() => LANDING_URL } },
               messages => [ [ REDIR_URL ], [ REDIR_URL ] ]);
  my @seq = map { "$_->{method} $_->{path}" } requests(@{ $r{log} });
  is_deeply($r{landed}, [ 1, 1 ], 'per message: both messages recorded the redirect');
  is(scalar(new_sessions(@{ $r{log} })), 2, 'per message: a session for each message');
  my ($del1) = grep { $seq[$_] eq 'DELETE /session/fake-1' } 0 .. $#seq;
  my ($new2) = grep { $seq[$_] eq 'POST /session' } reverse 0 .. $#seq;
  ok(defined $del1 && defined $new2 && $del1 < $new2,
     "per message: the first message's session is quit before the second's is created");
  is($seq[-1], 'DELETE /session/fake-2', "per message: the second message's session is quit at its end");
  is(scalar(probes(@{ $r{log} })), 2, 'per message: each new session is checked for the host list');
}

{
  my %r = scan(fake => { landing => { REDIR_URL() => LANDING_URL } },
               prefs => [ 'url_redirector_selenium_reuse_session 1' ],
               messages => [ [ REDIR_URL ], [ REDIR_URL ] ]);
  my @reqs = requests(@{ $r{log} });
  is_deeply($r{landed}, [ 1, 1 ], 'reuse: both messages recorded the redirect');
  is(scalar(new_sessions(@reqs)), 1, 'reuse: one session serves both messages');
  ok(!grep({ $_->{method} eq 'DELETE' } @reqs), 'reuse: the session is not quit');
  is(scalar(probes(@reqs)), 1, 'reuse: the kept session is not checked again');
}

{
  my %r = scan(fake => { landing => { REDIR_URL() => LANDING_URL }, probe_loads => 1 },
               messages => [ [ REDIR_URL ], [ REDIR_URL ] ]);
  my @reqs = requests(@{ $r{log} });
  ok(!$r{landed}[0] && !$r{landed}[1], 'host list not applied: nothing recorded');
  ok(!navigations_to(REDIR_URL, @{ $r{log} }), 'host list not applied: no lookup is made');
  is(scalar(grep { $_->{method} eq 'DELETE' } @reqs), 2, 'host list not applied: each session is quit');
  is(scalar @{ $r{warnings} }, 1, 'host list not applied: one warning for two messages');
  like($r{warnings}[0] || '', qr/did not refuse an address outside url_redirector_selenium/,
       'host list not applied: the warning says so');
}

{
  my %r = scan(fake => { landing => { REDIR_URL() => LANDING_URL } },
               prefs => [ 'url_redirector_selenium_reuse_session 1' ],
               messages => [ [ REDIR_URL ], [ REDIR_URL ] ],
               between => sub {
                 ok(expire_fake_sessions(), 'reuse: the fake forgot the kept session');
               });
  my @log = @{ $r{log} };
  my @seq = map { $_->{event} ? "[$_->{event}]" : "$_->{method} $_->{path}" } @log;
  my ($expired) = grep { $seq[$_] eq '[sessions expired]' } 0 .. $#seq;
  is_deeply($r{landed}, [ 1, 1 ], 'reuse, session gone: both messages recorded the redirect');
  is(scalar(new_sessions(@log)), 2, 'reuse, session gone: a new session replaces it');
  ok(defined $expired
     && grep({ $_ eq 'DELETE /session/fake-1' } @seq[$expired .. $#seq]),
     'reuse, session gone: the plugin quits the session that no longer answers');
  is_deeply($r{warnings}, [], 'reuse, session gone: no warning');
}

{
  # A kept session is used again only by a message whose configuration
  # gives the browser the same settings. Here the host list changes
  # between the two messages.
  my %r = scan(prefs => [ 'url_redirector_selenium_reuse_session 1' ],
               fake => { landing => { REDIR_URL() => LANDING_URL } },
               messages => [ [ REDIR_URL ], [ REDIR_URL ] ],
               between => sub {
                 my ($sa) = @_;
                 $sa->{conf}->parse_rules("url_redirector_selenium other.example\n");
               });
  my @seq = map { "$_->{method} $_->{path}" } requests(@{ $r{log} });
  my ($del1) = grep { $seq[$_] eq 'DELETE /session/fake-1' } 0 .. $#seq;
  my (undef, $new2) = grep { $seq[$_] eq 'POST /session' } 0 .. $#seq;
  is_deeply($r{landed}, [ 1, 1 ], 'reuse, other settings: both messages recorded the redirect');
  ok(defined $del1 && defined $new2 && $del1 < $new2,
     'reuse, other settings: the kept session is quit and a new one created');
  is_deeply($r{warnings}, [], 'reuse, other settings: no warning');
}

{
  my %fail = (REDIR_URL() => 'net::ERR_PROXY_CONNECTION_FAILED',
              REDIR_URL2() => 'net::ERR_PROXY_CONNECTION_FAILED');
  my %r = scan(proxy => PROXY, fake => { fail => \%fail },
               messages => [ [ REDIR_URL, REDIR_URL2 ], [ REDIR_URL, REDIR_URL2 ] ]);
  ok(navigations_to(REDIR_URL, @{ $r{log} }) && !$r{landed}[0] && !$r{landed}[1],
     'proxy unreachable: the navigations failed and nothing was recorded');
  is(scalar(navigations_to(REDIR_URL, @{ $r{log} })), 2,
     'proxy unreachable: each lookup is tried once per message, not retried');
  is(scalar @{ $r{warnings} }, 1, 'proxy unreachable: one warning for four failed lookups');
  like($r{warnings}[0] || '',
       qr/Selenium navigation failed with url_redirector_selenium_proxy configured; the configured proxy may be unreachable; the lookup was abandoned, not retried direct/,
       'proxy unreachable: the warning says the proxy may be unreachable');
}

{
  my %r = scan(proxy => PROXY,
               fake => { fail => { REDIR_URL() => 'net::ERR_CONNECTION_REFUSED' } });
  is(scalar @{ $r{warnings} }, 1, 'target refused, with a proxy: one warning');
  like($r{warnings}[0] || '', qr/Selenium navigation failed with url_redirector_selenium_proxy configured; the lookup was abandoned/,
       'target refused, with a proxy: the warning reports the failed navigation');
  unlike($r{warnings}[0] || '', qr/proxy may be unreachable/,
         'target refused, with a proxy: the warning does not blame the proxy');
}

{
  my %r = scan(fake => { fail => { REDIR_URL() => 'net::ERR_CONNECTION_REFUSED' } });
  ok(navigations_to(REDIR_URL, @{ $r{log} }) && !$r{landed}[0],
     'target refused, no proxy: the navigation failed and nothing was recorded');
  is_deeply($r{warnings}, [], 'target refused, no proxy: no warning');
}

{
  my $led = [
    perf_entry('Network.requestWillBeSent',
               { requestId => 'nav1', type => 'Document',
                 request => { url => REDIR_URL } }),
    perf_entry('Network.requestWillBeSent',
               { requestId => 'nav1', type => 'Document',
                 redirectResponse => { status => 302 },
                 request => { url => LANDING_URL } }),
  ];
  for my $proxy (PROXY, undef) {
    my $with = $proxy ? 'with a proxy' : 'no proxy';
    my %r = scan(($proxy ? (proxy => $proxy) : ()),
                 fake => { fail => { REDIR_URL() => 'net::ERR_NAME_NOT_RESOLVED' },
                           perf_log => { REDIR_URL() => $led } });
    ok($r{landed}[0], "led to an unlisted host, $with: where it led is recorded");
    is_deeply($r{warnings}, [], "led to an unlisted host, $with: no warning");
  }
}

{
  my $chain = sub {
    my ($refused) = @_;
    my @hops = ('http://192.0.2.20/hop1', 'http://192.0.2.20/hop2', LANDING_URL);
    return [
      perf_entry('Network.requestWillBeSent',
                 { requestId => 'nav1', type => 'Document',
                   request => { url => REDIR_URL } }),
      (map { perf_entry('Network.requestWillBeSent',
                        { requestId => 'nav1', type => 'Document',
                          redirectResponse => { status => 302 },
                          request => { url => $_ } }) } @hops),
      ($refused ? perf_entry('Network.loadingFailed',
                             { requestId => 'nav1',
                               errorText => 'net::ERR_TOO_MANY_REDIRECTS' }) : ()),
    ];
  };
  my %done = scan(fake => { landing => { REDIR_URL() => LANDING_URL },
                            perf_log => { REDIR_URL() => $chain->(0) } });
  ok($done{landed}[0], 'a redirect chain the browser finished is recorded');
  my %refused = scan(fake => { landing => { REDIR_URL() => LANDING_URL },
                               perf_log => { REDIR_URL() => $chain->(1) } });
  ok(navigations_to(REDIR_URL, @{ $refused{log} }) && !$refused{landed}[0],
     'a chain the browser stopped on its redirect limit is not recorded as a redirect');
}

# A chain that changes method: a url_redirector_selenium host leading to a
# url_redirector host, and the other way round. Each host is looked up with
# its own method.
{
  require HTTP::Response;
  my $plain = 'http://192.0.2.40/p';
  my @prefs = ("url_redirector 192.0.2.40");
  my %to_plain = (
    'an HTTP redirect' => {
      fail => { REDIR_URL() => 'net::ERR_NAME_NOT_RESOLVED' },
      perf_log => { REDIR_URL() => [
        perf_entry('Network.requestWillBeSent',
                   { requestId => 'nav1', type => 'Document',
                     request => { url => REDIR_URL } }),
        perf_entry('Network.requestWillBeSent',
                   { requestId => 'nav1', type => 'Document',
                     redirectResponse => { status => 302 },
                     request => { url => $plain } }),
      ] } },
    'a script' => { landing => { REDIR_URL() => $plain } },
  );
  for my $how (sort keys %to_plain) {
    my $ua = FakeRedirectorUA->new($plain => LANDING_URL);
    my %r = scan(fake => $to_plain{$how}, lwp => $ua, prefs => \@prefs);
    my $what = "a url_redirector_selenium host leading to a url_redirector host by $how";
    is_deeply($ua->{log}, [ "HEAD $plain" ], "$what: that host is looked up with HEAD");
    ok(!navigations_to($plain, @{ $r{log} }), "$what: the plugin does not send the browser there");
    is_deeply($r{recorded}[0], [ sort { $a cmp $b } LANDING_URL, $plain ], "$what: both destinations are recorded");
  }

  my $ua = FakeRedirectorUA->new($plain => REDIR_URL);
  my %r = scan(fake => { landing => { REDIR_URL() => LANDING_URL } }, lwp => $ua,
               messages => [ [ $plain ] ], prefs => \@prefs);
  my $what = 'a url_redirector host leading to a url_redirector_selenium host';
  is_deeply($ua->{log}, [ "HEAD $plain" ], "$what: the first host is looked up with HEAD");
  ok(navigations_to(REDIR_URL, @{ $r{log} }), "$what: the browser looks up the second");
  is_deeply($r{recorded}[0], [ sort { $a cmp $b } LANDING_URL, REDIR_URL ], "$what: both destinations are recorded");
}

# Chrome fetches an http URL on the default port as https first. The https
# URL is looked up in turn, and only a real redirect sets redir_url_301.
{
  my $up = 'http://192.0.2.10/u';
  (my $up_https = $up) =~ s/^http:/https:/;
  my %r = scan(fake => { landing => { $up => $up_https, REDIR_URL() => LANDING_URL } },
               messages => [ [ $up ], [ REDIR_URL ] ],
               prefs => [ "body SELENIUM_301 eval:redir_url_code('301')",
                          "body SELENIUM_200 eval:redir_url_code('200')" ]);
  my $what = 'a browser that fetches an http URL as https';
  ok(navigations_to($up_https, @{ $r{log} }), "$what: the https URL is looked up");
  ok(!$r{hits}[0]{SELENIUM_301}, "$what: redir_url_301 is not set");
  ok($r{hits}[0]{SELENIUM_200}, "$what: the URL is recorded as not redirecting");
  is_deeply($r{recorded}[0], [], "$what: no destination is recorded");
  ok($r{hits}[1]{SELENIUM_301}, 'a redirect to another host sets redir_url_301');
}

# url_redirector_timeout bounds each Selenium navigation.
for my $case ([ 'by default', [], 5000 ],
              [ 'with url_redirector_timeout 3', [ 'url_redirector_timeout 3' ], 3000 ]) {
  my ($why, $prefs, $ms) = @$case;
  my %r = scan(prefs => $prefs);
  my @set = map { $_->{body} }
            grep { $_->{method} eq 'POST' && $_->{path} =~ m{/timeouts$} } requests(@{ $r{log} });
  is_deeply(\@set, [ { pageLoad => $ms } ], "$why the session's page-load timeout is $ms ms");
}


SKIP: {
  skip "long tests disabled", 3 unless conf_bool('run_long_tests');
  my $time_limit = 3;
  my %r = scan(fake => { hang => 1 }, prefs => [ "time_limit $time_limit" ]);
  require Mail::SpamAssassin::Plugin::Redirectors;
  my $create = Mail::SpamAssassin::Plugin::Redirectors->can('SELENIUM_CREATE_TIMEOUT');
  my $bound = $time_limit + ($create ? $create->() : 0) + 5;
  note(sprintf("the scan took %.1f s, bound %d s%s", $r{secs}, $bound,
               $create ? '' : ' (the plugin has no SELENIUM_CREATE_TIMEOUT)'));
  ok($create && $r{secs} < $bound,
     'a server that never answers holds the scan up no more than the session-creation bound past the deadline');
  ok(!$r{landed}[0], 'a server that never answers: nothing recorded');
  is_deeply($r{warnings}, [],
            'a server that never answers past the deadline: reported as the deadline, not a warning');
}
# The processing deadline arriving while a WebDriver call has not
# answered: no further URL is looked up, nothing is recorded and nothing
# is warned about. The plugin looks up a message's URLs in no fixed order,
# so each case holds a call made before the first lookup (0 lookups
# started) or during it (1).
{
  my $time_limit = 3;
  my %land = (landing => { REDIR_URL() => LANDING_URL, REDIR_URL2() => LANDING_URL });
  my %fail = (fail => { REDIR_URL() => 'net::ERR_CONNECTION_REFUSED',
                        REDIR_URL2() => 'net::ERR_CONNECTION_REFUSED' });
  my $nav_to = sub { my ($re) = @_;
    return sub { $_[0] eq 'navigate' && ref $_[2] eq 'HASH' && ($_[2]{url} || '') =~ $re } };
  my $either = join('|', map { quotemeta } REDIR_URL, REDIR_URL2);
  my @cases = (
    [ 'setting the session timeouts', 0, { %land, stall => sub { $_[0] eq 'timeouts' } } ],
    [ 'the host-list check', 0, { %land, stall => $nav_to->(qr{^http://127\.0\.0\.\d+/\z}) } ],
    [ 'the browser reset', 0, { %land, stall => $nav_to->(qr{^about:blank\z}) } ],
    [ 'the log read after the reset', 0, { %land, stall => sub { $_[0] eq 'log' && $_[1] == 1 } } ],
    [ 'the navigation', 1, { %land, stall => $nav_to->(qr{^(?:$either)\z}) } ],
    [ 'the redirect summary', 1, { %land, stall => sub { $_[0] eq 'log' && $_[1] == 2 } } ],
    [ 'reading the current URL', 1, { %land, stall => sub { $_[0] eq 'get_url' } } ],
    [ 'the summary of a failed navigation', 1,
      { %fail, stall => sub { $_[0] eq 'log' && $_[1] == 2 } } ],
    [ 'waiting for the page to navigate', 1, {} ],
  );

  SKIP: {
    skip "long tests disabled", 3 * @cases + 4 unless conf_bool('run_long_tests');
    my @prefs = ("time_limit $time_limit", 'url_redirector_timeout 10');

    for my $case (@cases) {
      my ($where, $started, $fake) = @$case;
      my %r = scan(fake => { %$fake, stall_secs => $time_limit + 2 },
                   messages => [ [ REDIR_URL, REDIR_URL2 ] ], prefs => \@prefs);
      note(sprintf("deadline during %s: the scan took %.1f s", $where, $r{secs}));
      my $looked_up = grep { navigations_to($_, @{ $r{log} }) } REDIR_URL, REDIR_URL2;
      is($looked_up, $started, "deadline during $where: no further URL is looked up");
      is_deeply($r{recorded}[0], [], "deadline during $where: nothing is recorded");
      is_deeply($r{warnings}, [], "deadline during $where: no warning");
    }

    my %kept = scan(fake => { %land, stall_secs => $time_limit + 2,
                              stall => sub { $_[0] eq 'log' && $_[1] == 3 } },
                    messages => [ [ REDIR_URL ], [ REDIR_URL2 ] ],
                    prefs => [ @prefs, 'url_redirector_selenium_reuse_session 1' ]);
    ok(!navigations_to(REDIR_URL2, @{ $kept{log} }) && !@{ $kept{recorded}[1] },
       'deadline during the check of a kept session: nothing is looked up or recorded');
    is_deeply($kept{warnings}, [], 'deadline during the check of a kept session: no warning');

    my %cut = scan(fake => { %land, stall_secs => $time_limit + 2,
                             stall => $nav_to->(qr{^\Q@{[ REDIR_URL ]}\E\z}) },
                   messages => [ [ REDIR_URL ], [ REDIR_URL2 ] ],
                   prefs => [ @prefs, 'url_redirector_selenium_reuse_session 1' ]);
    is(scalar(new_sessions(@{ $cut{log} })), 2,
       'reuse: a message cut short by the deadline does not pass its session on');
    is_deeply($cut{recorded}[1], [ LANDING_URL ],
              'reuse: the next message is looked up in a new session');
  }
}


###
### A real WebDriver server, over the network
###
# tier 3

SKIP: {
  skip "Net tests disabled", 2 unless conf_bool('run_net_tests');
  my $sock = IO::Socket::IP->new(PeerHost => '127.0.0.1', PeerPort => 4444,
                                 Timeout => 2);
  skip "no WebDriver server on 127.0.0.1:4444", 2 unless $sock;
  $sock->close;

  tstprefs(q{
dns_query_restriction allow apache.org

clear_url_redirector
url_redirector_selenium spamassassin.apache.org
url_redirector_selenium_host 127.0.0.1
url_redirector_selenium_port 4444

body HAS_REDIR_URL              eval:redir_url()
uri URI_PAGE_LINK		m,^https://spamassassin\.apache\.org/full/4\.0\.x/$,
});
  %patterns = (
     q{ 1.0 HAS_REDIR_URL } => '',
     q{ 1.0 URI_PAGE_LINK } => '',
  );
  %anti_patterns = ();
  sarun ("-t < data/spam/redirectors/base.eml", \&patterns_run_cb);
  ok_all_patterns();
}

done_testing();
