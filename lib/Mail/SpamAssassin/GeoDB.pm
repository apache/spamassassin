# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

=head1 NAME

Mail::SpamAssassin::GeoDB - unified interface for geoip modules

Plugins need to signal SA main package the modules they want loaded

package Mail::SpamAssassin::Plugin::MyPlugin;
sub new {
  ...
  $self-E<gt>{main}-E<gt>{geodb_wanted}-E<gt>{country} = 1;
  $self-E<gt>{main}-E<gt>{geodb_wanted}-E<gt>{isp} = 1;
)

(internal stuff still subject to change)

=cut

package Mail::SpamAssassin::GeoDB;

use strict;
use warnings;
# use bytes;
use re 'taint';

use Socket;
use version 0.77;

our @ISA = qw();

use Mail::SpamAssassin::Constants qw(:ip);
use Mail::SpamAssassin::Logger;

my @geoip_default_path = qw(
  /usr/local/share/GeoIP
  /usr/share/GeoIP
  /var/lib/GeoIP
  /opt/share/GeoIP
);

# load order (city contains country, isp contains asn)
my @geoip_types = qw( city country isp asn );

# v6 is not needed, automatically tries *v6.dat also
my %geoip_default_files = (
  'city' => ['GeoIPCity.dat','GeoLiteCity.dat'],
  'country' => ['GeoIP.dat'],
  'isp' => ['GeoIPISP.dat'],
  'asn' => ['GeoIPASNum.dat'],
);

my %geoip2_default_files = (
  'city' => ['GeoIP2-City.mmdb','GeoLite2-City.mmdb',
             'dbip-city.mmdb','dbip-city-lite.mmdb'],
  'country' => ['GeoIP2-Country.mmdb','GeoLite2-Country.mmdb',
                'dbip-country.mmdb','dbip-country-lite.mmdb'],
  'isp' => ['GeoIP2-ISP.mmdb','GeoLite2-ISP.mmdb'],
  'asn' => ['GeoIP2-ASN.mmdb','GeoLite2-ASN.mmdb'],
);

my %country_to_continent = (
'AP'=>'AS','EU'=>'EU','AD'=>'EU','AE'=>'AS','AF'=>'AS','AG'=>'NA',
'AI'=>'NA','AL'=>'EU','AM'=>'AS','CW'=>'NA','AO'=>'AF','AQ'=>'AN',
'AR'=>'SA','AS'=>'OC','AT'=>'EU','AU'=>'OC','AW'=>'NA','AZ'=>'AS',
'BA'=>'EU','BB'=>'NA','BD'=>'AS','BE'=>'EU','BF'=>'AF','BG'=>'EU',
'BH'=>'AS','BI'=>'AF','BJ'=>'AF','BM'=>'NA','BN'=>'AS','BO'=>'SA',
'BR'=>'SA','BS'=>'NA','BT'=>'AS','BV'=>'AN','BW'=>'AF','BY'=>'EU',
'BZ'=>'NA','CA'=>'NA','CC'=>'AS','CD'=>'AF','CF'=>'AF','CG'=>'AF',
'CH'=>'EU','CI'=>'AF','CK'=>'OC','CL'=>'SA','CM'=>'AF','CN'=>'AS',
'CO'=>'SA','CR'=>'NA','CU'=>'NA','CV'=>'AF','CX'=>'AS','CY'=>'AS',
'CZ'=>'EU','DE'=>'EU','DJ'=>'AF','DK'=>'EU','DM'=>'NA','DO'=>'NA',
'DZ'=>'AF','EC'=>'SA','EE'=>'EU','EG'=>'AF','EH'=>'AF','ER'=>'AF',
'ES'=>'EU','ET'=>'AF','FI'=>'EU','FJ'=>'OC','FK'=>'SA','FM'=>'OC',
'FO'=>'EU','FR'=>'EU','FX'=>'EU','GA'=>'AF','GB'=>'EU','GD'=>'NA',
'GE'=>'AS','GF'=>'SA','GH'=>'AF','GI'=>'EU','GL'=>'NA','GM'=>'AF',
'GN'=>'AF','GP'=>'NA','GQ'=>'AF','GR'=>'EU','GS'=>'AN','GT'=>'NA',
'GU'=>'OC','GW'=>'AF','GY'=>'SA','HK'=>'AS','HM'=>'AN','HN'=>'NA',
'HR'=>'EU','HT'=>'NA','HU'=>'EU','ID'=>'AS','IE'=>'EU','IL'=>'AS',
'IN'=>'AS','IO'=>'AS','IQ'=>'AS','IR'=>'AS','IS'=>'EU','IT'=>'EU',
'JM'=>'NA','JO'=>'AS','JP'=>'AS','KE'=>'AF','KG'=>'AS','KH'=>'AS',
'KI'=>'OC','KM'=>'AF','KN'=>'NA','KP'=>'AS','KR'=>'AS','KW'=>'AS',
'KY'=>'NA','KZ'=>'AS','LA'=>'AS','LB'=>'AS','LC'=>'NA','LI'=>'EU',
'LK'=>'AS','LR'=>'AF','LS'=>'AF','LT'=>'EU','LU'=>'EU','LV'=>'EU',
'LY'=>'AF','MA'=>'AF','MC'=>'EU','MD'=>'EU','MG'=>'AF','MH'=>'OC',
'MK'=>'EU','ML'=>'AF','MM'=>'AS','MN'=>'AS','MO'=>'AS','MP'=>'OC',
'MQ'=>'NA','MR'=>'AF','MS'=>'NA','MT'=>'EU','MU'=>'AF','MV'=>'AS',
'MW'=>'AF','MX'=>'NA','MY'=>'AS','MZ'=>'AF','NA'=>'AF','NC'=>'OC',
'NE'=>'AF','NF'=>'OC','NG'=>'AF','NI'=>'NA','NL'=>'EU','NO'=>'EU',
'NP'=>'AS','NR'=>'OC','NU'=>'OC','NZ'=>'OC','OM'=>'AS','PA'=>'NA',
'PE'=>'SA','PF'=>'OC','PG'=>'OC','PH'=>'AS','PK'=>'AS','PL'=>'EU',
'PM'=>'NA','PN'=>'OC','PR'=>'NA','PS'=>'AS','PT'=>'EU','PW'=>'OC',
'PY'=>'SA','QA'=>'AS','RE'=>'AF','RO'=>'EU','RU'=>'EU','RW'=>'AF',
'SA'=>'AS','SB'=>'OC','SC'=>'AF','SD'=>'AF','SE'=>'EU','SG'=>'AS',
'SH'=>'AF','SI'=>'EU','SJ'=>'EU','SK'=>'EU','SL'=>'AF','SM'=>'EU',
'SN'=>'AF','SO'=>'AF','SR'=>'SA','ST'=>'AF','SV'=>'NA','SY'=>'AS',
'SZ'=>'AF','TC'=>'NA','TD'=>'AF','TF'=>'AN','TG'=>'AF','TH'=>'AS',
'TJ'=>'AS','TK'=>'OC','TM'=>'AS','TN'=>'AF','TO'=>'OC','TL'=>'AS',
'TR'=>'EU','TT'=>'NA','TV'=>'OC','TW'=>'AS','TZ'=>'AF','UA'=>'EU',
'UG'=>'AF','UM'=>'OC','US'=>'NA','UY'=>'SA','UZ'=>'AS','VA'=>'EU',
'VC'=>'NA','VE'=>'SA','VG'=>'NA','VI'=>'NA','VN'=>'AS','VU'=>'OC',
'WF'=>'OC','WS'=>'OC','YE'=>'AS','YT'=>'AF','RS'=>'EU','ZA'=>'AF',
'ZM'=>'AF','ME'=>'EU','ZW'=>'AF','AX'=>'EU','GG'=>'EU','IM'=>'EU',
'JE'=>'EU','BL'=>'NA','MF'=>'NA','BQ'=>'NA','SS'=>'AF','**'=>'**',
);

sub new {
  my ($class, $conf) = @_;
  $class = ref($class) || $class;

  my $self = {};
  bless ($self, $class);

  $self->{cache} = ();
  $self->init_database($conf || {});
  $self;
}

sub init_database {
  my ($self, $opts) = @_;

  # Try city too if country wanted
  $opts->{wanted}->{city} = 1 if $opts->{wanted}->{country};
  # Try isp too if asn wanted
  $opts->{wanted}->{isp} = 1 if $opts->{wanted}->{asn};

  my $geodb_opts = {
    'module' => $opts->{conf}->{module} || undef,
    'dbs' => $opts->{conf}->{options} || undef,
    'wanted' => $opts->{wanted} || undef,
    'search_path' => defined $opts->{conf}->{geodb_search_path} ?
      $opts->{conf}->{geodb_search_path} : \@geoip_default_path,
  };

  my ($db, $dbapi, $loaded);

  ## GeoIP2
  if (!$db && (!$geodb_opts->{module} || $geodb_opts->{module} eq 'geoip2')) {
    ($db, $dbapi) = $self->load_geoip2($geodb_opts);
    $loaded = 'geoip2' if $db;
  }

  ## Geo::IP
  if (!$db && (!$geodb_opts->{module} || $geodb_opts->{module} eq 'geoip')) {
    ($db, $dbapi) = $self->load_geoip($geodb_opts);
    $loaded = 'geoip' if $db;
  }

  ## IP::Country::DB_File
  if (!$db && $geodb_opts->{module} && $geodb_opts->{module} eq 'dbfile') {
    # Only try if geodb_module and path to ipcc.db specified
    ($db, $dbapi) = $self->load_dbfile($geodb_opts);
    $loaded = 'dbfile' if $db;
  }

  ## IP::Country::Fast
  if (!$db && (!$geodb_opts->{module} || $geodb_opts->{module} eq 'fast')) {
    ($db, $dbapi) = $self->load_fast($geodb_opts);
    $loaded = 'fast' if $db;
  }

  if (!$db) {
    dbg("geodb: No supported database could be loaded");
    die("No supported GeoDB database could be loaded\n");
  }

  # country can be aliased to city
  if (!$dbapi->{country} && $dbapi->{city}) {
    $dbapi->{country} = $dbapi->{city};
  }
  if (!$dbapi->{country_v6} && $dbapi->{city_v6}) {
    $dbapi->{country_v6} = $dbapi->{city_v6}
  }
  # GeoIP2 asn can be aliased to isp
  if ($loaded eq 'geoip2') {
    if (!$dbapi->{asn} && $dbapi->{isp}) {
      $dbapi->{asn} = $dbapi->{isp};
    }
    if (!$dbapi->{asn_v6} && $dbapi->{isp_v6}) {
      $dbapi->{asn_v6} = $dbapi->{isp_v6}
    }
  }

  $self->{db} = $db;
  $self->{dbapi} = $dbapi;

  foreach (@{$self->get_dbinfo()}) {
    dbg("geodb: database info: ".$_);
  }
  #dbg("geodb: apis available: ".join(', ', sort keys %{$self->{dbapi}}));

  return 1;
}

sub load_geoip2 {
  my ($self, $geodb_opts) = @_;
  my ($db, $dbapi, $ok);

  # Warn about fatal errors if this module was specifically requested
  my $errwarn = ($geodb_opts->{module}||'') eq 'geoip2';

  eval {
    require MaxMind::DB::Reader;
  } or do {
    my $err = $@;
    $err =~ s/ at .*//s;
    $err = "geodb: MaxMind::DB::Reader (GeoIP2) module load failed: $err";
    $errwarn ? warn("$err\n") : dbg($err);
    return (undef, undef);
  };

  my %path;
  foreach my $dbtype (@geoip_types) {
    # skip country if city already loaded
    next if $dbtype eq 'country' && $db->{city};
    # skip asn if isp already loaded
    next if $dbtype eq 'asn' && $db->{isp};
    # skip if not needed
    next if $geodb_opts->{wanted} && !$geodb_opts->{wanted}->{$dbtype};
    # only autosearch if no absolute path given
    if (!defined $geodb_opts->{dbs}->{$dbtype}) {
      # Try some default locations
      PATHS_GEOIP2: foreach my $p (@{$geodb_opts->{search_path}}) {
        foreach my $f (@{$geoip2_default_files{$dbtype}}) {
          if (-f "$p/$f") {
            $path{$dbtype} = "$p/$f";
            dbg("geodb: GeoIP2: search found $dbtype $p/$f");
            last PATHS_GEOIP2;
          }
        }
      }
    } else {
      if (!-f $geodb_opts->{dbs}->{$dbtype}) {
        dbg("geodb: GeoIP2: $dbtype database requested, but not found: ".
          $geodb_opts->{dbs}->{$dbtype});
        next;
      }
      $path{$dbtype} = $geodb_opts->{dbs}->{$dbtype};
    }

    if (defined $path{$dbtype}) {
      eval {
        $db->{$dbtype} = MaxMind::DB::Reader->new(
          file => $path{$dbtype},
        );
        die "unknown error" unless $db->{$dbtype};
        1;
      };
      if ($@ || !$db->{$dbtype}) {
        my $err = $@;
        $err =~ s/\s+Trace begun.*//s;
        $err =~ s/ at .*//s;
        dbg("geodb: GeoIP2: $dbtype load failed: $err");
      } else {
        dbg("geodb: GeoIP2: loaded $dbtype from $path{$dbtype}");
        $ok = 1;
      }
    } else {
      my $from = defined $geodb_opts->{dbs}->{$dbtype} ?
        $geodb_opts->{dbs}->{$dbtype} : "default locations";
      dbg("geodb: GeoIP2: $dbtype database not found from $from");
    } 
  }

  if (!$ok) {
    warn("geodb: GeoIP2 requested, but no databases could be loaded\n") if $errwarn;
    return (undef, undef)
  }

  # dbinfo_DBTYPE()
  $db->{city} and $dbapi->{dbinfo_city} = sub {
    my $m = $_[0]->{db}->{city}->metadata();
    return "GeoIP2 city: ".$m->description()->{en}." / ".localtime($m->build_epoch());
  };
  $db->{country} and $dbapi->{dbinfo_country} = sub {
    my $m = $_[0]->{db}->{country}->metadata();
    return "GeoIP2 country: ".$m->description()->{en}." / ".localtime($m->build_epoch());
  };
  $db->{isp} and $dbapi->{dbinfo_isp} = sub {
    my $m = $_[0]->{db}->{isp}->metadata();
    return "GeoIP2 isp: ".$m->description()->{en}." / ".localtime($m->build_epoch());
  };
  $db->{asn} and $dbapi->{dbinfo_asn} = sub {
    my $m = $_[0]->{db}->{asn}->metadata();
    return "GeoIP2 asn: ".$m->description()->{en}." / ".localtime($m->build_epoch());
  };

  # city()
  $db->{city} and $dbapi->{city} = $dbapi->{city_v6} = sub {
    my $res = {};
    my $city;
    eval {
      $city = $_[0]->{db}->{city}->record_for_address($_[1]);
      1;
    } or do {
      $@ =~ s/\s+Trace begun.*//s;
      dbg("geodb: GeoIP2 city query failed for $_[1]: $@");
      return $res;
    };
    eval {
      $res->{city_name} = $city->{city}->{names}->{en};
      $res->{country} = $city->{country}->{iso_code};
      $res->{country_name} = $city->{country}->{names}->{en};
      $res->{continent} = $city->{continent}->{code};
      $res->{continent_name} = $city->{continent}->{names}->{en};
      1;
    };
    return $res;
  };

  # country()
  $db->{country} and $dbapi->{country} = $dbapi->{country_v6} = sub {
    my $res = {};
    my $country;
    eval {
      $country = $_[0]->{db}->{country}->record_for_address($_[1]);
      1;
    } or do {
      $@ =~ s/\s+Trace begun.*//s;
      dbg("geodb: GeoIP2 country query failed for $_[1]: $@");
      return $res;
    };
    eval {
      $res->{country} = $country->{country}->{iso_code};
      $res->{country_name} = $country->{country}->{names}->{en};
      $res->{continent} = $country->{continent}->{code};
      $res->{continent_name} = $country->{continent}->{names}->{en};
      1;
    };
    return $res;
  };

  # isp()
  $db->{isp} and $dbapi->{isp} = $dbapi->{isp_v6} = sub {
    my $res = {};
    my $isp;
    eval {
      $isp = $_[0]->{db}->{isp}->record_for_address($_[1]);
      1;
    } or do {
      $@ =~ s/\s+Trace begun.*//s;
      dbg("geodb: GeoIP2 isp query failed for $_[1]: $@");
      return $res;
    };
    eval {
      $res->{asn} = $isp->{autonomous_system_number};
      $res->{asn_organization} = $isp->{autonomous_system_organization};
      $res->{isp} = $isp->{isp};
      $res->{organization} = $isp->{organization};
      1;
    };
    return $res;
  };

  # asn()
  $db->{asn} and $dbapi->{asn} = $dbapi->{asn_v6} = sub {
    my $res = {};
    my $asn;
    eval {
      $asn = $_[0]->{db}->{asn}->record_for_address($_[1]);
      1;
    } or do {
      $@ =~ s/\s+Trace begun.*//s;
      dbg("geodb: GeoIP2 asn query failed for $_[1]: $@");
      return $res;
    };
    eval {
      $res->{asn} = $asn->{autonomous_system_number};
      $res->{asn_organization} = $asn->{autonomous_system_organization};
      1;
    };
    return $res;
  };

  return ($db, $dbapi);
}

sub load_geoip {
  my ($self, $geodb_opts) = @_;
  my ($db, $dbapi, $ok);
  my ($gic_wanted, $gic_have, $gip_wanted, $gip_have);
  my ($flags, $fix_stderr, $can_ipv6);

  # Warn about fatal errors if this module was specifically requested
  my $errwarn = ($geodb_opts->{module}||'') eq 'geoip';

  eval {
    require Geo::IP;
    # need GeoIP C library 1.6.3 and GeoIP perl API 1.4.4 or later to avoid messages leaking - Bug 7153
    $gip_wanted = version->parse('v1.4.4');
    $gip_have = version->parse(Geo::IP->VERSION);
    $gic_wanted = version->parse('v1.6.3');
    eval { $gic_have = version->parse(Geo::IP->lib_version()); }; # might not have lib_version()
    $gic_have = 'none' if !defined $gic_have;
    dbg("geodb: GeoIP: versions: Geo::IP $gip_have, C library $gic_have");
    $flags = 0;
    $fix_stderr = 0;
    if (ref($gic_have) eq 'version') {
      # this code burps an ugly message if it fails, but that's redirected elsewhere
      eval '$flags = Geo::IP::GEOIP_SILENCE' if $gip_wanted >= $gip_have;
      $fix_stderr = $flags && $gic_wanted >= $gic_have;
    }
    $can_ipv6 = Geo::IP->VERSION >= 1.39 && Geo::IP->api eq 'CAPI';
    1;
  } or do {
    my $err = $@;
    $err =~ s/ at .*//s;
    $err = "geodb: Geo::IP module load failed: $err";
    $errwarn ? warn("$err\n") : dbg($err);
    return (undef, undef);
  };

  my %path;
  foreach my $dbtype (@geoip_types) {
    # skip country if city already loaded
    next if $dbtype eq 'country' && $db->{city};
    # skip asn if isp already loaded
    next if $dbtype eq 'asn' && $db->{isp};
    # skip if not needed
    next if $geodb_opts->{wanted} && !$geodb_opts->{wanted}->{$dbtype};
    # only autosearch if no absolute path given
    if (!defined $geodb_opts->{dbs}->{$dbtype}) {
      # Try some default locations
      PATHS_GEOIP: foreach my $p (@{$geodb_opts->{search_path}}) {
        foreach my $f (@{$geoip_default_files{$dbtype}}) {
          if (-f "$p/$f") {
            $path{$dbtype} = "$p/$f";
            dbg("geodb: GeoIP: search found $dbtype $p/$f");
            if ($can_ipv6 && $f =~ s/\.(dat)$/v6.$1/i) {
              if (-f "$p/$f") {
                $path{$dbtype."_v6"} = "$p/$f";
                dbg("geodb: GeoIP: search found $dbtype $p/$f");
              }
            }
            last PATHS_GEOIP;
          }
        }
      }
    } else {
      if (!-f $geodb_opts->{dbs}->{$dbtype}) {
        dbg("geodb: GeoIP: $dbtype database requested, but not found: ".
          $geodb_opts->{dbs}->{$dbtype});
        next;
      }
      $path{$dbtype} = $geodb_opts->{dbs}->{$dbtype};
    }
  }

  if (!$can_ipv6) {
    dbg("geodb: GeoIP: IPv6 support not enabled, versions Geo::IP 1.39, GeoIP C API 1.4.7 required");
  }

  if ($fix_stderr) {
    open(OLDERR, ">&STDERR");
    open(STDERR, ">/dev/null");
  }
  foreach my $dbtype (@geoip_types) {
    next unless defined $path{$dbtype};
    eval {
      $db->{$dbtype} = Geo::IP->open($path{$dbtype}, Geo::IP->GEOIP_STANDARD | $flags);
      if ($can_ipv6 && defined $path{$dbtype."_v6"}) {
        $db->{$dbtype."_v6"} = Geo::IP->open($path{$dbtype."_v6"}, Geo::IP->GEOIP_STANDARD | $flags);
      }
    };
    if ($@ || !$db->{$dbtype}) {
      my $err = $@;
      $err =~ s/ at .*//s;
      dbg("geodb: GeoIP: database $path{$dbtype} load failed: $err");
    } else {
      dbg("geodb: GeoIP: loaded $dbtype from $path{$dbtype}");
      $ok = 1;
    }
  }
  if ($fix_stderr) {
    open(STDERR, ">&OLDERR");
    close(OLDERR);
  }

  if (!$ok) {
    warn("geodb: GeoIP requested, but no databases could be loaded\n") if $errwarn;
    return (undef, undef)
  }

  # dbinfo_DBTYPE()
  $db->{city} and $dbapi->{dbinfo_city} = sub {
    return "Geo::IP IPv4 city: " . ($_[0]->{db}->{city}->database_info || '?')." / IPv6: ".
      ($_[0]->{db}->{city_v6} ? $_[0]->{db}->{city_v6}->database_info || '?' : 'no')
  };
  $db->{country} and $dbapi->{dbinfo_country} = sub {
    return "Geo::IP IPv4 country: " . ($_[0]->{db}->{country}->database_info || '?')." / IPv6: ".
      ($_[0]->{db}->{country_v6} ? $_[0]->{db}->{country_v6}->database_info || '?' : 'no')
  };
  $db->{isp} and $dbapi->{dbinfo_isp} = sub {
    return "Geo::IP IPv4 isp: " . ($_[0]->{db}->{isp}->database_info || '?')." / IPv6: ".
      ($_[0]->{db}->{isp_v6} ? $_[0]->{db}->{isp_v6}->database_info || '?' : 'no')
  };
  $db->{asn} and $dbapi->{dbinfo_asn} = sub {
    return "Geo::IP IPv4 asn: " . ($_[0]->{db}->{asn}->database_info || '?')." / IPv6: ".
      ($_[0]->{db}->{asn_v6} ? $_[0]->{db}->{asn_v6}->database_info || '?' : 'no')
  };

  # city()
  $db->{city} and $dbapi->{city} = sub {
    my $res = {};
    my $city;
    if ($_[1] =~ IS_IPV4_ADDRESS) {
      $city = $_[0]->{db}->{city}->record_by_addr($_[1]);
    } elsif ($_[0]->{db}->{city_v6}) {
      $city = $_[0]->{db}->{city_v6}->record_by_addr_v6($_[1]);
    }
    if (!defined $city) {
      dbg("geodb: GeoIP city query failed for $_[1]");
      return $res;
    }
    $res->{city_name} = $city->city;
    $res->{country} = $city->country_code;
    $res->{country_name} = $city->country_name;
    $res->{continent} = $city->continent_code;
    return $res;
  };
  $dbapi->{city_v6} = $dbapi->{city} if $db->{city_v6};

  # country()
  $db->{country} and $dbapi->{country} = sub {
    my $res = {};
    my $country;
    eval {
      if ($_[1] =~ IS_IPV4_ADDRESS) {
        $country = $_[0]->{db}->{country}->country_code_by_addr($_[1]);
      } elsif ($_[0]->{db}->{country_v6}) {
        $country = $_[0]->{db}->{country_v6}->country_code_by_addr_v6($_[1]);
      }
      1;
    };
    if (!defined $country) {
      dbg("geodb: GeoIP country query failed for $_[1]");
      return $res;
    };
    $res->{country} = $country || 'XX';
    $res->{continent} = $country_to_continent{$country} || 'XX';
    return $res;
  };
  $dbapi->{country_v6} = $dbapi->{country} if $db->{country_v6};

  # isp()
  $db->{isp} and $dbapi->{isp} = sub {
    my $res = {};
    my $isp;
    eval {
      if ($_[1] =~ IS_IPV4_ADDRESS) {
        $isp = $_[0]->{db}->{isp}->isp_by_addr($_[1]);
      } else {
        # TODO?
        return $res;
      }
      1;
    };
    if (!defined $isp) {
      dbg("geodb: GeoIP isp query failed for $_[1]");
      return $res;
    };
    $res->{isp} = $isp;
    return $res;
  };

  # asn()
  $db->{asn} and $dbapi->{asn} = sub {
    my $res = {};
    my $asn;
    eval {
      if ($_[1] =~ IS_IPV4_ADDRESS) {
        $asn = $_[0]->{db}->{asn}->isp_by_addr($_[1]);
      } else {
        # TODO?
        return $res;
      }
      1;
    };
    if (!defined $asn || $asn !~ /^((?:AS)?\d+)(?:\s+(.+))?/) {
      dbg("geodb: GeoIP asn query failed for $_[1]");
      return $res;
    };
    $res->{asn} = $1;
    $res->{asn_organization} = $2 if defined $2;
    return $res;
  };

  return ($db, $dbapi);
}

sub load_dbfile {
  my ($self, $geodb_opts) = @_;
  my ($db, $dbapi);

  # Warn about fatal errors if this module was specifically requested
  my $errwarn = ($geodb_opts->{module}||'') eq 'dbfile';

  if (!defined $geodb_opts->{dbs}->{country}) {
    my $err = "geodb: IP::Country::DB_File requires geodb_options country:/path/to/ipcc.db";
    $errwarn ? warn("$err\n") : dbg($err);
    return (undef, undef);
  }

  if (!-f $geodb_opts->{dbs}->{country}) {
    my $err = "geodb: IP::Country::DB_File database not found: ".$geodb_opts->{dbs}->{country};
    $errwarn ? warn("$err\n") : dbg($err);
    return (undef, undef);
  }

  eval {
    require IP::Country::DB_File;
    $db->{country} = IP::Country::DB_File->new($geodb_opts->{dbs}->{country});
    1;
  };
  if ($@ || !$db->{country}) {
    my $err = $@;
    $err =~ s/ at .*//s;
    $err = "geodb: IP::Country::DB_File country load failed: $err";
    $errwarn ? warn("$err\n") : dbg($err);
    return (undef, undef);
  } else {
    dbg("geodb: IP::Country::DB_File loaded country from ".$geodb_opts->{dbs}->{country});
  }

  # dbinfo_DBTYPE()
  $db->{country} and $dbapi->{dbinfo_country} = sub {
    return "IP::Country::DB_File country: ".localtime($_[0]->{db}->{country}->db_time());
  };

  # country();
  $db->{country} and $dbapi->{country} = $dbapi->{country_v6} = sub {
    my $res = {};
    my $country;
    if ($_[1] =~ IS_IPV4_ADDRESS) {
      $country = $_[0]->{db}->{country}->inet_atocc($_[1]);
    } else {
      $country = $_[0]->{db}->{country}->inet6_atocc($_[1]);
    }
    if (!defined $country) {
      dbg("geodb: IP::Country::DB_File country query failed for $_[1]");
      return $res;
    };
    $res->{country} = $country || 'XX';
    $res->{continent} = $country_to_continent{$country} || 'XX';
    return $res;
  };

  return ($db, $dbapi);
}

sub load_fast {
  my ($self, $geodb_opts) = @_;
  my ($db, $dbapi);

  # Warn about fatal errors if this module was specifically requested
  my $errwarn = ($geodb_opts->{module}||'') eq 'fast';

  eval {
    require IP::Country::Fast;
    $db->{country} = IP::Country::Fast->new();
    1;
  };
  if ($@ || !$db->{country}) {
    my $err = $@;
    $err =~ s/ at .*//s;
    $err = "geodb: IP::Country::Fast load failed: $err";
    $errwarn ? warn("$err\n") : dbg($err);
    return (undef, undef);
  }

  # dbinfo_DBTYPE()
  $db->{country} and $dbapi->{dbinfo_country} = sub {
    return "IP::Country::Fast country: ".localtime($_[0]->{db}->{country}->db_time());
  };

  # country();
  $db->{country} and $dbapi->{country} = sub {
    my $res = {};
    my $country;
    if ($_[1] =~ IS_IPV4_ADDRESS) {
      $country = $_[0]->{db}->{country}->inet_atocc($_[1]);
    } else {
      return $res;
    }
    if (!defined $country) {
      dbg("geodb: IP::Country::Fast country query failed for $_[1]");
      return $res;
    };
    $res->{country} = $country || 'XX';
    $res->{continent} = $country_to_continent{$country} || 'XX';
    return $res;
  };

  return ($db, $dbapi);
}

# return array, infoline per database type
sub get_dbinfo {
  my ($self, $db) = @_;

  my @lines;
  foreach (@geoip_types) {
    if (exists $self->{dbapi}->{"dbinfo_".$_}) {
      push @lines,
        $self->{dbapi}->{"dbinfo_".$_}->($self) || "$_ failed";
    }
  }

  return \@lines;
}

sub get_country {
  my ($self, $ip) = @_;

  return undef if !defined $ip || $ip !~ /\S/; ## no critic (ProhibitExplicitReturnUndef)

  if ($ip =~ IS_IP_PRIVATE) {
    return '**';
  }

  if ($ip !~ IS_IP_ADDRESS) {
    $ip = name_to_ip($ip);
    return 'XX' if !defined $ip;
  }
  
  if ($self->{dbapi}->{city}) {
    return $self->_get('city',$ip)->{country} || 'XX';
  } elsif ($self->{dbapi}->{country}) {
    return $self->_get('country',$ip)->{country} || 'XX';
  } else {
    return undef; ## no critic (ProhibitExplicitReturnUndef)
  }
}

sub get_continent {
  my ($self, $ip) = @_;

  return undef if !defined $ip || $ip !~ /\S/; ## no critic (ProhibitExplicitReturnUndef)

  # If it's already CC, use our own lookup table..
  if (length($ip) == 2) {
    return $country_to_continent{uc($ip)} || 'XX';
  }

  if ($self->{dbapi}->{city}) {
    return $self->_get('city',$ip)->{continent} || 'XX';
  } elsif ($self->{dbapi}->{country}) {
    return $self->_get('country',$ip)->{continent} || 'XX';
  } else {
    return undef; ## no critic (ProhibitExplicitReturnUndef)
  }
}

sub get_isp {
  my ($self, $ip) = @_;

  return undef if !defined $ip || $ip !~ /\S/; ## no critic (ProhibitExplicitReturnUndef)

  if ($self->{dbapi}->{isp}) {
    return $self->_get('isp',$ip)->{isp};
  } else {
    return undef; ## no critic (ProhibitExplicitReturnUndef)
  }
}

sub get_isp_org {
  my ($self, $ip) = @_;

  return undef if !defined $ip || $ip !~ /\S/; ## no critic (ProhibitExplicitReturnUndef)

  if ($self->{dbapi}->{isp}) {
    return $self->_get('isp',$ip)->{organization};
  } else {
    return undef; ## no critic (ProhibitExplicitReturnUndef)
  }
}

sub get_asn {
  my ($self, $ip) = @_;

  return undef if !defined $ip || $ip !~ /\S/; ## no critic (ProhibitExplicitReturnUndef)

  if ($self->{dbapi}->{asn}) {
    return $self->_get('asn',$ip)->{asn};
  } elsif ($self->{dbapi}->{isp}) {
    return $self->_get('isp',$ip)->{asn};
  } else {
    return undef; ## no critic (ProhibitExplicitReturnUndef)
  }
}

sub get_asn_org {
  my ($self, $ip) = @_;

  return undef if !defined $ip || $ip !~ /\S/; ## no critic (ProhibitExplicitReturnUndef)

  if ($self->{dbapi}->{asn}) {
    return $self->_get('asn',$ip)->{asn_organization};
  } elsif ($self->{dbapi}->{isp}) {
    return $self->_get('isp',$ip)->{asn_organization};
  } else {
    return undef; ## no critic (ProhibitExplicitReturnUndef)
  }
}

sub get_all {
  my ($self, $ip) = @_;

  return undef if !defined $ip || $ip !~ /\S/; ## no critic (ProhibitExplicitReturnUndef)

  my $all = {};

  if ($ip =~ IS_IP_PRIVATE) {
    return { 'country' => '**' };
  }

  if ($ip !~ IS_IP_ADDRESS) {
    $ip = name_to_ip($ip);
    if (!defined $ip) {
      return { 'country' => 'XX' };
    }
  }
  
  if ($self->{dbapi}->{city}) {
    my $res = $self->_get('city',$ip);
    $all->{$_} = $res->{$_} foreach (keys %$res);
  } elsif ($self->{dbapi}->{country}) {
    my $res = $self->_get('country',$ip);
    $all->{$_} = $res->{$_} foreach (keys %$res);
  }

  if ($self->{dbapi}->{isp}) {
    my $res = $self->_get('isp',$ip);
    $all->{$_} = $res->{$_} foreach (keys %$res);
  }

  if ($self->{dbapi}->{asn}) {
    my $res = $self->_get('asn',$ip);
    $all->{$_} = $res->{$_} foreach (keys %$res);
  }

  return $all;
}

sub can {
  my ($self, $check) = @_;

  return defined $self->{dbapi}->{$check};
}

# TODO: use SA internal dns synchronously?
# This shouldn't be called much, as plugins
# should do their own resolving if needed
sub name_to_ip {
  my $name = shift;
  if (my $ip = inet_aton($name)) {
    $ip = inet_ntoa($ip);
    dbg("geodb: resolved internally $name: $ip");
    return $ip;
  }
  dbg("geodb: failed to internally resolve $name");
  return undef; ## no critic (ProhibitExplicitReturnUndef)
}

sub _get {
  my ($self, $type, $ip) = @_;

  # reset cache at 100 ips
  if (scalar keys %{$self->{cache}} >= 100) {
    $self->{cache} = ();
  }

  if (!exists $self->{cache}{$ip}{$type}) {
    if ($self->{dbapi}->{$type}) {
      $self->{cache}{$ip}{$type} = $self->{dbapi}->{$type}->($self,$ip);
    } else {
      return undef; ## no critic (ProhibitExplicitReturnUndef)
    }
  }

  return $self->{cache}{$ip}{$type};
}

1;
