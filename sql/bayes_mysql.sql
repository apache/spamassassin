
CREATE TABLE bayes_expire (
  username varchar(200) NOT NULL default '',
  runtime int(11) NOT NULL default '0',
  KEY bayes_expire_idx1 (username)
) TYPE=MyISAM;

CREATE TABLE bayes_global_vars (
  variable varchar(30) NOT NULL default '',
  value varchar(200) NOT NULL default '',
  PRIMARY KEY  (variable)
) TYPE=MyISAM;

INSERT INTO bayes_global_vars VALUES ('VERSION','2');

CREATE TABLE bayes_seen (
  username varchar(200) NOT NULL default '',
  msgid varchar(200) binary NOT NULL default '',
  flag char(1) NOT NULL default '',
  PRIMARY KEY  (username,msgid),
  KEY bayes_seen_idx1 (username,flag)
) TYPE=MyISAM;

CREATE TABLE bayes_token (
  username varchar(200) NOT NULL default '',
  token varchar(200) binary NOT NULL default '',
  spam_count int(11) NOT NULL default '0',
  ham_count int(11) NOT NULL default '0',
  atime int(11) NOT NULL default '0',
  PRIMARY KEY  (username,token)
) TYPE=MyISAM;

CREATE TABLE bayes_vars (
  username varchar(200) NOT NULL default '',
  spam_count int(11) NOT NULL default '0',
  ham_count int(11) NOT NULL default '0',
  last_expire int(11) NOT NULL default '0',
  last_atime_delta int(11) NOT NULL default '0',
  last_expire_reduce int(11) NOT NULL default '0',
  PRIMARY KEY  (username)
) TYPE=MyISAM;
