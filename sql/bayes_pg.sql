
CREATE TABLE bayes_expire (
  username varchar(200) NOT NULL default '',
  runtime integer NOT NULL default '0'
);

CREATE INDEX bayes_expire_idx1 ON bayes_expire (username);

CREATE TABLE bayes_global_vars (
  variable varchar(30) NOT NULL default '',
  value varchar(200) NOT NULL default '',
  PRIMARY KEY  (variable)
);

INSERT INTO bayes_global_vars VALUES ('VERSION','2');

CREATE TABLE bayes_seen (
  username varchar(200) NOT NULL default '',
  msgid varchar(200) NOT NULL default '',
  flag character(1) NOT NULL default '',
  PRIMARY KEY  (username,msgid)
);

CREATE INDEX bayes_seen_idx1 ON bayes_seen (username, flag);

CREATE TABLE bayes_token (
  username varchar(200) NOT NULL default '',
  token varchar(200) NOT NULL default '',
  spam_count integer NOT NULL default '0',
  ham_count integer NOT NULL default '0',
  atime integer NOT NULL default '0',
  PRIMARY KEY  (username,token)
);

CREATE TABLE bayes_vars (
  username varchar(200) NOT NULL default '',
  spam_count integer NOT NULL default '0',
  ham_count integer NOT NULL default '0',
  last_expire integer NOT NULL default '0',
  last_atime_delta integer NOT NULL default '0',
  last_expire_reduce integer NOT NULL default '0',
  PRIMARY KEY  (username)
);
