
CREATE TABLE bayes_expire (
  id integer NOT NULL default '0',
  runtime integer NOT NULL default '0'
);

CREATE INDEX bayes_expire_idx1 ON bayes_expire (id);

CREATE TABLE bayes_global_vars (
  variable varchar(30) NOT NULL default '',
  value varchar(200) NOT NULL default '',
  PRIMARY KEY  (variable)
);

INSERT INTO bayes_global_vars VALUES ('VERSION','3');

CREATE TABLE bayes_seen (
  id integer NOT NULL default '0',
  msgid varchar(200) NOT NULL default '',
  flag character(1) NOT NULL default '',
  PRIMARY KEY  (id,msgid)
);

CREATE TABLE bayes_token (
  id integer NOT NULL default '0',
  token char(5) NOT NULL default '',
  spam_count integer NOT NULL default '0',
  ham_count integer NOT NULL default '0',
  atime integer NOT NULL default '0',
  PRIMARY KEY  (id,token)
);

CREATE TABLE bayes_vars (
  id serial NOT NULL,
  username varchar(200) NOT NULL default '',
  spam_count integer NOT NULL default '0',
  ham_count integer NOT NULL default '0',
  token_count integer NOT NULL default '0',
  last_expire integer NOT NULL default '0',
  last_atime_delta integer NOT NULL default '0',
  last_expire_reduce integer NOT NULL default '0',
  oldest_token_age integer NOT NULL default '2147483647',
  newest_token_age integer NOT NULL default '0',
  PRIMARY KEY  (id)
);

CREATE INDEX bayes_vars_idx1 ON bayes_vars (username);