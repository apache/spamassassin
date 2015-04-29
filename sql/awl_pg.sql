CREATE TABLE awl (
  username varchar(100) NOT NULL default '',
  email varchar(255) NOT NULL default '',
  ip varchar(40) NOT NULL default '',
  count bigint NOT NULL default '0',
  totscore float NOT NULL default '0',
  signedby varchar(255) NOT NULL default '',
  PRIMARY KEY (username,email,signedby,ip)
);

ALTER TABLE awl SET (fillfactor=95);

