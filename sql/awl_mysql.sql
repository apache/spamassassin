CREATE TABLE awl (
  username varchar(100) NOT NULL default '',
  email varbinary(255) NOT NULL default '',
  ip varchar(40) NOT NULL default '',
  count int(11) NOT NULL default '0',
  totscore float NOT NULL default '0',
  signedby varchar(255) NOT NULL default '',
  PRIMARY KEY (username,email,signedby,ip)
) ENGINE=InnoDB;
