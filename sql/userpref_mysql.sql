CREATE TABLE userpref (
  username varchar(100) NOT NULL default '',
  preference varchar(30) NOT NULL default '',
  value varchar(100) NOT NULL default '',
  prefid int(11) NOT NULL auto_increment,
  PRIMARY KEY  (prefid),
  KEY username (username)
) TYPE=MyISAM;
