CREATE TABLE userpref (
  username varchar(100) NOT NULL,
  preference varchar(30) NOT NULL,
  value varchar(100) NOT NULL,
  prefid int(11) NOT NULL auto_increment,
  PRIMARY KEY (prefid),
  INDEX (username)
) TYPE=MyISAM;

