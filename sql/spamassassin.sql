CREATE TABLE userpref (
  username varchar(8) default NOT NULL,
  preference varchar(30) default NOT NULL,
  value varchar(100) default NOT NULL,
  prefid int(11) NOT NULL auto_increment,
  PRIMARY KEY (prefid)
) TYPE=MyISAM;

