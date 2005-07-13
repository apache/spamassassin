CREATE TABLE awl (
  username varchar(100) NOT NULL default '',
  email varchar(200) NOT NULL default '',
  ip varchar(10) NOT NULL default '',
  count bigint default '0',
  totscore float default '0'
);
CREATE UNIQUE INDEX awl_pkey ON awl (username,email,ip);
