CREATE TABLE userpref (
  prefid bigserial NOT NULL unique primary key,
  username varchar(100) NOT NULL,
  preference varchar(50) NOT NULL,
  value varchar(100) NOT NULL
);
CREATE INDEX userpref_username_idx ON userpref(username);
