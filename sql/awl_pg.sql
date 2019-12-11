CREATE TABLE awl (
  username varchar(100) NOT NULL default '',
  email varchar(255) NOT NULL default '',
  ip varchar(40) NOT NULL default '',
  msgcount bigint NOT NULL default '0',
  totscore float NOT NULL default '0',
  signedby varchar(255) NOT NULL default '',
  last_hit timestamp NOT NULL default CURRENT_TIMESTAMP,
  PRIMARY KEY (username,email,signedby,ip)
);

create index awl_last_hit on awl (last_hit);

create OR REPLACE function update_awl_last_hit()
RETURNS TRIGGER AS $$
BEGIN
  NEW.last_hit = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ language 'plpgsql';

create TRIGGER update_awl_update_last_hit BEFORE UPDATE
ON awl FOR EACH ROW EXECUTE PROCEDURE
update_awl_last_hit();

ALTER TABLE awl SET (fillfactor=95);
