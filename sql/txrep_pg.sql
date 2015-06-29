CREATE TABLE txrep (
  username varchar(100) NOT NULL default '',
  email varchar(255) NOT NULL default '',
  ip varchar(40) NOT NULL default '',
  count int(11) NOT NULL default '0',
  totscore float NOT NULL default '0',
  signedby varchar(255) NOT NULL default '',
  last_hit timestamp NOT NULL default CURRENT_TIMESTAMP,
  PRIMARY KEY (username,email,signedby,ip)
);

create index txrep_last_hit on txrep (last_hit);

create OR REPLACE function update_txrep_last_hit()
RETURNS TRIGGER AS $$
BEGIN
  NEW.last_hit = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ language 'plpgsql';

create TRIGGER update_txrep_update_last_hit BEFORE UPDATE
ON txrep FOR EACH ROW EXECUTE PROCEDURE
update_txrep_last_hit();

ALTER TABLE txrep SET (fillfactor=95);

