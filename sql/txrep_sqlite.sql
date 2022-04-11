CREATE TABLE txrep (
  username varchar(100) NOT NULL default '',
  email varchar(255) NOT NULL default '',
  ip varchar(40) NOT NULL default '',
  msgcount int(11) NOT NULL default '0',
  totscore float NOT NULL default '0',
  signedby varchar(255) NOT NULL default '',
  last_hit timestamp NOT NULL default CURRENT_TIMESTAMP,
  PRIMARY KEY (username,email,signedby,ip)
);

CREATE INDEX last_hit ON txrep (last_hit);

CREATE TRIGGER [UpdateLastHit]
    AFTER UPDATE
    ON txrep
    FOR EACH ROW
    WHEN NEW.last_hit < OLD.last_hit
BEGIN
    UPDATE txrep SET last_hit=CURRENT_TIMESTAMP 
    WHERE (username=OLD.username AND email=OLD.email AND signedby=OLD.signedby AND ip=OLD.ip);
END;
