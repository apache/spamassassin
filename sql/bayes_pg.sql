
CREATE TABLE bayes_expire (
  id integer NOT NULL default '0',
  runtime integer NOT NULL default '0'
) WITHOUT OIDS;

CREATE INDEX bayes_expire_idx1 ON bayes_expire (id);

CREATE TABLE bayes_global_vars (
  variable varchar(30) NOT NULL default '',
  value varchar(200) NOT NULL default '',
  PRIMARY KEY  (variable)
) WITHOUT OIDS;

INSERT INTO bayes_global_vars VALUES ('VERSION','3');

CREATE TABLE bayes_seen (
  id integer NOT NULL default '0',
  msgid varchar(200) NOT NULL default '',
  flag character(1) NOT NULL default '',
  PRIMARY KEY  (id,msgid)
) WITHOUT OIDS;

CREATE TABLE bayes_token (
  id integer NOT NULL default '0',
  token bytea NOT NULL default '',
  spam_count integer NOT NULL default '0',
  ham_count integer NOT NULL default '0',
  atime integer NOT NULL default '0',
  PRIMARY KEY  (id,token)
) WITHOUT OIDS;

CREATE INDEX bayes_token_idx1 ON bayes_token (token);

CREATE TABLE bayes_vars (
  id serial NOT NULL,
  username varchar(200) NOT NULL default '',
  spam_count integer NOT NULL default '0',
  ham_count integer NOT NULL default '0',
  token_count integer NOT NULL default '0',
  last_expire integer NOT NULL default '0',
  last_atime_delta integer NOT NULL default '0',
  last_expire_reduce integer NOT NULL default '0',
  oldest_token_age integer NOT NULL default '2147483647',
  newest_token_age integer NOT NULL default '0',
  PRIMARY KEY  (id)
) WITHOUT OIDS;

CREATE UNIQUE INDEX bayes_vars_idx1 ON bayes_vars (username);

CREATE OR REPLACE FUNCTION put_token(integer, bytea, integer, integer, integer) RETURNS bool AS ' 
DECLARE 
	inuserid ALIAS for $1; 
        intoken ALIAS for $2; 
        inspam_count ALIAS for $3; 
        inham_count ALIAS for $4; 
        inatime ALIAS for $5; 
        got_token record;
	updated_atime_p bool;
BEGIN
  updated_atime_p := FALSE;
  SELECT INTO got_token spam_count, ham_count, atime 
    FROM bayes_token 
   WHERE id = inuserid 
     AND token = intoken; 
   IF NOT FOUND THEN 
     -- we do not insert negative counts, just return true
     IF (inspam_count < 0 OR inham_count < 0) THEN
       RETURN TRUE;
     END IF;
     INSERT INTO bayes_token (id, token, spam_count, ham_count, atime) 
     VALUES (inuserid, intoken, inspam_count, inham_count, inatime); 
     IF NOT FOUND THEN 
       RAISE EXCEPTION ''unable to insert into bayes_token''; 
       return FALSE;
     END IF;
     UPDATE bayes_vars SET token_count = token_count + 1 
      WHERE id = inuserid; 
     IF NOT FOUND THEN 
       RAISE EXCEPTION ''unable to update token_count in bayes_vars''; 
       return FALSE;
     END IF;
     UPDATE bayes_vars SET newest_token_age = inatime 
      WHERE id = inuserid AND newest_token_age < inatime; 
     IF NOT FOUND THEN 
       UPDATE bayes_vars
          SET oldest_token_age = inatime
        WHERE id = inuserid
          AND oldest_token_age > inatime; 
     END IF;
     return TRUE; 
  ELSE 
    IF (inspam_count != 0) THEN
      -- no need to update atime if it is < the existing value
      IF (inatime < got_token.atime) THEN
        UPDATE bayes_token 
           SET spam_count = spam_count + inspam_count
         WHERE id = inuserid
           AND token = intoken
           AND spam_count + inspam_count >= 0;
      ELSE 
        UPDATE bayes_token 
           SET spam_count = spam_count + inspam_count,
               atime = inatime
         WHERE id = inuserid
           AND token = intoken
           AND spam_count + inspam_count >= 0;
        IF FOUND THEN
          updated_atime_p := TRUE;
        END IF;
      END IF;
    END IF;
    IF (inham_count != 0) THEN
      -- no need to update atime is < the existing value or if it was already updated
      IF inatime < got_token.atime OR updated_atime_p THEN
        UPDATE bayes_token 
           SET ham_count = ham_count + inham_count
         WHERE id = inuserid
           AND token = intoken
           AND ham_count + inham_count >= 0;
      ELSE 
        UPDATE bayes_token 
           SET ham_count = ham_count + inham_count,
               atime = inatime
         WHERE id = inuserid
           AND token = intoken
           AND ham_count + inham_count >= 0;
        IF FOUND THEN
          updated_atime_p := TRUE;
        END IF;
      END IF;
    END IF;
    IF updated_atime_p THEN
      UPDATE bayes_vars
         SET oldest_token_age = inatime
       WHERE id = inuserid
         AND oldest_token_age > inatime;
    END IF;
    return TRUE;
  END IF;
END; 
' LANGUAGE 'plpgsql'; 

 
