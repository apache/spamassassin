-- SpamAssassin ExtractText plugin - PostgreSQL cache schema
-- Usage: psql -U <username> -d <database> -f extracttext_pgsql.sql

CREATE TABLE IF NOT EXISTS extracttext_cache (
  file_hash   TEXT        PRIMARY KEY NOT NULL,
  file_name   TEXT        NOT NULL,
  file_text   TEXT        NOT NULL,
  hits        INTEGER     NOT NULL DEFAULT 1,
  created     INTEGER     NOT NULL,
  modified    INTEGER     NOT NULL
);

-- Optional index to speed up TTL-based cleanup queries
-- CREATE INDEX IF NOT EXISTS extracttext_modified
--   ON extracttext_cache(created);
