CREATE TABLE short_url_cache (
  short_url   TEXT PRIMARY KEY NOT NULL,
  decoded_url TEXT NOT NULL,
  hits        INTEGER NOT NULL DEFAULT 1,
  created     INTEGER NOT NULL ,
  modified    INTEGER NOT NULL
);
CREATE INDEX short_url_by_modified
  ON short_url_cache(short_url, modified);
CREATE INDEX short_url_modified
  ON short_url_cache(modified);
