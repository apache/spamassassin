CREATE TABLE short_url_cache (
  short_url VARCHAR(256) NOT NULL,
  decoded_url VARCHAR(512) NOT NULL,
  hits INT NOT NULL DEFAULT 1,
  created INT NOT NULL,
  modified INT NOT NULL,
  PRIMARY KEY (short_url)
);
-- Maintaining index for cleaning is likely more expensive than occasional full table scan
-- ALTER TABLE short_url_cache ADD INDEX short_url_created (created);
