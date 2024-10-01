CREATE TABLE redir_url_cache (
  redir_url VARCHAR(256) NOT NULL,
  target_url VARCHAR(512) NOT NULL,
  hits INT NOT NULL DEFAULT 1,
  created INT NOT NULL,
  modified INT NOT NULL,
  PRIMARY KEY (redirs_url)
);
-- Maintaining index for cleaning is likely more expensive than occasional full table scan
-- ALTER TABLE redir_url_cache ADD INDEX redir_url_created (created);
