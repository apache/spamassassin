-- One-time migration of the deprecated DecodeShortURLs plugin's cache
-- into the Redirectors plugin's cache. redir_url_cache is created
-- automatically by the plugin on first run.
--
-- Usage: sqlite3 /path/to/cache.db < migrate_decodeshorturl_to_redirectors_sqlite.sql

INSERT INTO redir_url_cache (redir_url, target_url, hits, created, modified)
SELECT short_url, decoded_url, hits, created, modified
FROM short_url_cache
ON CONFLICT(redir_url) DO NOTHING;