-- One-time migration of the deprecated DecodeShortURLs plugin's cache
-- into the Redirectors plugin's cache. Run after redir_url_cache exists
-- (created via sql/redirectors_mysql.sql).
--
-- Usage: mysql -u <user> -p <database> < migrate_decodeshorturl_to_redirectors_mysql.sql

INSERT IGNORE INTO `redir_url_cache` (`redir_url`, `target_url`, `hits`, `created`, `modified`)
SELECT `short_url`, `decoded_url`, `hits`, `created`, `modified`
FROM `short_url_cache`;