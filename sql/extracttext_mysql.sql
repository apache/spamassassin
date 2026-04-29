CREATE TABLE `extracttext_cache` (
  `file_hash` char(32) NOT NULL,
  `file_name` varchar(256) NOT NULL,
  `file_text` varchar(512) NOT NULL,
  `hits` int(11) NOT NULL DEFAULT 1,
  `created` int(11) NOT NULL,
  `modified` int(11) NOT NULL,
  PRIMARY KEY (`file_hash`)
) ENGINE=InnoDB;
-- Maintaining index for cleaning is likely more expensive than occasional full table scan
-- ALTER TABLE `extracttext_cache` ADD INDEX `extracttext_modified` (`created`);
