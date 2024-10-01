CREATE TABLE `redir_url_cache`
( `redir_url` VARCHAR(255) NOT NULL,
  `target_url` VARCHAR(512) NOT NULL,
  `hits` INT NOT NULL DEFAULT 1,
  `created` INT(11) NOT NULL,
  `modified` INT(11) NOT NULL,
  PRIMARY KEY (`redir_url`)
) ENGINE = InnoDB;
-- Maintaining index for cleaning is likely more expensive than occasional full table scan
-- ALTER TABLE `redir_url_cache` ADD INDEX `redir_url_created` (`created`);
