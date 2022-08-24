CREATE TABLE `short_url_cache`
( `short_url` VARCHAR(255) NOT NULL,
  `decoded_url` VARCHAR(512) NOT NULL,
  `hits` INT NOT NULL DEFAULT 1,
  `created` INT(11) NOT NULL,
  `modified` INT(11) NOT NULL,
  PRIMARY KEY (`short_url`)
) ENGINE = InnoDB;
-- Maintaining index for cleaning is likely more expensive than occasional full table scan
-- ALTER TABLE `short_url_cache` ADD INDEX `short_url_created` (`created`);
