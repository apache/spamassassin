CREATE TABLE `short_url_cache`
( `short_url` VARCHAR(256) NOT NULL ,
  `decoded_url` VARCHAR(512) NOT NULL ,
  `hits` MEDIUMINT NOT NULL DEFAULT 1,
  `created` INT(11) NOT NULL ,
  `modified` INT(11) NOT NULL ,
  PRIMARY KEY (`short_url`)
) ENGINE = InnoDB;
ALTER TABLE `spam_bayes`.`short_url_cache` ADD INDEX `short_url_by_modified` (`short_url`, `modified`);
ALTER TABLE `spam_bayes`.`short_url_cache` ADD INDEX `short_url_modified` (`modified`);
