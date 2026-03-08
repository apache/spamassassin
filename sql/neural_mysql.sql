CREATE TABLE neural_seen (
  username varchar(200) NOT NULL DEFAULT 'default',
  msgid varchar(200) binary NOT NULL DEFAULT '',
  flag char(1) NOT NULL DEFAULT '',
  PRIMARY KEY neural_seen_idx1 (username, msgid)
) ENGINE=InnoDB;

CREATE TABLE neural_vocabulary (
  username varchar(200) NOT NULL DEFAULT '',
  keyword varchar(256) NOT NULL DEFAULT '',
  total_count int(11) NOT NULL DEFAULT '0',
  docs_count int(11) NOT NULL DEFAULT '0',
  spam_count int(11) NOT NULL DEFAULT '0',
  ham_count int(11) NOT NULL DEFAULT '0',
  model_position int(11) DEFAULT NULL,
  PRIMARY KEY neural_vocab_idx1 (username, keyword),
  KEY neural_vocab_model_pos_idx (username, model_position)
) ENGINE=InnoDB;
