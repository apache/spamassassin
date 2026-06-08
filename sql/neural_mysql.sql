CREATE TABLE neural_seen (
  username VARCHAR(200) NOT NULL DEFAULT 'default',
  msgid VARBINARY(200) NOT NULL DEFAULT '',
  flag CHAR(1) NOT NULL DEFAULT '',
  PRIMARY KEY (username, msgid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE neural_vocabulary (
  username VARCHAR(200) NOT NULL DEFAULT '',
  keyword VARCHAR(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '',
  total_count INT NOT NULL DEFAULT 0,
  docs_count INT NOT NULL DEFAULT 0,
  spam_count INT NOT NULL DEFAULT 0,
  ham_count INT NOT NULL DEFAULT 0,
  model_position INT DEFAULT NULL,
  PRIMARY KEY (username, keyword),
  KEY neural_vocab_model_pos_idx (username, model_position)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE neural_vars (
  username varchar(200) NOT NULL default '',
  variable varchar(30)  NOT NULL default '',
  value    varchar(200) NOT NULL default '',
  PRIMARY KEY (username, variable)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE neural_training_buffer (
  username varchar(200) NOT NULL default '',
  class    ENUM('spam', 'ham') NOT NULL,
  slot     int          NOT NULL default 0,
  ts       int          NOT NULL default 0,
  token    varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL default '',
  count    int          NOT NULL default 1,
  PRIMARY KEY (username, class, slot, token)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
