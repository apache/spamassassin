CREATE TABLE IF NOT EXISTS neural_seen (
  username VARCHAR(200) NOT NULL DEFAULT 'default',
  msgid VARCHAR(200) NOT NULL DEFAULT '',
  flag CHAR(1) NOT NULL DEFAULT '',
  UNIQUE (username, msgid)
);

CREATE TABLE IF NOT EXISTS neural_vocabulary (
  username VARCHAR(200) NOT NULL DEFAULT '',
  keyword VARCHAR(256) NOT NULL DEFAULT '',
  total_count INTEGER NOT NULL DEFAULT 0,
  docs_count INTEGER NOT NULL DEFAULT 0,
  spam_count INTEGER NOT NULL DEFAULT 0,
  ham_count INTEGER NOT NULL DEFAULT 0,
  model_position INTEGER DEFAULT NULL,
  UNIQUE (username, keyword)
);

CREATE INDEX IF NOT EXISTS neural_vocabulary_username_idx ON neural_vocabulary(username);
CREATE INDEX IF NOT EXISTS neural_vocabulary_model_position_idx ON neural_vocabulary(username, model_position);
