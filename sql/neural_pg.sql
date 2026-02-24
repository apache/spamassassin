-- PostgreSQL schema for NeuralNetwork plugin
-- Create extension for UUID if needed (optional)
-- CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE neural_seen (
  username VARCHAR(200) NOT NULL DEFAULT 'default',
  msgid VARCHAR(200) NOT NULL DEFAULT '',
  flag CHAR(1) NOT NULL DEFAULT '',
  UNIQUE (username, msgid)
);

CREATE INDEX neural_seen_username_idx ON neural_seen(username);
CREATE INDEX neural_seen_msgid_idx ON neural_seen(msgid);

CREATE TABLE neural_vocabulary (
  username VARCHAR(200) NOT NULL DEFAULT '',
  keyword VARCHAR(256) NOT NULL DEFAULT '',
  total_count INTEGER NOT NULL DEFAULT 0,
  docs_count INTEGER NOT NULL DEFAULT 0,
  spam_count INTEGER NOT NULL DEFAULT 0,
  ham_count INTEGER NOT NULL DEFAULT 0,
  UNIQUE (username, keyword)
);

CREATE INDEX neural_vocabulary_username_idx ON neural_vocabulary(username);
CREATE INDEX neural_vocabulary_keyword_idx ON neural_vocabulary(keyword);
CREATE INDEX neural_vocabulary_spam_count_idx ON neural_vocabulary(spam_count DESC);
CREATE INDEX neural_vocabulary_total_count_idx ON neural_vocabulary(total_count DESC);
