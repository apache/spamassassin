delete from bayes_seen where id = (SELECT id FROM bayes_vars WHERE username = 'benchmark');
optimize table bayes_seen;
delete from bayes_token where id = (SELECT id FROM bayes_vars WHERE username = 'benchmark');
optimize table bayes_token;
delete from bayes_vars where username = 'benchmark';
optimize table bayes_vars;

