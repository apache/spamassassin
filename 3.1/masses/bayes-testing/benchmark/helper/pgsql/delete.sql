delete from bayes_seen where id = (SELECT id FROM bayes_vars WHERE username = 'benchmark');
vacuum full analyze bayes_seen;
delete from bayes_token where id = (SELECT id FROM bayes_vars WHERE username = 'benchmark');
vacuum full analyze bayes_token;
delete from bayes_vars where username = 'benchmark';
vacuum full analyze bayes_vars;

