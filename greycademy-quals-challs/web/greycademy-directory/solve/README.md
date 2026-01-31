The search form directly interpolates input into the SQL query (see `service/app.py` around the `current_query` assignment). With debug mode enabled the page prints the SQL string and each row returned by PostgreSQL.

The accounts table only has `username` and `email`, while the flag lives in a separate `secrets(secret)` table. Because the vulnerable query returns two columns, we can `UNION` in data from that second table to surface the flag.

Steps to retrieve it:

1. Enable debug mode and submit a harmless username to view the rendered query:  
   `SELECT username, email FROM accounts WHERE username LIKE '%<INPUT>%'`
2. Submit the payload `jinkai' UNION SELECT 'flag', secret from secrets --` as the username.
3. PostgreSQL now evaluates  
   `SELECT username, email FROM accounts WHERE username LIKE '%jinkai' UNION SELECT 'flag', secret FROM secrets --%'`  
   so the `secrets` row is appended to the results.
