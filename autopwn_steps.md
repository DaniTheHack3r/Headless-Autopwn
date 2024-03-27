# Autopwn Steps

1. Setup a simple http server that will capture the admin cookie.
2. Send a XSS payload in a post request to the /support endpoint.
3. Send a post request with the new cookie with a bash payload to establish a connection to grab the user flag.
4. Exploit the vulnerability by creating a file called initdb.sh to get root access.
5. Retrieve root flag.