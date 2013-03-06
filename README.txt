Simple Apache access filter based on IP/login pairs for HTTP-based applications without such a future.

=== Enabling ===
Add following directives to httpd.conf
LoadModule access_filter_module modules/mod_access_filter.so

UseAccessFilter On

=== Configuring ===
Main module config is expected in 'conf/access_filter.txt'. Each line in the file should be in the following form:
<Network Address><Tab><File name>

  * Network address is the literal part of an allowed IP address. I.e. 10.1.1 will match both 10.1.1.10 and 10.1.100.10
  * Tab is one tabulation character. No spaces allowed.
  * File name is a path to a file with a list of logins allowed in the given network. One login per line, no extra characters.

=== Logging ===
The module will log 'allowed' and 'denied' events in the error log. The messages are logged at the 'error' level. The messages' format is following: 'User <login> from <remote IP> blocked|allowed'
