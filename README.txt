You will need two terminal tabs.

[In terminal Tab 1]
cd into the folder Server and run server.py
(python3 server.py)
Use the default configuration.
The password is 'passwordServer'

You can view the log file in another terminal tab by doing (tail -f Server.log)


[In terminal Tab 2]
cd into Client and run client.py
(python3 client.py)
Use the default configuration.
For staff ID, use the ID (s45678). It should be the default. This is an examiner id.
On the client the password for all the accounts is (passwordClient).

UPLOADING an exam.
When asked for Module Code, use the default.
When asked for filename of exam, enter 'AY20132014S2_ST2504_Exam.v1.pdf'
When asked for filename of solution, enter 'AY20132014S2_ST2504_Sol.v1.pdf'

You can test with the following options as the staff ID.
Examiner 	=> s45678
Principal Admin => s23456
Backup Admin 	=> s34567

Note: The public private keys have been created to simulate all the accounts running on the same system, thus the private key is the same for all, however the system has been setup to be used with multiple key pairs.
