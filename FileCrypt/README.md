# FileCrypt
In this project i created a Java application for securing files. It works with user accounts (uname,pass login), secured with a digest (generated with PBKDF2WithHmacSHA1 method) encrypted  with asymmetric RSA encryption (2048 bits keypair) with app's keypair (public key on file, private hardcoded) and saved in a digests archive. Data is encrypted/decrypted with symmetric AES algorithm encryption (256 bits keys). 

###### GUI Screenshots

![0](https://raw.githubusercontent.com/christosav/projects_security/master/FileCrypt/scr/0.jpg)
![1](https://raw.githubusercontent.com/christosav/projects_security/master/FileCrypt/scr/1.jpg)
