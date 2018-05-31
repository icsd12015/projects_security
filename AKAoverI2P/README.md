# AKAoverI2P
In this project we implemented a Authentication and Key Agreement (ΑΚΑ) Protocol, between two entities, where the protocol messages were being exchanged via the I2P network. Alice (customer) and Bob (server) exchange appropriate messages to create a 128bits symmetric cryptographic key. Bob owns a self-signed certificate in the X.509 standard used to confirm his identity from customers (unilateral authentication).


The steps of this AKA protocol are shown in the figure below.  
![0](https://raw.githubusercontent.com/christosav/projects_security/master/AKAoverI2P/scs/0.jpg)
Alice starts messaging by sending a greeting message to Bob (step 1). Then Bob responds with a Cookie. The Cookie is a random 64-bit string (step 2). Alice creates her own Cookie and sends it to Bob along with the Cookie that she received from Step 2, adding the cryptographic suites she can support (step 3). Alice should support at least 2 symmetric encryption algorithms and at least 2 algorithms to ensureundefined integrity. The algorithms are being selected by you. Then (step 4) Bob answers 3 to Alice by sending the suites she chose (1 for integrity and 1 for confidentiality) along with her digital certificate. After Alice confirms the validity of the certificate, it continues with the creation of a random 128-bit RN alphanumeric string, or otherwise stops communicating with Bob. If there is no problem in confirming Bob's identity, Alice produces the cookie_Bob | Cookie_Alice | RN using the SHA-256 algorithm. Alice then cuts the summary into two segments and creates 2 cryptographic keys of 128 bits where one is used to ensure confidentiality of the messages and the second one to ensure integrity. Then she sends to Bob the random alphanumeric RN encrypted with the recipient's public key (Step 5a) as well as the summary undefined resulting from HMAC of cryptographic suites (Step 5b). Bob then follows the same procedure followed by Alice to create the 2 keys on his side as well, confirming the correct choice of cryptographic suites by Alice. Finally, Bob responds with a symmetrically encrypted confirmation message to Alice (Step 6). 

###### Client Screenshots

![C1](https://raw.githubusercontent.com/christosav/projects_security/master/AKAoverI2P/scs/ClientSC1.jpg)
![C2](https://raw.githubusercontent.com/christosav/projects_security/master/AKAoverI2P/scs/ClientSC2.jpg)

###### Server scseenshots

![S1](https://raw.githubusercontent.com/christosav/projects_security/master/AKAoverI2P/scs/ServerSC1.jpg)
![S2](https://raw.githubusercontent.com/christosav/projects_security/master/AKAoverI2P/scs/ServerSC2.jpg)
![S3](https://raw.githubusercontent.com/christosav/projects_security/master/AKAoverI2P/scs/ServerSC3.jpg)
