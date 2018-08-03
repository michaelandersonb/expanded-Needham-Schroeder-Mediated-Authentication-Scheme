The code is organized into 4 java projects

1. NSMAuthAlice: The client program that connects to NSMAuthKDC and NSMAuthBob
2. NSMAuthKDC: The KDC which creates tickets for Bob when requested from NSMAuthAlice
3. NSMAuthBob: The server which authenticates NSMAuthAlice using a ticket from NSMAuthKDC
4. NSMAuthTrudy: Attacker which uses ECB basic authentication to execute a reflection attack on Bob to impersonate Alice using a snooped authentication message

Alice, Bob, and the KDC both take 2 arguments. The first argument specifies the 3des encryption mode (cbc|ecb) and the second argument specifies the authentication mode (basic|advanced). All three programs must be run with the same arguments and the KDC and Bob must be run first.

Trudy can only run when the Server is running in ecb basic mode.
