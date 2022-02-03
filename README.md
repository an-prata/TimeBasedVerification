# TimeBasedVerification
A simple class library to create encrypted codes based on the time to verify data or actions in a program.

This class library allows for a client device and remote device to exchange data and verify the time of the data's creation. To do this the client must produce an RSA key pair, and send the public key to the remote device. The remote device can then create a code using a non-client version of any of the Verifier classes. This code can be sent, along with data, to the client, who, using the keys from before, can decrypt and check the code to be within a certain span of time.

The code can be checked a number of ways, either using the ShiftedTolerantVerifier class to bit shift the 64-bit code any number of times to the right, cutting off binary digits, using the TolerantVerifier class to assign a delegate that makes any 2 given ulongs more similar, or taking the decrypted code itself from an overload of MakeVerificationCode from any of the Verifier classes to check if the code is valid manually.
