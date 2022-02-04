// TimeBasedVerification (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2022 Evan Overman (https://github.com/an-prata)
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Security.Cryptography;
using Xunit;

namespace TimeBasedVerification.Tests
{
    public class VerifierTests
    {
        [Fact]
        public void CodeEncryptionTest()
        {
            const int keySize = 2048;

            RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
            Verifier verifier = new(cryptoServiceProvider.ExportParameters(true), keySize, true);
            VerificationCode verificationCode = verifier.MakeVerificationCode(out byte[] preimageBytes, false);

            verifier.CheckVerificationCode(verificationCode, out byte[] decryptedCodeBytes);
            verifier.Dispose();

            ulong preimage = 0, decryptedCode = 0;

            for (int i = 0; i < 8; i++)
            {
                int currentByte = i * 8;                                // Gets the distance between the desired byte and it's first binary digit in bits.
                ulong image = (ulong)(preimageBytes[i] << currentByte); // Gets the value of the desired byte and shifts it to the desired location.
                preimage |= image;                                      // Adds the desired byte to preimage.
            }

            for (int i = 0; i < 8; i++)
            {
                int currentByte = i * 8;                                        // Gets the distance between the desired byte and it's first binary digit in bits.
                ulong image = (ulong)(decryptedCodeBytes[i] << currentByte);    // Gets the value of the desired byte and shifts it to the desired location.
                decryptedCode |= image;                                         // Adds the desired byte to preimage.
            }

            Assert.Equal(preimage, decryptedCode);
            Assert.NotEqual(verificationCode.Code, decryptedCodeBytes);
        }

        [Fact]
        public void CodeVerificationTest()
        {
            const int keySize = 2048;

            const ulong mask = 0b_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_0000_0000;

            RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
            Verifier verifier0 = new(cryptoServiceProvider.ExportParameters(false), keySize, false);

            VerificationCode verificationCode = verifier0.MakeVerificationCode(out ulong code);
            verifier0.Dispose();

            Verifier verifier1 = new(cryptoServiceProvider.ExportParameters(true), keySize, true);

            // Since the class counts on seconds this will change the value it produces to check the code, making them unequal.
            Thread.Sleep(2000); 

            // Checks the values without tolerance to time, should be false.
            Assert.False(verifier1.CheckVerificationCode(verificationCode, out ulong decryptedCode));   
            verifier1.Dispose();

            // Applies a tolerance to time differences using the mask.
            Assert.Equal(code & mask, decryptedCode & mask);    
        }

        [Fact]
        public void LateCodeVerificationTest()
        {
            const int keySize = 2048;

            RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
            Verifier verifier0 = new(cryptoServiceProvider.ExportParameters(false), keySize, false);

            VerificationCode verificationCode = verifier0.MakeVerificationCode();
            verifier0.Dispose();

            // VerifierBase has a very low tolerance for latency between code creation and verification
            // because of this, without applying tolerances to the values and checking them manualy
            // they will become invalid in just a second.
            Thread.Sleep(1000); 
            Verifier verifier1 = new(cryptoServiceProvider.ExportParameters(true), keySize, true);
            Assert.False(verifier1.CheckVerificationCode(verificationCode));
            
            verifier1.Dispose();
        }

        [Fact]
        public void PrivateDataCheckTest()
        {
            const int keySize = 2048;

            RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
            Verifier verifier = new(cryptoServiceProvider.ExportParameters(false), keySize, false);
            VerificationCode verificationCode = verifier.MakeVerificationCode();
            Assert.Throws<CryptographicException>(() => verifier.CheckVerificationCode(verificationCode));
            verifier.Dispose();
        }

        [Fact]
        public void DisposeTest()
        {
            const int keySize = 2048;

            RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
            Verifier verifier = new(cryptoServiceProvider.ExportParameters(true), keySize, true);
            VerificationCode verificationCode = verifier.MakeVerificationCode();
            verifier.CheckVerificationCode(verificationCode);
            verifier.Dispose();

            Assert.Throws<ObjectDisposedException>(() => verifier.MakeVerificationCode());
            Assert.Throws<ObjectDisposedException>(() => verifier.CheckVerificationCode(verificationCode));
        }
    }
}

// VerifierTests.cs (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2022 Evan Overman (https://github.com/an-prata)