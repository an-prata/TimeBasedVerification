// TimeBasedVerification (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2022 Evan Overman (https://github.com/an-prata)
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Security.Cryptography;
using Xunit;

namespace TimeBasedVerification.Tests
{
    public class TolerantVerifierTests
    {
        private ulong ApplyTolerance(ulong code)
        {
            const ulong mask = 0b_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_0000_0000;
            return code & mask;
        }

        [Fact]
        public void CodeEncryptionTest()
        {
            const int keySize = 2048;

            RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
            TolerantVerifier verifier = new(cryptoServiceProvider.ExportParameters(true), keySize, true, ApplyTolerance);
            VerificationCode verificationCode = verifier.MakeVerificationCode(out byte[] preimageBytes, false);

            Assert.True(verifier.CheckVerificationCode(verificationCode, out byte[] decryptedCodeBytes));

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

            RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
            TolerantVerifier verifier0 = new(cryptoServiceProvider.ExportParameters(false), keySize, false, ApplyTolerance);

            VerificationCode verificationCode = verifier0.MakeVerificationCode(out ulong code);
            verifier0.Dispose();

            TolerantVerifier verifier1 = new(cryptoServiceProvider.ExportParameters(true), keySize, true, ApplyTolerance);
            Assert.True(verifier1.CheckVerificationCode(verificationCode, out ulong decryptedCode));
            verifier1.Dispose();
        }

        [Fact]
        public void LateCodeVerificationTest()
        {
            const int keySize = 2048;

            RSACryptoServiceProvider cryptoServiceProvider = new(keySize);

            TolerantVerifier verifier0 = new(cryptoServiceProvider.ExportParameters(false), keySize, false, ApplyTolerance);
            VerificationCode verificationCode = verifier0.MakeVerificationCode();

            verifier0.Dispose();
            Thread.Sleep(1000); 

            TolerantVerifier verifier1 = new(cryptoServiceProvider.ExportParameters(true), keySize, true, ApplyTolerance);
            Assert.True(verifier1.CheckVerificationCode(verificationCode));

            verifier1.Dispose();
        }

        [Fact]
        public void PrivateDataCheckTest()
        {
            const int keySize = 2048;

            RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
            TolerantVerifier verifier = new(cryptoServiceProvider.ExportParameters(false), keySize, false, ApplyTolerance);
            VerificationCode verificationCode = verifier.MakeVerificationCode();
            Assert.Throws<CryptographicException>(() => verifier.CheckVerificationCode(verificationCode));
            verifier.Dispose();
        }

        [Fact]
        public void DisposeTest()
        {
            const int keySize = 2048;

            RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
            TolerantVerifier verifier = new(cryptoServiceProvider.ExportParameters(true), keySize, true, ApplyTolerance);
            VerificationCode verificationCode = verifier.MakeVerificationCode();
            verifier.CheckVerificationCode(verificationCode);
            verifier.Dispose();

            Assert.Throws<ObjectDisposedException>(() => verifier.MakeVerificationCode());
            Assert.Throws<ObjectDisposedException>(() => verifier.CheckVerificationCode(verificationCode));
        }
    }
}

// TolerantVerifierTests.cs (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2022 Evan Overman (https://github.com/an-prata)