// TimeBasedVerification (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2022 Evan Overman (https://github.com/an-prata)
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Security.Cryptography;
using Xunit;

namespace TimeBasedVerification.Tests
{
    public class ShiftedTolerantVerifierTests
    {
        [Theory]
        [InlineData(4, false)]
        [InlineData(8, false)]
        [InlineData(4, true)]
        [InlineData(8, true)]
        public void CodeEncryptionTest(int shift, bool shiftBack)
        {
            const int keySize = 2048;

            RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
            ShiftedTolerantVerifier verifier = new(cryptoServiceProvider.ExportParameters(true), keySize, shift, true, shiftBack);
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

        [Theory]
        [InlineData(4, false)]
        [InlineData(8, false)]
        [InlineData(4, true)]
        [InlineData(8, true)]
        public void CodeVerificationTest(int shift, bool shiftBack)
        {
            const int keySize = 2048;

            RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
            ShiftedTolerantVerifier verifier0 = new(cryptoServiceProvider.ExportParameters(true), keySize, shift, true, shiftBack);

            VerificationCode verificationCode = verifier0.MakeVerificationCode();
            verifier0.Dispose();

            ShiftedTolerantVerifier verifier1 = new(cryptoServiceProvider.ExportParameters(true), keySize, shift, true, shiftBack);
            Assert.True(verifier1.CheckVerificationCode(verificationCode));
            verifier1.Dispose();
        }

        [Theory]
        [InlineData(4, false)]
        [InlineData(8, false)]
        [InlineData(4, true)]
        [InlineData(8, true)]
        public void LateCodeVerificationTest(int shift, bool shiftBack)
        {
            const int keySize = 2048;

            RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
            ShiftedTolerantVerifier verifier0 = new(cryptoServiceProvider.ExportParameters(false), keySize, shift, false, shiftBack);

            VerificationCode verificationCode = verifier0.MakeVerificationCode();
            verifier0.Dispose();

            Thread.Sleep(1000);
            ShiftedTolerantVerifier verifier1 = new(cryptoServiceProvider.ExportParameters(true), keySize, shift, true, shiftBack);
            Assert.True(verifier1.CheckVerificationCode(verificationCode));

            verifier1.Dispose();
        }

        [Theory]
        [InlineData(4, false)]
        [InlineData(8, false)]
        [InlineData(4, true)]
        [InlineData(8, true)]
        public void PrivateDataCheckTest(int shift, bool shiftBack)
        {
            const int keySize = 2048;

            RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
            ShiftedTolerantVerifier verifier = new(cryptoServiceProvider.ExportParameters(true), keySize, shift, false, shiftBack);
            VerificationCode verificationCode = verifier.MakeVerificationCode();
            Assert.Throws<CryptographicException>(() => verifier.CheckVerificationCode(verificationCode));
            verifier.Dispose();
        }

        [Theory]
        [InlineData(4, false)]
        [InlineData(8, false)]
        [InlineData(4, true)]
        [InlineData(8, true)]
        public void DisposeTest(int shift, bool shiftBack)
        {
            const int keySize = 2048;

            RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
            ShiftedTolerantVerifier verifier = new(cryptoServiceProvider.ExportParameters(true), keySize, shift, true, shiftBack);
            VerificationCode verificationCode = verifier.MakeVerificationCode();
            verifier.CheckVerificationCode(verificationCode);
            verifier.Dispose();

            Assert.Throws<ObjectDisposedException>(() => verifier.MakeVerificationCode());
            Assert.Throws<ObjectDisposedException>(() => verifier.CheckVerificationCode(verificationCode));
        }
    }
}