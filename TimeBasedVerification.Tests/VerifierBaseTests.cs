// TimeBasedVerification (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2021 Evan Overman (https://github.com/an-prata)
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Security.Cryptography;
using Xunit;

namespace TimeBasedVerification.Tests;

public class VerifierBaseTests
{
	[Fact]
	public void CodeEncryptionTest()
	{
		const int keySize = 2048;

		RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
		VerifierBase verifier = new(cryptoServiceProvider.ExportParameters(true), keySize, true);
		VerificationCode verificationCode = verifier.MakeVerificationCode(out byte[] preimageBytes, false);

		verifier.CheckVerificationCode(verificationCode, out byte[] decryptedCodeBytes);
		verifier.Dispose();

		ulong preimage = 0, decryptedCode = 0;

		for (int i = 0; i < 8; i++)
		{
			int currentByte = i * 8;								// Gets the distance between the desired byte and it's first binary digit in bits.
			ulong image = (ulong)(preimageBytes[i] << currentByte);	// Gets the value of the desired byte and shifts it to the desired location.
			preimage |= image;										// Adds the desired byte to preimage.
		}

		for (int i = 0; i < 8; i++)
		{
			int currentByte = i * 8;										// Gets the distance between the desired byte and it's first binary digit in bits.
			ulong image = (ulong)(decryptedCodeBytes[i] << currentByte);	// Gets the value of the desired byte and shifts it to the desired location.
			decryptedCode |= image;											// Adds the desired byte to preimage.
		}

		Assert.Equal(preimage, decryptedCode);
		Assert.NotEqual(verificationCode.Code, decryptedCodeBytes);
	}

	[Fact]
	public void CodeVerificationTest()
	{
		const int keySize = 2048;

		const ulong mask = 0b_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_0000_0000_0000_0000;

		RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
		VerifierBase verifier0 = new(cryptoServiceProvider.ExportParameters(false), keySize, false);

		VerificationCode verificationCode = verifier0.MakeVerificationCode(out ulong code);
		verifier0.Dispose();

		VerifierBase verifier1 = new(cryptoServiceProvider.ExportParameters(true), keySize, true);
		Assert.False(verifier1.CheckVerificationCode(verificationCode, out ulong decryptedCode));	// Checks the values without tolerance to time, should be false.
		verifier1.Dispose();

		Assert.Equal(code & mask, decryptedCode & mask);	// Applies a tolerance to time differences using the mask.
	}

	[Fact]
	public void LateCodeVerificationTest()
	{
		const int keySize = 2048;

		RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
		VerifierBase verifier0 = new(cryptoServiceProvider.ExportParameters(false), keySize, false);

		VerificationCode verificationCode = verifier0.MakeVerificationCode();
		verifier0.Dispose();

		Thread.Sleep(1000); // VerifierBase has a very low tolerance for latency between code creation and verification
		VerifierBase verifier1 = new(cryptoServiceProvider.ExportParameters(true), keySize, true);
		Assert.False(verifier1.CheckVerificationCode(verificationCode));	// The Outcome of this may depend on the speed of execution.
		verifier1.Dispose();
	}

	[Fact]
	public void PrivateDataCheckTest()
	{
		const int keySize = 2048;

		RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
		VerifierBase verifier = new(cryptoServiceProvider.ExportParameters(false), keySize, false);
		VerificationCode verificationCode = verifier.MakeVerificationCode();
		Assert.Throws<CryptographicException>(() => verifier.CheckVerificationCode(verificationCode));
		verifier.Dispose();
	}

	[Fact]
	public void DisposeTest()
	{
		const int keySize = 2048;

		RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
		VerifierBase verifier = new(cryptoServiceProvider.ExportParameters(true), keySize, true);
		VerificationCode verificationCode = verifier.MakeVerificationCode();
		verifier.CheckVerificationCode(verificationCode);
		verifier.Dispose();

		Assert.Throws<ObjectDisposedException>(() => verifier.MakeVerificationCode());
		Assert.Throws<ObjectDisposedException>(() => verifier.CheckVerificationCode(verificationCode));
	}
}