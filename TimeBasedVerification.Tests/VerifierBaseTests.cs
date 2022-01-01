// TimeBasedVerification (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2021 Evan Overman (https://github.com/an-prata)
// Licensed under the MIT License.

using System;
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

		VerificationCode verificationCode = verifier.MakeVerificationCode(out ulong preimage);
		verifier.CheckVerificationCode(verificationCode, out ulong decryptedCode);
		verifier.CheckVerificationCode(verificationCode, out byte[] decryptedCodeBytes);

		Assert.Equal(preimage, decryptedCode);
		Assert.NotEqual(verificationCode.Code, decryptedCodeBytes);
	}

	[Fact]
	public void CodeVerificationTest()
	{
		const int keySize = 2048;
		RSACryptoServiceProvider cryptoServiceProvider = new(keySize);
		VerifierBase verifier0 = new(cryptoServiceProvider.ExportParameters(false), keySize, false);

		VerificationCode verificationCode = verifier0.MakeVerificationCode();
		verifier0.Dispose();

		VerifierBase verifier1 = new(cryptoServiceProvider.ExportParameters(true), keySize, true);
		Assert.True(verifier1.CheckVerificationCode(verificationCode));	// The Outcome of this may depend on the speed of execution.
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