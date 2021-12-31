// TimeBasedVerification (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2021 Evan Overman (https://github.com/an-prata)
// Licensed under the MIT License.

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
}