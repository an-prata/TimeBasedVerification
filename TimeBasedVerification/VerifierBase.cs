// TimeBasedVerification (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2021 Evan Overman (https://github.com/an-prata)
// Licensed under the MIT License.

using System;
using System.Security.Cryptography;

namespace TimeBasedVerification
{
	public class VerifierBase
	{
		private const ulong byteMask = 0b_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_1111_1111;

		/// <summary>
		/// Whether or not this class is being used as a client,
		/// since only clients should hold private keys this 
		/// can also be used to indicate whether or not
		/// CryptoServiceProvider contains private data.
		/// </summary>
		public bool IsClient { get; private set; }

		/// <summary>
		/// The DateTime struct used to get ticks since 
		/// Midnight, January 1, 2001 in Universal Time.
		/// </summary>
		public DateTime Time { get; }

		/// <summary>
		/// The CryptoServiceProvider used to create and verify
		/// time based codes.
		/// </summary>
		public RSACryptoServiceProvider CryptoServiceProvider { get; private set; }

		/// <summary>
		/// Creates a verification code based on teh current time
		/// and then encrypts it.
		/// </summary>
		/// 
		/// <returns>
		/// The encrypted and time-based verification code that
		/// was created.
		/// </returns>
		public VerificationCode MakeVerificationCode()
		{
			ulong preimage = (ulong)Time.Ticks;
			byte[] imageBytes = new byte[8];

			// Takes 64-bit ulong preimage and makes it a byte array of length 8
			// so that imageBytes[0] is the first 8 bits of preimage and imageBytes[2]
			// is the second 8 bits etc.
			for (int i = 0; i < 8; i++)
			{
				int currentByte = 8 * i;							// Gets the distance between the desired byte and it's first binary digit in bits.
				ulong currentByteMask = byteMask << currentByte;	// Creates a mask in which the desired byte is 1111_1111.
				ulong image = preimage & currentByteMask;			// Applies the mask so that image is set to 0 everywhere except the desired byte.
				imageBytes[i] = (byte)(image >> currentByte);		// Shifts image so that the desired byte is first and adds it to the array.
			}

			return new VerificationCode 
			{ 
				KeyLength = CryptoServiceProvider.KeySize, 
				Code = CryptoServiceProvider.Encrypt(imageBytes, true) 
			}; 
		}

		/// <summary>
		/// Checks if the encrypted code is valid by decrypting
		/// it and comparing to the time.
		/// </summary>
		/// 
		/// <param name="code">
		/// The code to check.
		/// </param>
		/// 
		/// <returns>
		/// True if code is valid.
		/// </returns>
		public bool CheckVerificationCode(VerificationCode code)
		{
			if (!IsClient) throw new CryptographicException("No private key present for decryption.");
			if (code.KeyLength != CryptoServiceProvider.KeySize) throw new CryptographicException("Key sizes don't match.");

			byte[] imageBytes;
			ulong preimage = 0;

			try { imageBytes = CryptoServiceProvider.Decrypt(code.Code, true); }
			catch (CryptographicException) { throw; }

			for (int i = 0; i < 8; i++)
			{
				int currentByte = i * 8;								// Gets the distance between the desired byte and it's first binary digit in bits.
				ulong image = (ulong)(imageBytes[i] << currentByte);	// Gets the value of the desired byte and shifts it to the desired location.
				preimage |= image;										// Adds the desired byte to preimage.
			}															// NOTE: The mask can be omitted since none of the values are more than 8 bits.

			return preimage == (ulong)Time.Ticks;
		}

		/// <summary>
		/// Checks if the encrypted code is valid by decrypting
		/// it and comparing to the time.
		/// </summary>
		/// 
		/// <param name="code">
		/// The code to check.
		/// </param>
		/// 
		/// <param name="decryptedCode">
		/// A byte array that will be assigned to the code
		/// after it has been decrypted.
		/// </param>
		/// 
		/// <returns>
		/// True if code is valid.
		/// </returns>
		public bool CheckVerificationCode(VerificationCode code, out byte[] decryptedCode)
		{
			if (!IsClient) throw new CryptographicException("No private key present for decryption.");
			if (code.KeyLength != CryptoServiceProvider.KeySize) throw new CryptographicException("Key sizes don't match.");

			byte[] imageBytes;
			ulong preimage = 0;

			try { imageBytes = CryptoServiceProvider.Decrypt(code.Code, true); }
			catch (CryptographicException) { throw; }

			for (int i = 0; i < 8; i++)
			{
				int currentByte = i * 8;								// Gets the distance between the desired byte and it's first binary digit in bits.
				ulong image = (ulong)(imageBytes[i] << currentByte);	// Gets the value of the desired byte and shifts it to the desired location.
				preimage |= image;										// Adds the desired byte to preimage.
			}															// NOTE: The mask can be omitted since none of the values are more than 8 bits.

			decryptedCode = imageBytes;
			return preimage == (ulong)Time.Ticks;
		}

		/// <summary>
		/// Checks if the encrypted code is valid by decrypting
		/// it and comparing to the time.
		/// </summary>
		/// 
		/// <param name="code">
		/// The code to check.
		/// </param>
		/// 
		/// <param name="decryptedCode">
		/// A ulong that will be assigned the preimage.
		/// </param>
		/// 
		/// <returns>
		/// True if code is valid.
		/// </returns>
		public bool CheckVerificationCode(VerificationCode code, out ulong decryptedCode)
		{
			if (!IsClient) throw new CryptographicException("No private key present for decryption.");
			if (code.KeyLength != CryptoServiceProvider.KeySize) throw new CryptographicException("Key sizes don't match.");

			byte[] imageBytes;
			ulong preimage = 0;

			try { imageBytes = CryptoServiceProvider.Decrypt(code.Code, true); }
			catch (CryptographicException) { throw; }

			for (int i = 0; i < 8; i++)
			{
				int currentByte = i * 8;								// Gets the distance between the desired byte and it's first binary digit in bits.
				ulong image = (ulong)(imageBytes[i] << currentByte);	// Gets the value of the desired byte and shifts it to the desired location.
				preimage |= image;										// Adds the desired byte to preimage.
			}															// NOTE: The mask can be omitted since none of the values are more than 8 bits.

			decryptedCode = preimage;
			return preimage == (ulong)Time.Ticks;
		}

		/// <summary>
		/// Creates a new instance of the VerifierBase class.
		/// It's recommended that you use VerifierShifted or
		/// VerifierRounded instead as they allow a small
		/// tolerance in the amount of time between creating
		/// and checking a verification code. In all likely
		/// hood this class is unusable in most cases.
		/// </summary>
		/// 
		/// <param name="encryptionKey">
		/// An RSAParameters object that contains the public
		/// or private key used by the VerifierBase class. 
		/// </param>
		/// 
		/// <param name="keySize">
		/// The size of the public or private key given in
		/// parameters.
		/// </param>
		/// 
		/// <param name="isClient">
		/// Should be true if the encryptionKey encludes
		/// private data as only the client should have a 
		/// private key.
		/// </param>
		public VerifierBase(RSAParameters parameters, int keySize, bool isClient)
		{
			IsClient = isClient;
			Time = new DateTime(0, DateTimeKind.Utc);
			CryptoServiceProvider = new RSACryptoServiceProvider(keySize);
			CryptoServiceProvider.ImportParameters(parameters);
		}
	}
}

