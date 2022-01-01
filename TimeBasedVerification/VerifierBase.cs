// TimeBasedVerification (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2021 Evan Overman (https://github.com/an-prata)
// Licensed under the MIT License.

using System;
using System.Security.Cryptography;

namespace TimeBasedVerification
{
	/// <summary>
	/// This class can be used to create and check verification codes based on the time,
	/// because this class does not round or shift the time in any way the likelyhood of
	/// a program getting the code before its invalid is near 0. Because  of this you 
	/// should either use one of the other classes to make and check codes, or use an
	/// overload of MakeVerificationCode() and CheckVerificationCode() that will allow 
	/// you to get either the preimage or image bytes variables and add your own 
	/// tolerances to the difference between them, e.g. getting the preimage and 
	/// bitshifting it to the right x times, this way the small time difference in making
	/// and decrypting the code can be accounted for.
	/// </summary>
	public class VerifierBase : IDisposable
	{
		private const ulong byteMask = 0b_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_1111_1111;

		private bool disposed = false;

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
		/// Creates a verification code based on the current time
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
		/// Creates a verification code based on the current time
		/// and then encrypts it.
		/// </summary>
		/// 
		/// <param name="code">
		/// A byte array to be assigned to the verification code.
		/// </param>
		/// 
		/// <param name="encrypted">
		/// Whether or not to encrypt the byte array. Does not 
		/// effect return value as it is always encrypted.
		/// </param>
		/// 
		/// <returns>
		/// The encrypted and time-based verification code that
		/// was created.
		/// </returns>
		public VerificationCode MakeVerificationCode(out byte[] code, bool encrypted = true)
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

			code = encrypted ? CryptoServiceProvider.Encrypt(imageBytes, true) : imageBytes;

			return new VerificationCode 
			{ 
				KeyLength = CryptoServiceProvider.KeySize, 
				Code = CryptoServiceProvider.Encrypt(imageBytes, true) 
			}; 
		}

		public VerificationCode MakeVerificationCode(out ulong code)
		{
			ulong preimage = (ulong)Time.Ticks;
			code = preimage;
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
			Time = new(0, DateTimeKind.Utc);
			CryptoServiceProvider = new(keySize);
			CryptoServiceProvider.ImportParameters(parameters);
		}

		public void Dispose() 
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		} 

		protected virtual void Dispose(bool disposing)
		{
			if (!disposed)
			{
				if (disposing) CryptoServiceProvider.Dispose();
				disposed = true;
			}
		}

		~VerifierBase() => Dispose(false);
	}
}

