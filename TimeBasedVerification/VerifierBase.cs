// TimeBasedVerification (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2022 Evan Overman (https://github.com/an-prata)
// Licensed under the MIT License.

using System.Security.Cryptography;

using static TimeBasedVerification.BitwiseHelpers.ByteArrays;
using static TimeBasedVerification.BitwiseHelpers.HumanReadable;
using static TimeBasedVerification.BitwiseHelpers.UnsignedNumericals;

namespace TimeBasedVerification
{
	/// <summary>
	/// This class can be used to create and check verification codes based on the time,
	/// because this class does not round or shift the time in any way the likelyhood of
	/// a program getting the code before its invalid is near 0. Because of this you 
	/// should either use one of the other classes to make and check codes, or use an
	/// overload of MakeVerificationCode() and CheckVerificationCode() that will allow 
	/// you to get either the preimage or image bytes variables and add your own 
	/// tolerances to the difference between them, e.g. getting the preimage and 
	/// bitshifting it to the right x times, this way the small time difference in making
	/// and decrypting the code can be accounted for.
	/// </summary>
	public class Verifier : IDisposable
	{
		private bool disposed = false;

		/// <summary>
		/// Whether or not this class is being used as a client,
		/// since only clients should hold private keys this 
		/// can also be used to indicate whether or not
		/// CryptoServiceProvider contains private data.
		/// </summary>
		public bool IsClient { get; private set; }

		/// <summary>
		/// The CryptoServiceProvider used to create and verify
		/// time based codes.
		/// </summary>
		public RSACryptoServiceProvider CryptoServiceProvider { get; private set; }

		public static ulong GetCurrentElapsedSeconds()
		{
			DateTime centuryBegin = new(2001, 1, 1);
			DateTime currentDate = DateTime.Now;
			return (ulong)(currentDate.Second - centuryBegin.Second);
		}

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
			ulong preimage = GetCurrentElapsedSeconds();
			byte[] imageBytes = ToBytes(preimage);

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
			ulong preimage = GetCurrentElapsedSeconds();
			byte[] imageBytes = ToBytes(preimage);

			code = encrypted ? CryptoServiceProvider.Encrypt(imageBytes, true) : imageBytes;

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
		/// The unencrypted code.
		/// </param>
		/// 
		/// <returns>
		/// The encrypted and time-based verification code that
		/// was created.
		/// </returns>
		public VerificationCode MakeVerificationCode(out ulong code)
		{
			ulong preimage = GetCurrentElapsedSeconds();
			byte[] imageBytes = ToBytes(preimage);
			code = preimage;

			return new VerificationCode
			{
				KeyLength = CryptoServiceProvider.KeySize,
				Code = CryptoServiceProvider.Encrypt(imageBytes, true)
			};
		}

		/// <summary>
        /// Creates a verification code based on the current time
        /// and then encrypts it. To make the code human readable
        /// it is encrypted without padding which can lead to a
        /// lower level of security.
        /// </summary>
        /// 
        /// <returns>
        /// The encrypted and time-based verification code that
        /// was created.
        /// </returns>
        public HumanReadableVerificationCode MakeHumanReadableVerificationCode()
        {
            ulong preimage = GetCurrentElapsedSeconds();
            byte[] imageBytes = ToBytes(preimage);
            ulong numericCode = ToUlong(CryptoServiceProvider.Encrypt(imageBytes, false));

            return new HumanReadableVerificationCode
            {
                KeyLength = CryptoServiceProvider.KeySize,
                Code = MakeHumanReadable(numericCode)
            };
        }

        /// <summary>
        /// Creates a verification code based on the current time
        /// and then encrypts it. To make the code human readable
        /// it is encrypted without padding which can lead to a
        /// lower level of security.
        /// </summary>
        /// 
        /// <param name="code">
        /// A byte array to be assigned to the unencrypted
        /// verification code.
        /// </param>
        /// 
        /// <returns>
        /// The encrypted and time-based verification code that
        /// was created.
        /// </returns>
        public HumanReadableVerificationCode MakeHumanReadableVerificationCode(out byte[] code)
        {
            ulong preimage = GetCurrentElapsedSeconds();
            byte[] imageBytes = ToBytes(preimage);

            code = imageBytes;

            ulong numericCode = ToUlong(CryptoServiceProvider.Encrypt(imageBytes, false));

            return new HumanReadableVerificationCode
            {
                KeyLength = CryptoServiceProvider.KeySize,
                Code = MakeHumanReadable(numericCode)
            };
        }

        /// <summary>
        /// Creates a verification code based on the current time
        /// and then encrypts it. To make the code human readable
        /// it is encrypted without padding which can lead to a
        /// lower level of security.
        /// </summary>
        /// 
        /// <param name="code">
        /// The unencrypted code.
        /// </param>
        /// 
        /// <returns>
        /// The encrypted and time-based verification code that
        /// was created.
        /// </returns>
        public HumanReadableVerificationCode MakeHumanReadableVerificationCode(out ulong code)
        {
            ulong preimage = GetCurrentElapsedSeconds();
            byte[] imageBytes = ToBytes(preimage);

			code = preimage;

            ulong numericCode = ToUlong(CryptoServiceProvider.Encrypt(imageBytes, false));

            return new HumanReadableVerificationCode
            {
                KeyLength = CryptoServiceProvider.KeySize,
                Code = MakeHumanReadable(numericCode)
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

			try 
			{ 
				byte[] imageBytes = CryptoServiceProvider.Decrypt(code.Code, true);
				ulong preimage = ToUlong(imageBytes);
				return preimage == GetCurrentElapsedSeconds(); 
			}
			catch (CryptographicException) { throw; }
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

			try 
			{ 
				byte[] imageBytes = CryptoServiceProvider.Decrypt(code.Code, true); 
				ulong preimage = ToUlong(imageBytes);

				decryptedCode = imageBytes;
				return preimage == GetCurrentElapsedSeconds();
			}
			catch (CryptographicException) { throw; }
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

			try 
			{ 
				byte[] imageBytes = CryptoServiceProvider.Decrypt(code.Code, true);
				ulong preimage = ToUlong(imageBytes);

				decryptedCode = preimage;
				return preimage == GetCurrentElapsedSeconds();
			}
			catch (CryptographicException) { throw; }
		}

		/// <summary>
		/// Creates a new instance of the Verifier class.
		/// It's recommended that you use VerifierShifted or
		/// VerifierRounded instead as they allow a small
		/// tolerance in the amount of time between creating
		/// and checking a verification code. In all likely
		/// hood this class is unusable in most cases.
		/// </summary>
		/// 
		/// <param name="encryptionKey">
		/// An RSAParameters object that contains the public
		/// or private key used by the Verifier class. 
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
		public Verifier(RSAParameters parameters, int keySize, bool isClient)
		{
			IsClient = isClient;
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

		~Verifier() => Dispose(false);
	}
}

// VerifierBase.cs (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2022 Evan Overman (https://github.com/an-prata)