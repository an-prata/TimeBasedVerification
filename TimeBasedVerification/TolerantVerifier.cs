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
    /// a delegate can be passed into the constructor that can be used to add tolerance.
    /// This tolerance can be bitshifting to the right to make the times of the code's
    /// creation and checking more similar, or some other way of making the times more
    /// alike, this is so that when you check the code, not so much time has passed that
    /// it is no longer valid.
    /// </summary>
    public class TolerantVerifier : IDisposable
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

        private ToleranceDelegate ApplyTolerance { get; set; }

        public delegate ulong ToleranceDelegate(ulong image);

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
                return ApplyTolerance(preimage) == ApplyTolerance(GetCurrentElapsedSeconds());
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
                return ApplyTolerance(preimage) == ApplyTolerance(GetCurrentElapsedSeconds());
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
                return ApplyTolerance(preimage) == ApplyTolerance(GetCurrentElapsedSeconds());
            }
            catch (CryptographicException) { throw; }  
        }

        /// <summary>
        /// Checks if the encrypted code is valid by decrypting
        /// it and comparing to the time using the tolerance
        /// parameter.
        /// </summary>
        /// 
        /// <param name="code">
        /// The code to check.
        /// </param>
        /// 
        /// <param name="tolerance">
        /// The delegate to be used instead of the one passed
        /// into the contructor.
        /// </param>
        /// 
        /// <returns>
        /// True if code is valid.
        /// </returns>
        public bool CheckVerificationCode(VerificationCode code, ToleranceDelegate tolerance)
        {
            if (!IsClient) throw new CryptographicException("No private key present for decryption.");
            if (code.KeyLength != CryptoServiceProvider.KeySize) throw new CryptographicException("Key sizes don't match.");

            try 
            { 
                byte[] imageBytes = CryptoServiceProvider.Decrypt(code.Code, true); 
                ulong preimage = ToUlong(imageBytes);
                return tolerance(preimage) == tolerance(GetCurrentElapsedSeconds());
            }
            catch (CryptographicException) { throw; }
        }

        /// <summary>
        /// Checks if the encrypted code is valid by decrypting
        /// it and comparing to the time using the tolerance
        /// parameter.
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
        /// <param name="tolerance">
        /// The delegate to be used instead of the one passed
        /// into the contructor.
        /// </param>
        /// 
        /// <returns>
        /// True if code is valid.
        /// </returns>
        public bool CheckVerificationCode(VerificationCode code, out byte[] decryptedCode, ToleranceDelegate tolerance)
        {
            if (!IsClient) throw new CryptographicException("No private key present for decryption.");
            if (code.KeyLength != CryptoServiceProvider.KeySize) throw new CryptographicException("Key sizes don't match.");

            try 
            { 
                byte[] imageBytes = CryptoServiceProvider.Decrypt(code.Code, true); 
                ulong preimage = ToUlong(imageBytes);

                decryptedCode = imageBytes;
                return tolerance(preimage) == tolerance(GetCurrentElapsedSeconds());
            }
            catch (CryptographicException) { throw; }
        }

        /// <summary>
        /// Checks if the encrypted code is valid by decrypting
        /// it and comparing to the time using the tolerance
        /// parameter.
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
        /// <param name="tolerance">
        /// The delegate to be used instead of the one passed
        /// into the contructor.
        /// </param>
        /// 
        /// <returns>
        /// True if code is valid.
        /// </returns>
        public bool CheckVerificationCode(VerificationCode code, out ulong decryptedCode, ToleranceDelegate tolerance)
        {
            if (!IsClient) throw new CryptographicException("No private key present for decryption.");
            if (code.KeyLength != CryptoServiceProvider.KeySize) throw new CryptographicException("Key sizes don't match.");

            try 
            { 
                byte[] imageBytes = CryptoServiceProvider.Decrypt(code.Code, true);
                ulong preimage = ToUlong(imageBytes); 

                decryptedCode = preimage;
                return tolerance(preimage) == tolerance(GetCurrentElapsedSeconds());
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
        /// <returns>
        /// True if code is valid.
        /// </returns>
        public bool CheckVerificationCode(HumanReadableVerificationCode code)
        {
            if (!IsClient) throw new CryptographicException("No private key present for decryption.");
            if (code.KeyLength != CryptoServiceProvider.KeySize) throw new CryptographicException("Key sizes don't match.");

            try 
            { 
                byte[] codeBytes = ToBytes(GetOriginalNumeric64(code.Code));
				byte[] imageBytes = CryptoServiceProvider.Decrypt(codeBytes, false); 
                ulong preimage = ToUlong(imageBytes);
                return ApplyTolerance(preimage) == ApplyTolerance(GetCurrentElapsedSeconds());
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
        public bool CheckVerificationCode(HumanReadableVerificationCode code, out byte[] decryptedCode)
        {
            if (!IsClient) throw new CryptographicException("No private key present for decryption.");
            if (code.KeyLength != CryptoServiceProvider.KeySize) throw new CryptographicException("Key sizes don't match.");

            try 
            { 
                byte[] codeBytes = ToBytes(GetOriginalNumeric64(code.Code));
				byte[] imageBytes = CryptoServiceProvider.Decrypt(codeBytes, false);  
                ulong preimage = ToUlong(imageBytes);

                decryptedCode = imageBytes;
                return ApplyTolerance(preimage) == ApplyTolerance(GetCurrentElapsedSeconds());
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
        public bool CheckVerificationCode(HumanReadableVerificationCode code, out ulong decryptedCode)
        {
            if (!IsClient) throw new CryptographicException("No private key present for decryption.");
            if (code.KeyLength != CryptoServiceProvider.KeySize) throw new CryptographicException("Key sizes don't match.");

            try 
            { 
                byte[] codeBytes = ToBytes(GetOriginalNumeric64(code.Code));
				byte[] imageBytes = CryptoServiceProvider.Decrypt(codeBytes, false);  
                ulong preimage = ToUlong(imageBytes);

                decryptedCode = preimage;
                return ApplyTolerance(preimage) == ApplyTolerance(GetCurrentElapsedSeconds());
            }
            catch (CryptographicException) { throw; }  
        }

        /// <summary>
        /// Checks if the encrypted code is valid by decrypting
        /// it and comparing to the time using the tolerance
        /// parameter.
        /// </summary>
        /// 
        /// <param name="code">
        /// The code to check.
        /// </param>
        /// 
        /// <param name="tolerance">
        /// The delegate to be used instead of the one passed
        /// into the contructor.
        /// </param>
        /// 
        /// <returns>
        /// True if code is valid.
        /// </returns>
        public bool CheckVerificationCode(HumanReadableVerificationCode code, ToleranceDelegate tolerance)
        {
            if (!IsClient) throw new CryptographicException("No private key present for decryption.");
            if (code.KeyLength != CryptoServiceProvider.KeySize) throw new CryptographicException("Key sizes don't match.");

            try 
            { 
                byte[] codeBytes = ToBytes(GetOriginalNumeric64(code.Code));
				byte[] imageBytes = CryptoServiceProvider.Decrypt(codeBytes, false);  
                ulong preimage = ToUlong(imageBytes);
                return tolerance(preimage) == tolerance(GetCurrentElapsedSeconds());
            }
            catch (CryptographicException) { throw; }
        }

        /// <summary>
        /// Checks if the encrypted code is valid by decrypting
        /// it and comparing to the time using the tolerance
        /// parameter.
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
        /// <param name="tolerance">
        /// The delegate to be used instead of the one passed
        /// into the contructor.
        /// </param>
        /// 
        /// <returns>
        /// True if code is valid.
        /// </returns>
        public bool CheckVerificationCode(HumanReadableVerificationCode code, out byte[] decryptedCode, ToleranceDelegate tolerance)
        {
            if (!IsClient) throw new CryptographicException("No private key present for decryption.");
            if (code.KeyLength != CryptoServiceProvider.KeySize) throw new CryptographicException("Key sizes don't match.");

            try 
            { 
                byte[] codeBytes = ToBytes(GetOriginalNumeric64(code.Code));
				byte[] imageBytes = CryptoServiceProvider.Decrypt(codeBytes, false);  
                ulong preimage = ToUlong(imageBytes);

                decryptedCode = imageBytes;
                return tolerance(preimage) == tolerance(GetCurrentElapsedSeconds());
            }
            catch (CryptographicException) { throw; }
        }

        /// <summary>
        /// Checks if the encrypted code is valid by decrypting
        /// it and comparing to the time using the tolerance
        /// parameter.
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
        /// <param name="tolerance">
        /// The delegate to be used instead of the one passed
        /// into the contructor.
        /// </param>
        /// 
        /// <returns>
        /// True if code is valid.
        /// </returns>
        public bool CheckVerificationCode(HumanReadableVerificationCode code, out ulong decryptedCode, ToleranceDelegate tolerance)
        {
            if (!IsClient) throw new CryptographicException("No private key present for decryption.");
            if (code.KeyLength != CryptoServiceProvider.KeySize) throw new CryptographicException("Key sizes don't match.");

            try 
            { 
                byte[] codeBytes = ToBytes(GetOriginalNumeric64(code.Code));
				byte[] imageBytes = CryptoServiceProvider.Decrypt(codeBytes, false); 
                ulong preimage = ToUlong(imageBytes); 

                decryptedCode = preimage;
                return tolerance(preimage) == tolerance(GetCurrentElapsedSeconds());
            }
            catch (CryptographicException) { throw; }
        }

        /// <summary>
        /// Creates a new instance of the TolerantVerifier class.
        /// It's recommended that you use VerifierShifted or
        /// VerifierRounded instead as they allow a small
        /// tolerance in the amount of time between creating
        /// and checking a verification code. In all likely
        /// hood this class is unusable in most cases.
        /// </summary>
        /// 
        /// <param name="encryptionKey">
        /// An RSAParameters object that contains the public
        /// or private key used by the TolerantVerifier class. 
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
        /// 
        /// <param name="tolerance">
        /// The delegate to be used to apply an amount of
        /// tolerance to the verification proccess, e.g.
        /// bit shift to the right.
        /// </param>
        public TolerantVerifier(RSAParameters parameters, int keySize, bool isClient, ToleranceDelegate tolerance)
        {
            IsClient = isClient;
            CryptoServiceProvider = new(keySize);
            CryptoServiceProvider.ImportParameters(parameters);
            ApplyTolerance = tolerance ?? throw new ArgumentException("tolerance was null: consider using Verifier.");
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

        ~TolerantVerifier() => Dispose(false);
    }
}

// TolerantVerifier.cs (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2022 Evan Overman (https://github.com/an-prata)