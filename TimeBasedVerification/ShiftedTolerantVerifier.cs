// TimeBasedVerification (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2021 Evan Overman (https://github.com/an-prata)
// Licensed under the MIT License.

using System.Security.Cryptography;

namespace TimeBasedVerification
{
    /// <summary>
    /// This class can be used to create and check verification codes based on the time,
    /// it takes an optional unsigned integer as a parameter in the constructor that will 
    /// used to shift the code that many times to the right. An option boolean parameter 
    /// can be used to make it shift back and make that many bits 0. This unsigned integer 
    /// can be overiden withoverides of CheckVerificationCode() to use the same class for 
    /// multiple different right shift operations.
    /// </summary>
    public class ShiftedTolerantVerifier : IDisposable
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
        /// The CryptoServiceProvider used to create and verify
        /// time based codes.
        /// </summary>
        public RSACryptoServiceProvider CryptoServiceProvider { get; private set; }

        private readonly int _shift;

        private readonly bool _shiftBack;

        private static ulong ApplyTolerance(ulong image, int shift, bool shiftBack)
        {
            ulong shiftedImage = image >> shift;
            if (!shiftBack) return shiftedImage;
            return shiftedImage << shift;
        }

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
            byte[] imageBytes = new byte[8];

            // Takes 64-bit ulong preimage and makes it a byte array of length 8
            // so that imageBytes[0] is the first 8 bits of preimage and imageBytes[2]
            // is the second 8 bits etc.
            for (int i = 0; i < 8; i++)
            {
                int currentByte = 8 * i;                            // Gets the distance between the desired byte and it's first binary digit in bits.
                ulong currentByteMask = byteMask << currentByte;    // Creates a mask in which the desired byte is 1111_1111.
                ulong image = preimage & currentByteMask;           // Applies the mask so that image is set to 0 everywhere except the desired byte.
                imageBytes[i] = (byte)(image >> currentByte);       // Shifts image so that the desired byte is first and adds it to the array.
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
            ulong preimage = GetCurrentElapsedSeconds();
            byte[] imageBytes = new byte[8];

            // Takes 64-bit ulong preimage and makes it a byte array of length 8
            // so that imageBytes[0] is the first 8 bits of preimage and imageBytes[2]
            // is the second 8 bits etc.
            for (int i = 0; i < 8; i++)
            {
                int currentByte = 8 * i;                            // Gets the distance between the desired byte and it's first binary digit in bits.
                ulong currentByteMask = byteMask << currentByte;    // Creates a mask in which the desired byte is 1111_1111.
                ulong image = preimage & currentByteMask;           // Applies the mask so that image is set to 0 everywhere except the desired byte.
                imageBytes[i] = (byte)(image >> currentByte);       // Shifts image so that the desired byte is first and adds it to the array.
            }

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
            code = preimage;
            byte[] imageBytes = new byte[8];

            // Takes 64-bit ulong preimage and makes it a byte array of length 8
            // so that imageBytes[0] is the first 8 bits of preimage and imageBytes[2]
            // is the second 8 bits etc.
            for (int i = 0; i < 8; i++)
            {
                int currentByte = 8 * i;                            // Gets the distance between the desired byte and it's first binary digit in bits.
                ulong currentByteMask = byteMask << currentByte;    // Creates a mask in which the desired byte is 1111_1111.
                ulong image = preimage & currentByteMask;           // Applies the mask so that image is set to 0 everywhere except the desired byte.
                imageBytes[i] = (byte)(image >> currentByte);       // Shifts image so that the desired byte is first and adds it to the array.
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
            ulong preimage = 0b_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000;

            try { imageBytes = CryptoServiceProvider.Decrypt(code.Code, true); }
            catch (CryptographicException) { throw; }

            for (int i = 0; i < 8; i++)
            {
                int currentByte = i * 8;                                // Gets the distance between the desired byte and it's first binary digit in bits.
                ulong image = ((ulong)imageBytes[i]) << currentByte;    // Gets the value of the desired byte and shifts it to the desired location.
                preimage |= image;                                      // Adds the desired byte to preimage.
            }                                                           // NOTE: The mask can be omitted since none of the values are more than 8 bits.

            return ApplyTolerance(preimage, _shift, _shiftBack) == ApplyTolerance(GetCurrentElapsedSeconds(), _shift, _shiftBack);
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
                int currentByte = i * 8;                                // Gets the distance between the desired byte and it's first binary digit in bits.
                ulong image = ((ulong)imageBytes[i]) << currentByte;    // Gets the value of the desired byte and shifts it to the desired location.
                preimage |= image;                                      // Adds the desired byte to preimage.
            }                                                           // NOTE: The mask can be omitted since none of the values are more than 8 bits.

            decryptedCode = imageBytes;
            return ApplyTolerance(preimage, _shift, _shiftBack) == ApplyTolerance(GetCurrentElapsedSeconds(), _shift, _shiftBack);
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
                int currentByte = i * 8;                                // Gets the distance between the desired byte and it's first binary digit in bits.
                ulong image = ((ulong)imageBytes[i]) << currentByte;    // Gets the value of the desired byte and shifts it to the desired location.
                preimage |= image;                                      // Adds the desired byte to preimage.
            }                                                           // NOTE: The mask can be omitted since none of the values are more than 8 bits.

            decryptedCode = preimage;
            return ApplyTolerance(preimage, _shift, _shiftBack) == ApplyTolerance(GetCurrentElapsedSeconds(), _shift, _shiftBack);
        }

        /// <summary>
        /// Checks if the encrypted code is valid by decrypting
        /// it and comparing to the time using the shift and
        /// shiftback parameters provided.
        /// </summary>
        /// 
        /// <param name="code">
        /// The code to check.
        /// </param>
        /// 
        /// <param name="shift">
        /// The second operand in the right shift operation to
        /// performed to add tolerance to the code check.
        /// </param>
        /// 
        /// <param name="shiftBack">
        /// Whether or not to shift the code back by int shift
        /// and replace bits with 0.
        /// </param>
        /// 
        /// <returns>
        /// True if code is valid.
        /// </returns>
        public bool CheckVerificationCode(VerificationCode code, int shift, bool shiftBack = false)
        {
            if (!IsClient) throw new CryptographicException("No private key present for decryption.");
            if (code.KeyLength != CryptoServiceProvider.KeySize) throw new CryptographicException("Key sizes don't match.");

            byte[] imageBytes;
            ulong preimage = 0b_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000;

            try { imageBytes = CryptoServiceProvider.Decrypt(code.Code, true); }
            catch (CryptographicException) { throw; }

            for (int i = 0; i < 8; i++)
            {
                int currentByte = i * 8;                                // Gets the distance between the desired byte and it's first binary digit in bits.
                ulong image = ((ulong)imageBytes[i]) << currentByte;    // Gets the value of the desired byte and shifts it to the desired location.
                preimage |= image;                                      // Adds the desired byte to preimage.
            }                                                           // NOTE: The mask can be omitted since none of the values are more than 8 bits.


            return ApplyTolerance(preimage, shift, shiftBack) == ApplyTolerance(GetCurrentElapsedSeconds(), shift, shiftBack);
        }

        /// <summary>
        /// Checks if the encrypted code is valid by decrypting
        /// it and comparing to the time using the shift and
        /// shiftback parameters provided.
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
        /// <param name="shift">
        /// The second operand in the right shift operation to
        /// performed to add tolerance to the code check.
        /// </param>
        /// 
        /// <param name="shiftBack">
        /// Whether or not to shift the code back by int shift
        /// and replace bits with 0.
        /// </param>
        /// 
        /// <returns>
        /// True if code is valid.
        /// </returns>
        public bool CheckVerificationCode(VerificationCode code, out byte[] decryptedCode, int shift, bool shiftBack = false)
        {
            if (!IsClient) throw new CryptographicException("No private key present for decryption.");
            if (code.KeyLength != CryptoServiceProvider.KeySize) throw new CryptographicException("Key sizes don't match.");

            byte[] imageBytes;
            ulong preimage = 0;

            try { imageBytes = CryptoServiceProvider.Decrypt(code.Code, true); }
            catch (CryptographicException) { throw; }

            for (int i = 0; i < 8; i++)
            {
                int currentByte = i * 8;                                // Gets the distance between the desired byte and it's first binary digit in bits.
                ulong image = ((ulong)imageBytes[i]) << currentByte;    // Gets the value of the desired byte and shifts it to the desired location.
                preimage |= image;                                      // Adds the desired byte to preimage.
            }                                                           // NOTE: The mask can be omitted since none of the values are more than 8 bits.

            decryptedCode = imageBytes;
            return ApplyTolerance(preimage, shift, shiftBack) == ApplyTolerance(GetCurrentElapsedSeconds(), shift, shiftBack);
        }

        /// <summary>
        /// Checks if the encrypted code is valid by decrypting
        /// it and comparing to the time using the shift and
        /// shiftback parameters provided.
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
        /// <param name="shift">
        /// The second operand in the right shift operation to
        /// performed to add tolerance to the code check.
        /// </param>
        /// 
        /// <param name="shiftBack">
        /// Whether or not to shift the code back by int shift
        /// and replace bits with 0.
        /// </param>
        /// 
        /// <returns>
        /// True if code is valid.
        /// </returns>
        public bool CheckVerificationCode(VerificationCode code, out ulong decryptedCode, int shift, bool shiftBack = false)
        {
            if (!IsClient) throw new CryptographicException("No private key present for decryption.");
            if (code.KeyLength != CryptoServiceProvider.KeySize) throw new CryptographicException("Key sizes don't match.");

            byte[] imageBytes;
            ulong preimage = 0;

            try { imageBytes = CryptoServiceProvider.Decrypt(code.Code, true); }
            catch (CryptographicException) { throw; }

            for (int i = 0; i < 8; i++)
            {
                int currentByte = i * 8;                                // Gets the distance between the desired byte and it's first binary digit in bits.
                ulong image = ((ulong)imageBytes[i]) << currentByte;    // Gets the value of the desired byte and shifts it to the desired location.
                preimage |= image;                                      // Adds the desired byte to preimage.
            }                                                           // NOTE: The mask can be omitted since none of the values are more than 8 bits.

            decryptedCode = preimage;
            return ApplyTolerance(preimage, shift, shiftBack) == ApplyTolerance(GetCurrentElapsedSeconds(), shift, shiftBack);
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
        /// <param name="shift">
        /// The second operand in the right shift operation to
        /// performed to add tolerance to the code check.
        /// </param>
        /// 
        /// <param name="isClient">
        /// Should be true if the encryptionKey encludes
        /// private data as only the client should have a 
        /// private key.
        /// </param>
        /// 
        /// <param name="shiftBack">
        /// Whether or not to shift the code back by int shift
        /// and replace bits with 0.
        /// </param>
        public ShiftedTolerantVerifier(RSAParameters parameters, int keySize, int shift, bool isClient, bool shiftBack = false)
        {
            IsClient = isClient;
            _shift = shift;
            _shiftBack = shiftBack;

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

        ~ShiftedTolerantVerifier() => Dispose(false);
    }
}