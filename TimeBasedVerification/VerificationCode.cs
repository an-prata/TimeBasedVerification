// TimeBasedVerification (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2021 Evan Overman (https://github.com/an-prata)
// Licensed under the MIT License.

namespace TimeBasedVerification
{
    public struct VerificationCode
    {
        /// <summary>
        /// The length of the key used to encrypt the code.
        /// </summary>
        public int KeyLength { get; set; }

        /// <summary>
        /// The code made with MakeVerificationCode.
        /// </summary>
        public byte[] Code { get; set; }
    }
}