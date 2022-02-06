// TimeBasedVerification (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2022 Evan Overman (https://github.com/an-prata)
// Licensed under the MIT License.

namespace TimeBasedVerification
{
    public struct HumanReadableVerificationCode
    {
        /// <summary>
        /// The length of the key used to encrypt the code.
        /// </summary>
        public int KeyLength { get; set; }

        /// <summary>
        /// The code made with MakeHumanReadableVerificationCode.
        /// </summary>
        public string Code { get; set; }
    }
}

// HumanReadableVerificationCode.cs (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2022 Evan Overman (https://github.com/an-prata)