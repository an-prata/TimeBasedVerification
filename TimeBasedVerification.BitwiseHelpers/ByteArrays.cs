// TimeBasedVerification (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2022 Evan Overman (https://github.com/an-prata)
// Licensed under the MIT License.

namespace TimeBasedVerification.BitwiseHelpers
{
	/// <summary>
	/// Used to convert unsigned numerical types to byte arrays and vice versa.
	/// </summary>
	public static class ByteArrays
	{
		private const ushort byteMask16 = 0b_0000_0000_1111_1111;

		private const uint byteMask32 = 0b_0000_0000_0000_0000_0000_0000_1111_1111;

		private const ulong byteMask64 = 0b_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_1111_1111;

		/// <summary>
		/// Takes 16-bit ushort preimage and makes it a byte array.
		/// </summary>
		/// 
		/// <param name="preimage">
		/// A ushort to turn into a byte[].
		/// </param>
		/// 
		/// <returns>
		/// A byte array of length 2 so that index 0 is the first 8 bits of 
		/// preimage and index 1 is the second 8 bits.
		/// </returns>
		public static byte[] ToBytes(ushort preimage)
		{
			byte[] imageBytes = new byte[2];

            for (int i = 0; i < 2; i++)
            {
				// Gets the distance between the desired byte and it's first binary digit in bits.
                int currentByte = 8 * i;

				// Creates a mask in which the desired byte is 1111_1111.
                ushort currentByteMask = (ushort)(byteMask16 << currentByte);

				// Applies the mask so that image is set to 0 everywhere except the desired byte.
                ushort image = (ushort)(preimage & currentByteMask);

				// Shifts image so that the desired byte is first and adds it to the array.
				imageBytes[i] = (byte)(image >> currentByte);
            }

			return imageBytes;
		}

		/// <summary>
		/// Takes 32-bit uint preimage and makes it a byte array.
		/// </summary>
		/// 
		/// <param name="preimage">
		/// A uint to turn into a byte[].
		/// </param>
		/// 
		/// <returns>
		/// A byte array of length 4 so that index 0 is the first 8 bits of 
		/// preimage and index 1 is the second 8 bits etc.
		/// </returns>
		public static byte[] ToBytes(uint preimage)
		{
			byte[] imageBytes = new byte[4];

            for (int i = 0; i < 4; i++)
            {
				// Gets the distance between the desired byte and it's first binary digit in bits.
                int currentByte = 8 * i;

				// Creates a mask in which the desired byte is 1111_1111.
                uint currentByteMask = byteMask32 << currentByte;

				// Applies the mask so that image is set to 0 everywhere except the desired byte.
                uint image = preimage & currentByteMask;

				// Shifts image so that the desired byte is first and adds it to the array.
				imageBytes[i] = (byte)(image >> currentByte);
            }

			return imageBytes;
		}

		/// <summary>
		/// Takes 64-bit ulong preimage and makes it a byte array.
		/// </summary>
		/// 
		/// <param name="preimage">
		/// A ulong to turn into a byte[].
		/// </param>
		/// 
		/// <returns>
		/// A byte array of length 8 so that index 0 is the first 8 bits of 
		/// preimage and index 1 is the second 8 bits etc.
		/// </returns>
		public static byte[] ToBytes(ulong preimage)
		{
			byte[] imageBytes = new byte[8];

            for (int i = 0; i < 8; i++)
            {
				// Gets the distance between the desired byte and it's first binary digit in bits.
                int currentByte = 8 * i;

				// Creates a mask in which the desired byte is 1111_1111.
                ulong currentByteMask = byteMask64 << currentByte;

				// Applies the mask so that image is set to 0 everywhere except the desired byte.
                ulong image = preimage & currentByteMask;

				// Shifts image so that the desired byte is first and adds it to the array.
				imageBytes[i] = (byte)(image >> currentByte);
            }

			return imageBytes;
		}
	}
}

// ByteArrays.cs (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2022 Evan Overman (https://github.com/an-prata)