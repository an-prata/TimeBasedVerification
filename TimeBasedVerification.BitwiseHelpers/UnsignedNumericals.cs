// TimeBasedVerification (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2022 Evan Overman (https://github.com/an-prata)
// Licensed under the MIT License.

namespace TimeBasedVerification.BitwiseHelpers
{
	public static class UnsignedNumericals
	{
		/// <summary>
		/// Takes a byte array of length 2 and makes a ushort.
		/// </summary>
		/// 
		/// <param name="imageBytes">
		/// The byte[] to turn into a ushort.
		/// </param>
		/// 
		/// <returns>
		/// A ushort made from the elements of imageBytes.
		/// </returns>
		public static ulong ToUshort(byte[] imageBytes)
		{
			if (imageBytes.Length != 2)
			{
				throw new ArgumentException("imageBytes was wrong length.");
			}

			ulong preimage = 0;

			for (int i = 0; i < 2; i++)
			{
				// Gets the distance between the desired byte and it's first binary digit in bits.
				int currentByte = i * 8;

				// Gets the value of the desired byte and shifts it to the desired location.
				ushort image = (ushort)(imageBytes[i] << currentByte);
				
				// Adds the desired byte to preimage.
				preimage |= image;
			}

			return preimage;
		}

		/// <summary>
		/// Takes a byte array of length 4 and makes a uint.
		/// </summary>
		/// 
		/// <param name="imageBytes">
		/// The byte[] to turn into a uint.
		/// </param>
		/// 
		/// <returns>
		/// A uint made from the elements of imageBytes.
		/// </returns>
		public static ulong ToUint(byte[] imageBytes)
		{
			if (imageBytes.Length != 4)
			{
				throw new ArgumentException("imageBytes was wrong length.");
			}

			ulong preimage = 0;

			for (int i = 0; i < 4; i++)
			{
				// Gets the distance between the desired byte and it's first binary digit in bits.
				int currentByte = i * 8;

				// Gets the value of the desired byte and shifts it to the desired location.
				uint image = ((uint)imageBytes[i]) << currentByte;
				
				// Adds the desired byte to preimage.
				preimage |= image;
			}

			return preimage;
		}

		/// <summary>
		/// Takes a byte array of length 8 and makes a ulong.
		/// </summary>
		/// 
		/// <param name="imageBytes">
		/// The byte[] to turn into a ulong.
		/// </param>
		/// 
		/// <returns>
		/// A ulong made from the elements of imageBytes.
		/// </returns>
		public static ulong ToUlong(byte[] imageBytes)
		{
			if (imageBytes.Length != 8)
			{
				throw new ArgumentException("imageBytes was wrong length.");
			}

			ulong preimage = 0;

			for (int i = 0; i < 8; i++)
			{
				// Gets the distance between the desired byte and it's first binary digit in bits.
				int currentByte = i * 8;

				// Gets the value of the desired byte and shifts it to the desired location.
				ulong image = ((ulong)imageBytes[i]) << currentByte;
				
				// Adds the desired byte to preimage.
				preimage |= image;
			}

			return preimage;
		}
	}
}

// UnsignedNumericals.cs (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2022 Evan Overman (https://github.com/an-prata)