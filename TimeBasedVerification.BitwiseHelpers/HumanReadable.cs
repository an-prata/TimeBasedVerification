// TimeBasedVerification (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2022 Evan Overman (https://github.com/an-prata)
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TimeBasedVerification.BitwiseHelpers
{
	/// <summary>
	/// A class used to convert potentially very large numeric types
	/// to short human readable strings, in a fashion very similar to
	/// hexadecimal it uses numbers 0-9 and letters a-v, giving it 16
	/// more characters to work with. It takes chunks of 5 bits at a
	/// time and uses the corrosponding character to represent it.
	/// </summary>
	public static class HumanReadable
	{
		private const string digits = "0123456789abcdefghijklmnopqrstuv";

		private const ushort byteMask16 = 0b_0_00000_00000_11111;

		private const uint byteMask32 = 0b_00_00000_00000_00000_00000_00000_11111;

		private const ulong byteMask64 = 0b_000_00000_00000_00000_00000_00000_00000_00000_00000_00000_00000_000000_11111;

		/// <summary>
		/// Takes a ushort and makes it a 4 character human readable string.
		/// </summary>
		/// 
		/// <param name="preimage">
		/// The ushort to be made a string.
		/// </param>
		/// 
		/// <returns>
		/// A 4 character human readable string.
		/// </returns>
		public static string MakeHumanReadable(ushort preimage)
		{
			string image = "";

			for (int i = 0; i < 4; i++)
			{
				// Gets the distance between the desired 5 bits and it's first binary digit in bits.
				int currentByte = 5 * i;

				// Creates a mask in which the desired 5 bits is 111111.
				ushort currentByteMask = (ushort)(byteMask16 << currentByte);

				// Gets a number between 0 and 31 to find a digit from string digits.
				int digit = (preimage & currentByteMask) >> currentByte;

				// Adds the new found digit to string image.
				image += digits[digit];
			}

			return image;
		}

		/// <summary>
		/// Takes a uint and makes it a 7 character human readable string.
		/// </summary>
		/// 
		/// <param name="preimage">
		/// The uint to be made a string.
		/// </param>
		/// 
		/// <returns>
		/// A 7 character human readable string.
		/// </returns>
		public static string MakeHumanReadable(uint preimage)
		{
			string image = "";

			for (int i = 0; i < 7; i++)
			{
				// Gets the distance between the desired 5 bits and it's first binary digit in bits.
				int currentByte = 5 * i;

				// Creates a mask in which the desired 5 bits is 111111.
				uint currentByteMask = byteMask32 << currentByte;

				// Gets a number between 0 and 31 to find a digit from string digits.
				int digit = (int)((preimage & currentByteMask) >> currentByte);

				// Adds the new found digit to string image.
				image += digits[digit];
			}

			return image;
		}

		/// <summary>
		/// Takes a ulong and makes it an 12 character human readable string.
		/// </summary>
		/// 
		/// <param name="preimage">
		/// The ulong to be made a string.
		/// </param>
		/// 
		/// <returns>
		/// An 12 character human readable string.
		/// </returns>
		public static string MakeHumanReadable(ulong preimage)
		{
			string image = "";

			for (int i = 0; i < 12; i++)
			{
				// Gets the distance between the desired 5 bits and it's first binary digit in bits.
				int currentByte = 5 * i;

				// Creates a mask in which the desired 5 bits is 111111.
				ulong currentByteMask = byteMask64 << currentByte;

				// Gets a number between 0 and 31 to find a digit from string digits.
				int digit = (int)((preimage & currentByteMask) >> currentByte);

				// Adds the new found digit to string image.
				image += digits[digit];
			}

			return image;
		}

		/// <summary>
		/// Takes a 4 character human readable string and makes a 16-bit ushort.
		/// </summary>
		/// 
		/// <param name="humanReadable">
		/// The string to be made a ushort.
		/// </param>
		/// 
		/// <returns>
		/// An unsigned 16-bit ushort.
		/// </returns>
		public static ushort GetOriginalNumeric16(string humanReadable)
		{
			if (humanReadable.Length != 4)
			{
				throw new ArgumentException("Given string was incorrect length.");
			}

			ushort originalNumeric = 0;

			for (int i = 0; i < 4; i++)
			{
				// Gets the distance between the desired 5 bits and orginalNumeric's 
				// first binary digit in bits.
				int currentByte = 5 * i;

				// Gets the value of the current digit from the string humanReadable.
				ushort digit = (ushort)digits.IndexOf(humanReadable[i]);

				// Positions the bits of ushort digit to the current 5-bit byte.
				ushort bits = (ushort)(digit << currentByte);

				// Adds the bits to ushort original numeric.
				originalNumeric |= bits;
			}

			return originalNumeric;
		}

		/// <summary>
		/// Takes a 7 character human readable string and makes a 32-bit uint.
		/// </summary>
		/// 
		/// <param name="humanReadable">
		/// The string to be made a uint.
		/// </param>
		/// 
		/// <returns>
		/// An unsigned 32-bit uint.
		/// </returns>
		public static uint GetOriginalNumeric32(string humanReadable)
		{
			if (humanReadable.Length != 7)
			{
				throw new ArgumentException("Given string was incorrect length.");
			}

			uint originalNumeric = 0;

			for (int i = 0; i < 7; i++)
			{
				// Gets the distance between the desired 5 bits and orginalNumeric's 
				// first binary digit in bits.
				int currentByte = 5 * i;

				// Gets the value of the current digit from the string humanReadable.
				uint digit = (uint)digits.IndexOf(humanReadable[i]);

				// Positions the bits of uint digit to the current 5-bit byte.
				uint bits = digit << currentByte;

				// Adds the bits to uint original numeric.
				originalNumeric |= bits;
			}

			return originalNumeric;
		}

		/// <summary>
		/// Takes a 12 character human readable string and makes a 64-bit ulong.
		/// </summary>
		/// 
		/// <param name="humanReadable">
		/// The string to be made a ulong.
		/// </param>
		/// 
		/// <returns>
		/// An unsigned 64-bit ulong.
		/// </returns>
		public static ulong GetOriginalNumeric64(string humanReadable)
		{
			if (humanReadable.Length != 12)
			{
				throw new ArgumentException("Given string was incorrect length.");
			}

			ulong originalNumeric = 0;

			for (int i = 0; i < 12; i++)
			{
				// Gets the distance between the desired 5 bits and orginalNumeric's 
				// first binary digit in bits.
				int currentByte = 5 * i;

				// Gets the value of the current digit from the string humanReadable.
				ulong digit = (ulong)digits.IndexOf(humanReadable[i]);

				// Positions the bits of ulong digit to the current 5-bit byte.
				ulong bits = digit << currentByte;

				// Adds the bits to ulong original numeric.
				originalNumeric |= bits;
			}

			return originalNumeric;
		}
	}
}

// HumanReadable.cs (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2022 Evan Overman (https://github.com/an-prata)