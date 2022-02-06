// TimeBasedVerification (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2022 Evan Overman (https://github.com/an-prata)
// Licensed under the MIT License.

using Xunit;

using static TimeBasedVerification.BitwiseHelpers.HumanReadable;

namespace TimeBasedVerification.Tests.BitwiseHelpers
{
	public class HumanReadableTests
	{
		[Theory]
		[InlineData(
			0b_1_11000_01110_00001,
			"1eo1"
		)]
		[InlineData(
			0b_0_00010_01010_01011,
			"ba20"
		)]
		[InlineData(
			0b_0_00111_10101_01111,
			"fl70"
		)]
		public void ConversionTest16(ushort given, string expected)
		{
			Assert.Equal(expected, MakeHumanReadable(given));
		}

		[Theory]
		[InlineData(
			0b_11_00010_00101_01111_11000_00000_01101,
			"d0of523"
		)]
		[InlineData(
			0b_10_10111_01111_10110_00110_01010_10010,
			"ia6mfn2"
		)]
		[InlineData(
			0b_00_01001_00010_11000_00011_01101_00110,
			"6d3o290"
		)]
		public void ConversionTest32(uint given, string expected)
		{
			Assert.Equal(expected, MakeHumanReadable(given));
		}

		[Theory]
		[InlineData(
			0b_0110_10001_11111_10100_01110_01000_01011_11011_00111_01011_10010_11110_10110,
			"muib7rb8ekvh6"
		)]
		[InlineData(
			0b_0101_11001_10101_11111_10110_00111_10111_11101_10000_10001_11010_00100_00011,
			"34qhgtn7mvlp5"
		)]
		[InlineData(
			0b_0010_10101_11101_11111_11011_10000_01101_00100_11100_10100_11101_10110_10001,
			"hmtks4dgrvtl2"
		)]
		public void ConversionTest64(ulong given, string expected)
		{
			Assert.Equal(expected, MakeHumanReadable(given));
		}

		[Theory]
		[InlineData(
			0b_1_11000_01110_00001,
			"1eo1"
		)]
		[InlineData(
			0b_0_00010_01010_01011,
			"ba20"
		)]
		[InlineData(
			0b_0_00111_10101_01111,
			"fl70"
		)]
		public void OriginalNumericTest16(ushort expected, string given)
		{
			Assert.Equal(expected, GetOriginalNumeric16(given));
		}

		[Theory]
		[InlineData(
			0b_11_00010_00101_01111_11000_00000_01101,
			"d0of523"
		)]
		[InlineData(
			0b_10_10111_01111_10110_00110_01010_10010,
			"ia6mfn2"
		)]
		[InlineData(
			0b_00_01001_00010_11000_00011_01101_00110,
			"6d3o290"
		)]
		public void OriginalNumericTest32(uint expected, string given)
		{
			Assert.Equal(expected, GetOriginalNumeric32(given));
		}

		[Theory]
		[InlineData(
			0b_0110_10001_11111_10100_01110_01000_01011_11011_00111_01011_10010_11110_10110,
			"muib7rb8ekvh6"
		)]
		[InlineData(
			0b_0101_11001_10101_11111_10110_00111_10111_11101_10000_10001_11010_00100_00011,
			"34qhgtn7mvlp5"
		)]
		[InlineData(
			0b_0010_10101_11101_11111_11011_10000_01101_00100_11100_10100_11101_10110_10001,
			"hmtks4dgrvtl2"
		)]
		public void OriginalNumericTest64(ulong expected, string given)
		{
			Assert.Equal(expected, GetOriginalNumeric64(given));
		}
	}
}

// HumanReadableTests.cs (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2022 Evan Overman (https://github.com/an-prata)