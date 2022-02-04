// TimeBasedVerification (https://github.com/an-prata/TimeBasedVerification)
// Copyright (c) 2021 Evan Overman (https://github.com/an-prata)
// Licensed under the MIT License.

using Xunit;

using static TimeBasedVerification.BitwiseHelpers.UnsignedNumericals;

namespace TimeBasedVerification.Tests.BitwiseHelpers
{
    public class UnsignedNumericalTest
    {
        [Theory]
        [InlineData(
            0b_11100001_11000001,
            new byte[] {
                0b_11000001, 
                0b_11100001
            }
        )]
        [InlineData(
            0b_00001001_01001011,
            new byte[] {
                0b_01001011, 
                0b_00001001
            }
        )]
        [InlineData(
            0b_00011110_10101111,
            new byte[] {
                0b_10101111, 
                0b_00011110
            }
        )]
        public void ConversionTest(ushort expected, byte[] given)
        {
            Assert.Equal(expected, ToUshort(given));
        }

        [Theory]
        [InlineData(
            0b_11000100_01010111_11100000_00001101,
            new byte[] {
                0b_00001101, 
                0b_11100000, 
                0b_01010111, 
                0b_11000100
            }
        )]
        [InlineData(
            0b_10101110_11111011_00011001_01010010,
            new byte[] {
                0b_01010010, 
                0b_00011001, 
                0b_11111011, 
                0b_10101110
            }
        )]
        [InlineData(
            0b_00010010_00101100_00001101_10100110,
            new byte[] {
                0b_10100110, 
                0b_00001101, 
                0b_00101100, 
                0b_00010010
            }
        )]
        public void ConversionTest32(uint expected, byte[] given)
        {
            Assert.Equal(expected, ToUint(given));
        }

        [Theory]
        [InlineData(
            0b_01101000_11111110_10001110_01000010_11110110_01110101_11001011_11010110,
            new byte[] {
                0b_11010110, 
                0b_11001011, 
                0b_01110101, 
                0b_11110110, 
                0b_01000010, 
                0b_10001110, 
                0b_11111110, 
                0b_01101000
            }
        )]
        [InlineData(
            0b_01011100_11010111_11110110_00111101_11111011_00001000_11101000_10000011,
            new byte[] {
                0b_10000011, 
                0b_11101000, 
                0b_00001000, 
                0b_11111011, 
                0b_00111101, 
                0b_11110110, 
                0b_11010111, 
                0b_01011100
            }
        )]
        [InlineData(
            0b_00101010_11110111_11111011_10000011_01001001_11001010_01110110_11010001,
            new byte[] {
                0b_11010001, 
                0b_01110110,
                0b_11001010, 
                0b_01001001, 
                0b_10000011, 
                0b_11111011, 
                0b_11110111, 
                0b_00101010
            }
        )]
        public void ConversionTest64(ulong expected, byte[] given)
        {
            Assert.Equal(expected, ToUlong(given));
        }
    }
}