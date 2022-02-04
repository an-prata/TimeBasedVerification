# TimeBasedVerification (https://github.com/an-prata/TimeBasedVerification)
# Copyright (c) 2021 Evan Overman (https://github.com/an-prata)
# Licensed under the MIT License.

# Use to generate valid pairs of parameters that can be used
# for ByteArraysTest.cs and UnsignedNumericTest.cs

import random

bits    = 64 # 64, 32, or 16
i       = 0

raw_numerical		= ""
byte_array          = ""
unsigned_numerical  = "0b"

for i in range(0, bits):
	digit = str(random.randint(0, 1))
	raw_numerical += digit
	if i % 8 == 0:
		unsigned_numerical += "_"
	unsigned_numerical += digit
	i += 1

print(unsigned_numerical)
print("\n")

for i in range(0, int(bits / 8)):
	byte_array += ", 0b_"
	for x in range(bits - ((i + 1) * 8), bits - ((i + 1) * 8) + 8):
		byte_array += raw_numerical[x]
	i += 1

print(byte_array.removeprefix(", "))