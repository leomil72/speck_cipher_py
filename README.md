
# SPECK64/128 BLOCK CIPHER
  

## What is it?
Speck cipher is a lightweight, easy to implement, relatively fast, simple
block cipher developed by NSA and released into the public domain in 2013.
It's aimed to software implementations and it's been developed primarily for
IoT applications but, due to its simplicity and relatively robustness, it
can be used for a wide range of applications.

The code has been translated from the C reference source released by
NSA itself. Surely, it can be optimized and improved but, as it is, it's
a good starting point.
https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf

## Speck64/128 block cipher
The Speck is a family of lightweight block ciphers publicly released by the
National Security Agency (NSA) in June 2013. Speck has been optimized for
performance in software implementations, while its sister algorithm, Simon,
has been optimized for hardware implementations. 
The NSA began working on the Simon and Speck ciphers in 2011. The
agency anticipated some agencies in the US federal government would need a
cipher that would operate well on a diverse collection of Internet of Things (IoT)
devices while maintaining an acceptable level of security.

Technically speaking, the Speck64/128 is a block cipher, meaning that it works
with fixed-width blocks of data to be encrypted/decrypted. The "64/128" in its
name stands for the main characteristics of the algorithm: the block is 64-bits
wide, while the key is 128-bits wide. The algorithms is based on the so-called
ARX scheme. ARX stands for Add-Rotate-Xor, indicating the 3 main operations
involed, the modular addition, the fixed rotation amounts, and the XOR.
Due to the limitations of the language and to keep the implementation as simple
as possible, I opted to implement the 64/128 version of the cipher that is based
on unsigned 32-bit variables, so that I could use the built-in types of Python,
keeping only the first 32-bits of the values stored in the variables.

## OFB (OUTPUT FEEDBACK) MODE OF OPERATION
The OFB, Output FeedBack, is a mode of operation that makes a block cipher
into a stream cipher. It generates keystream blocks, which are then XORed with
the plaintext blocks to get the ciphertext. This mode of operation is useful
when one has to process quantities of data whose size is not initially known,
like in a stream, or data whose size does not match that of the block size 
of the algorithm.

## Warranty
The software is provided "AS IS" without any warranty, either expressed or implied,
including, but not limited to, the implied warranties of merchantability and fitness
for a particular purpose. The author will not be liable for any special, incidental,
consequential or indirect damages due to loss of data or any other reason.

## Security
The software is a "proof of concept" and should therefore not be used where real,
certified data security is required. In these cases, the use of a cryptographically
secure algorithm, certified by the appropriate Agencies of your country, is recommended.

## License
This software is released under the terms of the GNU General Public License v3.0 or later