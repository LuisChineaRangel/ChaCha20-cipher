# ChaCha20 Cipher

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Twitter](https://img.shields.io/twitter/follow/luctstt.svg?label=Follow&style=social)](https://twitter.com/iluzioDev)

## Introduction 📋

The next program is an implementation of the ChaCha20 Stream Cipher written in Python, the objective is to generate a key stream from an specific input in order to encrypt/decrypt any kind of text.

> Stream ciphers are symmetric key cipher where plaintext digits are combined with a pseudorandom cipher digit stream (keystream). 

> ChaCha20 is a stream cipher designed by Daniel J. Bernstein. The secret key is 256 bits long (32 bytes). The cipher requires a nonce, which must not be reused across encryptions performed with the same key.

[ChaCha20 and XChaCha20 - PyCryptodome's documentation](https://pycryptodome.readthedocs.io/en/latest/src/cipher/chacha20.html)

<p float="left">
	<img src="https://upload.wikimedia.org/wikipedia/commons/1/1a/Dan_Bernstein_27C3.jpg" alt="Daniel J. Bernstein" height="225px">&nbsp;&nbsp;&nbsp;
  <img src="https://xilinx.github.io/Vitis_Libraries/security/2019.2/_images/chacha.png" alt="Input" height="225px">
</p>

## Features ✨

* Encryption and Decryption of any text.
* Customized inputs.
* Ascii Code-Text Convertion.
* Support Keys of variable length.
* Support for Hexadecimal or Decimal Formats.

## Install 🔧

```
git clone https://github.com/iluzioDev/ChaCha20-cipher
cd ChaCha20-cipher
python3 ChaCha20-cipher.py
```

## Usage 💡

Once executed, a menu will prompt asking for desired option:

```
■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
■              WELCOME TO THE CHACHA20 CIPHER TOOL!               ■
■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
What would you want to do?
[1] Encrypt/Decrypt Message.
[2] Encrypt/Decrypt Ascii Code.
[3] Convert Ascii Code to Text.
[4] Convert Text to Ascii Code.
[0] Exit.
■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
Option  ->
```

1. Encrypts/Decrypts a message after inserting key, counter and nonce values. The program will generate a key stream to make a XOR operation with the message.
2. Similar to option 1, encrypts/decrypts a message giving its ascii code ```(no plain text!)```.
3. Converts a given ascii code to its corresponding string. It's important to notice that the ascii code of each character has 3 digits!
  ```
  ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  Introduce ascii code: 072101108108111
  ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  OUTPUT TEXT: Hello
  ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
   ```
4. Similar to option 4, converts a string to its corresponding ascii code

## Maintainers 👷

<table>
  <tr>
    <td align="center"><a href="https://github.com/iluzioDev"><img src="https://avatars.githubusercontent.com/u/45295283?v=4" width="100px;" alt="IluzioDev"/><br /><sub><b>IluzioDev</b></sub></a><br />💻</td>
  </tr>
</table>

## License ⚖️

Distributed under the MIT License. [Click here](LICENSE.md) for more information.

---
<div align="center">
	<b>
		<a href="https://www.npmjs.com/package/get-good-readme">File generated with get-good-readme module</a>
	</b>
</div>