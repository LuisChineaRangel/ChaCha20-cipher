#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Feb 10 2023

@author: iluzioDev

This script implements the ChaCha20 stream cipher algorithm.
"""

# Receives a number or string containing an hexadecimal number in multiple possible formats
# ('0xAAAA', 'AAAA', 'AA:AA', 'AA : AA'...) and returns a text in the next format: 'AAAA'
def format_to_hex(x):
  x = str(x)
  if x.isnumeric():
    x = hex(int(x))
  x = x.upper().replace(' ', '').replace(':', '')
  if x[0:2] == '0X':
    x = x[2:]
  for i in range(len(x)):
    if x[i] not in '0123456789ABCDEF':
      raise ValueError('Invalid hexadecimal x!')
  return x

# Receives a string containing an hexadecimal number and returns a text in the next format: 'AAAA'
# with n digits (if n is greater than the number of digits of the number, it will be padded with 0s)
def format_to_hex_with_n_digits(x, n):
  if n < 1:
    raise ValueError('n must be a positive integer!')
  return format_to_hex(x).zfill(n)

# Receives a string containing an hexadecimal number and transforms it to binary
# with its equivalent length (1 hex = 4 bits)
def hex_to_bin(x):
  return bin(int(x, 16))[2:].zfill(len(x) * 4)

# Converts a string to ASCII Code Integers
def text_to_ascii(text):
  return [str(ord(i)).zfill(3) for i in text]

def ascii_to_text(ascii):
  ascii = str(ascii)
  if len(ascii) % 3 != 0:
    ascii = ascii.zfill(len(ascii) + (3 - (len(ascii) % 3)))
  return ''.join(chr(int(ascii[i - 2] + ascii[i - 1] + ascii[i])) for i in range(len(ascii) - 1, 0, -3))[::-1]

# Truncates a number to n characters
def truncate(x, n):
  return x & int('0x' + ('F' * n), 16)

# Split a string in n-sized chunks
def split_n_by_n(x, n):
  if n < 1:
    raise ValueError('n must be a positive integer!')
  if n > len(x):
    raise ValueError('n must be less than the string length!')
  if len(x) % n != 0:
    raise ValueError('String length is not a multiple of n!')
  return [x[i:i + n] for i in range(0, len(x), n)]

# Split a string in a word format ([['AA', 'BB', 'CC', 'DD'], ['EE', 'FF', 'GG', 'HH']...])
def split_into_words(x):
  return split_n_by_n(split_n_by_n(x, 2), 4)

# Rotates a number to the left n bits
def left_rotate_n_bits(x, n):
  if n < 0:
    raise ValueError('n must be a positive integer!')
  if n > N_BITS:
    raise ValueError('n must be less than the number of bits!')
  return (truncate(x << n, N_HEX)) | (x >> (N_BITS - n))

# Makes a quarter round operation
def quarter_round(a, b, c, d):
  a = truncate(a + b, N_HEX)
  d = left_rotate_n_bits(d ^ a, 16)
  c = truncate(c + d, N_HEX)
  b = left_rotate_n_bits(b ^ c, 12)
  a = truncate(a + b, N_HEX)
  d = left_rotate_n_bits(d ^ a, 8)
  c = truncate(c + d, N_HEX)
  b = left_rotate_n_bits(b ^ c, 7)
  return a, b, c, d

# Generates the key stream for encryption/decryption
def generate_key_stream(input):
  if len(input) != N_WORDS:
    raise ValueError('Input must have 16 words!')

  x = [None] * N_WORDS
  for i in range(N_WORDS):
    x[i] = input[i] = int(input[i], N_WORDS)

  for i in range(0, ROUNDS):
    # Columns round
    x[0], x[4], x[8], x[12] = quarter_round(x[0], x[4], x[8], x[12])
    x[1], x[5], x[9], x[13] = quarter_round(x[1], x[5], x[9], x[13])
    x[2], x[6], x[10], x[14] = quarter_round(x[2], x[6], x[10], x[14])
    x[3], x[7], x[11], x[15] = quarter_round(x[3], x[7], x[11], x[15])

    # Diagonal round
    x[0], x[5], x[10], x[15] = quarter_round(x[0], x[5], x[10], x[15])
    x[1], x[6], x[11], x[12] = quarter_round(x[1], x[6], x[11], x[12])
    x[2], x[7], x[8], x[13] = quarter_round(x[2], x[7], x[8], x[13])
    x[3], x[4], x[9], x[14] = quarter_round(x[3], x[4], x[9], x[14])

  return x

# Receives a state and formats it to hexadecimal
def format_state(state):
  for i in range(0, len(state), 4):
    state[i] = format_to_hex_with_n_digits(hex(int(state[i])), 8)
    state[i + 1] = format_to_hex_with_n_digits(hex(int(state[i + 1])), 8)
    state[i + 2] = format_to_hex_with_n_digits(hex(int(state[i + 2])), 8)
    state[i + 3] = format_to_hex_with_n_digits(hex(int(state[i + 3])), 8)

# Iterates the state and prints it
def iterate_state(state):
  print('')
  for i in range(0, len(state), 4):
    print('\t\t' + state[i] + ' ' + state[i + 1] +
          ' ' + state[i + 2] + ' ' + state[i + 3])
  print('')

def encrypt_decrypt(text, key_stream):
  if len(key_stream) != N_WORDS:
    raise ValueError('Key stream must have 16 words!')
  key_stream = ''.join(key_stream)
  text = ''.join(text_to_ascii(text))
  return int(text) ^ int(key_stream, 16)

###############################################################################


# Constants
ROUNDS = 10
CONSTANT = '61707865:3320646E:79622D32:6B206574'

# Format the constant to the correct format
CONSTANT = split_n_by_n(format_to_hex(CONSTANT), 8)

N_BITS = 32
N_HEX = int(N_BITS / 4)

N_WORDS = 16

def main():

  while True:
    key_is_hex = counter_is_hex = nonce_is_hex = False
    text = str()
    print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
    print('■              WELCOME TO THE CHACHA20 CIPHER TOOL!               ■')
    print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
    print('What would you want to do?')
    print('[1] Encrypt/Decrypt Message.')
    print('[2] Encrypt/Decrypt Ascii Code.')
    print('[3] Convert Ascii Code to Text.')
    print('[4] Convert Text to Ascii Code.')
    print('[0] Exit.')
    print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
    option = input('Option  ->  ')
    print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')

    # If option is not valid, ask again
    if option not in ['0', '1', '2', '3', '4']:
      print('Invalid option!')
      continue

    # If option is '0', exit
    if option == '0':
      print('See you soon!')
      print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
      break

    # If option is '1', start the cipher
    if option == '1' or option == '2':
      # Ask for key
      key = input('Introduce key: ')
      if not key.isnumeric():
        key_is_hex = True
      key = format_to_hex_with_n_digits(key, 64)
      if len(key) != 64:
        raise ValueError('Key must be 64 characters long!')
      key = split_into_words(key)

      # Ask for counter
      print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
      counter = input('Introduce counter: ')
      if not counter.isnumeric():
        counter_is_hex = True
      counter = format_to_hex_with_n_digits(counter, 8)
      if len(counter) > 8:
        raise ValueError('Counter must be up to 8 characters long!')
      counter = split_n_by_n(counter, 2)

      # Ask for nonce
      print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
      nonce = input('Introduce nonce: ')
      if not nonce.isnumeric():
        nonce_is_hex = True
      nonce = format_to_hex_with_n_digits(nonce, 24)
      if len(nonce) != 24:
        raise ValueError('Nonce must be 24 characters long!')
      nonce = split_into_words(nonce)

      initial_state = CONSTANT + key + [counter] + nonce

      # Transform to little endian the values corresponding to the key and the nonce
      if key_is_hex:
        for i in range(4, 12):
          initial_state[i].reverse()

      if counter_is_hex:
        initial_state[12].reverse()

      if nonce_is_hex:
        for i in range(13, 16):
          initial_state[i].reverse()

      # Rejoins the words of the state
      for i in range(len(initial_state)):
        initial_state[i] = ''.join(initial_state[i])

      final_state = generate_key_stream(initial_state)

      key_stream = [None] * N_WORDS
      for i in range(N_WORDS):
        key_stream[i] = truncate(initial_state[i] + final_state[i], N_HEX)

      print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
      print('■                  INITIAL STATE OF THE CIPHER                    ■')
      print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
      format_state(initial_state)
      iterate_state(initial_state)

      print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
      print('■               FINAL STATE OF CHACHA20 BLOCK                     ■')
      print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
      format_state(final_state)
      iterate_state(final_state)

      print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
      print('■                  KEY STREAM OF CHACHA20                         ■')
      print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
      format_state(key_stream)
      iterate_state(key_stream)

    if option == '1':
      # Ask for text to encrypt/decrypt
      print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
      text = input('Introduce text to encrypt/decrypt: ')

    if option == '2':
      # Ask for ascii code to convert to text in order to encrypt/decrypt
      print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
      ascii_code = input('Introduce ascii code: ')
      text = ascii_to_text(ascii_code)

    if option in ['1', '2']:
      output_ascii = encrypt_decrypt(text, key_stream)
      print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
      print('■                       ASCII OUTPUT                              ■')
      print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
      print(output_ascii)

    # If option is 3, ask for ascii code to convert to text
    if option == '3':
      ascii_code = input('Introduce ascii code: ')
      text = ascii_to_text(ascii_code)
      print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
      print('■                       OUTPUT TEXT                               ■')
      print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
      print(text)

    # If option is 4, ask for text to convert to ascii code
    if option == '4':
      text = input('Introduce text: ')
      ascii_code = ''.join(text_to_ascii(text))
      print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
      print('■                        ASCII CODE                               ■')
      print('■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■')
      print(ascii_code)

main()
