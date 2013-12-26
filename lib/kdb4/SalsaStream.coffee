# keepass.io
#
# Created by Pascal Mathis at 26.12.2013
# License: GPLv3 (Please see LICENSE for more information)

crypto = require('crypto')
constants = require('./constants')
Salsa20 = require('../util/salsa20')

module.exports = class SalsaStream
  # Initializes a new Salsa20 stream cipher with the given key.
  constructor: (salsaKey) ->
    # Hash salsa key with SHA256 and convert to byte array
    salsaKey = crypto.createHash('sha256').update(salsaKey, 'binary', 'binary').digest('binary')
    salsaKey = Array::slice.call(new Buffer(salsaKey, 'binary'), 0)

    # Create new Salsa20 instance
    @salsa20 = new Salsa20(salsaKey, constants.SALSA20_IV)
    @salsaBuffer = []

  # Unprotects the given payload. Remember that Salsa20 is a stream cipher,
  # so if there are multiple payloads, they must be decrypted in the same order
  # as they were encrypted. Otherwise you'll only receive garbage.
  unprotect: (payload) ->
    payload = new Buffer(payload, 'base64').toString('binary')
    return @xor(payload, @getSalsaBytes(payload.length))

  # XORs a string with the given key, used for Salsa20 en-/decryption
  xor: (payload, key) ->
    result = ''
    for index in [0...payload.length]
      result += String.fromCharCode(key[index] ^ payload.charCodeAt(index))

    return result

  # Tries to fetch the given amount of bytes from the internal Salsa20
  # buffer. If the buffer does not have enough bytes, the Salsa20 cipher
  # gets called so many times till the buffer is long enouh.
  getSalsaBytes: (count) ->
    # When current salsa buffer has not enough bytes,
    # grab another 64byte salsa20 chunk.
    while count > @salsaBuffer.length
      @salsaBuffer.push.apply(@salsaBuffer, @salsa20.getBytes(64))

    return @salsaBuffer.splice(0, count)