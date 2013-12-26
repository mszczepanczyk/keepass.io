# keepass.io
#
# Created by Pascal Mathis at 26.12.2013
# License: GPLv3 (Please see LICENSE for more information)

crypto = require('crypto')
constants = require('./constants')
Salsa20 = require('../util/salsa20')

module.exports = class SalsaStream
  constructor: (salsaKey) ->
    # Hash salsa key with SHA256 and convert to byte array
    salsaKey = crypto.createHash('sha256').update(salsaKey, 'binary', 'binary').digest('binary')
    salsaKey = Array::slice.call(new Buffer(salsaKey, 'binary'), 0)

    # Create new Salsa20 instance
    @salsa20 = new Salsa20(salsaKey, constants.SALSA20_IV)
    @salsaBuffer = []

  unprotect: (payload) ->
    payload = new Buffer(payload, 'base64').toString('binary')
    return @xor(payload, @getSalsaBytes(payload.length))

  xor: (payload, key) ->
    result = ''
    for index in [0...payload.length]
      result += String.fromCharCode(key[index] ^ payload.charCodeAt(index))

    return result

  getSalsaBytes: (count) ->
    # When current salsa buffer has not enough bytes,
    # grab another 64byte salsa20 chunk.
    while count > @salsaBuffer.length
      @salsaBuffer.push.apply(@salsaBuffer, @salsa20.getBytes(64))

    return @salsaBuffer.splice(0, count)