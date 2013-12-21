# keepass.io
#
# Created by Pascal Mathis at 10.12.2013
# License: GPLv3 (Please see LICENSE for more information)

async = require('async')
crypto = require('crypto')
constants = require('../constants')
errors = require('../util/errors')
helpers = require('../util/helpers')
Header = require('./Header')
Reader = require('./Reader')

module.exports = class Database
  constructor: (@rawDatabase, @compositeHash) ->
    @header = new Header()
    @reader = new Reader()

  # Reads the whole database. Please be careful, this method
  # overwrites / resets any existing data! Because this function
  # executes multiple steps one by one, a callback function IS required.
  read: (cb) ->
    # Check if a valid callback was given
    unless cb instanceof Function
      throw new errors.ParameterError('`read` expects a callback function.')

    # Process some tasks one by one. If an error
    # should occur, it will be directly forwarded
    # to the callback function.
    async.waterfall([
      (cb) => @header.read(@rawDatabase, cb)
      (cb) => @buildMasterKey(cb)
      (cb) => @decrypt(cb)
      (cb) => @processHBIO(cb)
    ], (err) -> cb(err))

  # TODO: Add documentation
  buildMasterKey: (cb) ->
    if constants.DUMP_KEYS then console.log 'Transformation seed: ' + @header.getField('TransformSeed').toString('hex')
    if constants.DUMP_KEYS then console.log 'Transformation rounds: ' + @header.getField('TransformRounds')

    # Transform composite hash for X rounds
    transformedKey = helpers.transformKey(
      new Buffer(@compositeHash, 'binary'),
      @header.getField('TransformSeed'),
      @header.getField('TransformRounds')
    )
    if constants.DUMP_KEYS then console.log 'Transformed key: ' + new Buffer(transformedKey, 'binary').toString('hex')

    # Build master key
    @masterKey = @header.getField('MasterSeed').toString('binary') + transformedKey
    @masterKey = crypto.createHash('sha256').update(@masterKey, 'binary').digest('binary')
    if constants.DUMP_KEYS then console.log 'Master key: ' + new Buffer(@masterKey, 'binary').toString('hex')

    return cb()

  # TODO: Add documentation
  decrypt: (cb) ->
    cipher = crypto.createDecipheriv('aes-256-cbc', @masterKey, @header.getField('EncryptionIV'))
    @decryptedData = @rawDatabase.slice(@header.getLength()).toString('binary')

    # Decrypt the database
    cipher.setAutoPadding(true)
    try
      @decryptedData = cipher.update(@decryptedData, 'binary', 'binary') + cipher.final('binary')
    catch e
      return cb(new errors.CredentialError('Invalid master key. Are you sure provided the correct credentials?'))
    @decryptedData = new Buffer(@decryptedData, 'binary')

    # KeePass splits the database into multiple hashed blocks
    # to ensure database integrity. Basically, it will compare
    # a calculated with a stored hash. If they don't match, something
    # is wrong with the database.
    streamStartBytes = @header.getField('StreamStartBytes').toString('binary')
    if streamStartBytes is @decryptedData.slice(0, streamStartBytes.length).toString('binary')
      @decryptedData = @decryptedData.slice(streamStartBytes.length)
      return cb()
    else
      return cb(new errors.DatabaseError('HBIO check failed. Either your database is corrupt or the provided credentials are incorrect.'))

  # TODO: Add documentation
  processHBIO: (cb) ->
    @joinedData = new Buffer(@decryptedData.length)
    readOffset = writeOffset = 0
    currentBlock = 0

    # Process all hashed blocks and write them into
    # @joinedData so we have one big piece over data
    loop
      index = @decryptedData.readUInt32LE(readOffset); readOffset += 4
      storedHash = @decryptedData.toString('hex', readOffset, readOffset + 32); readOffset += 32
      length = @decryptedData.readUInt32LE(readOffset); readOffset += 4

      # If a hashed block was found with a size greater than zero,
      # calculate a hash and compare it with the stored hash
      if length > 0
        data = @decryptedData.toString('binary', readOffset, readOffset + length); readOffset += length
        calculatedHash = crypto.createHash('sha256').update(data, 'binary', 'hex').digest('hex')
        if constants.DUMP_KEYS then console.log 'HBIO block #' + currentBlock + ': '  + calculatedHash

        # Compare the calculated hash with the stored one. If they are equal,
        # the data gets written to the result buffer. If not, an error will
        # be thrown.
        if storedHash isnt calculatedHash
          return cb(new errors.DatabaseError('HBIO check failed. It seems like your database is corrupt.'))
        else
          @joinedData.write(data, writeOffset, length, 'binary')
          writeOffset += length
      else
        if constants.DUMP_KEYS then console.log 'HBIO block #' + currentBlock + ': <empty>'

      # Break when an empty block was found
      currentBlock++
      break unless length != 0

    return cb()