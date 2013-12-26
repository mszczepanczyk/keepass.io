# keepass.io
#
# Created by Pascal Mathis at 10.12.2013
# License: GPLv3 (Please see LICENSE for more information)

async = require('async')
crypto = require('crypto')
zlib = require('zlib')
xml2js = require('xml2js')
constants = require('../constants')
errors = require('../util/errors')
helpers = require('../util/helpers')
Header = require('./Header')
Reader = require('./Reader')

module.exports = class Database
  constructor: (@rawDatabase, @compositeHash) ->
    @header = new Header()

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
      (cb) => @decompress(cb)
      (cb) => @convertToJson(cb)
      (cb) => @initializeAPI(cb)
    ], (err) -> cb(err))

  # This method builds the master key by transforming the
  # composite hash X times and applying SHA256 to the result.
  # X can be configured in KeePass, so each user is able to
  # decide how many transformation rounds should be done.
  # This can help to migitate bruteforce attempts, although
  # it increases the loading time of the database.
  #
  # If keepass.io can not use the native key transformation method,
  # a high amount of key transformation rounds could take very long...
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

  # Decrypts the database with the master key which was calculated before.
  # If the decryption fails or the stream start bytes don't match, the database
  # is either corrupt or the credentials were invalid, so an error will be thrown.
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

  # The KeePass data is stored in hashed blocks. Each block consists of a block index,
  # a stored precalculated hash, its length and the payload itself. To ensure database
  # integrity, the hash of each payload will be compared with the saved hash. If they
  # don't match, an error will be thrown.
  #
  # Although if a hashed block is valid and the hashes match, the payload gets written
  # into a separate buffer. If all blocks are valid, we will end up with one big chunk of data.
  processHBIO: (cb) ->
    @joinedData = new Buffer(@decryptedData.length)
    readOffset = writeOffset = 0

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
        if constants.DUMP_KEYS then console.log 'HBIO block #' + index + ': '  + calculatedHash

        # Compare the calculated hash with the stored one. If they are equal,
        # the data gets written to the result buffer. If not, an error will
        # be thrown.
        if storedHash isnt calculatedHash
          return cb(new errors.DatabaseError('HBIO check failed. It seems like your database is corrupt.'))
        else
          @joinedData.write(data, writeOffset, length, 'binary')
          writeOffset += length
      else
        if constants.DUMP_KEYS then console.log 'HBIO block #' + index + ': <empty>'

      # Break when an empty block was found
      break unless length != 0

    return cb()

  # If the header field 'CompressionFlags' is set to 1,
  # the database is compressed with gunzip. This method
  # checks if this flag is set and if yes, tries to
  # extract it. If the database is not compressed, this
  # method immediately returns.
  decompress: (cb) ->
    # If the database is not compressed, there is nothing to do.
    if not @header.getField('CompressionFlags')
      @databaseAsXml = @joinedData
      return cb()

    # Decompress the database with gzip
    try
      zlib.gunzip(@joinedData, (err, decompressedData) =>
        @databaseAsXml = decompressedData
        return cb()
      )
    catch e
      return cb(new errors.DatabaseError('Decompression failed. It seems like your database is corrupt.'))

  # Converts the XML database structure to JSON. Because xml2js is
  # 100% one-to-one bidirectional, we can later on just reverse
  # the process and save it into the KeePass database file.
  convertToJson: (cb) ->
    xml2js.parseString(@databaseAsXml, (err, json) =>
      if err then return cb(err)

      ###
      # Hey, why not '@databaseAsJson = json'? Because it would generate
      # a NEW object. But our reader and writer classes require a fixed
      # pointer which will be initialized during startup, so don't even
      # try to mess with this piece of code... You've been warned!
      delete @databaseAsJson[key] for key, value of @databaseAsJson
      @databaseAsJson[key] = value for key, value of json
      ###

      @databaseAsJson = json
      return cb()
    )

  # Initialize the API classes (reader and writer)
  # This should always be the last step to ensure that
  # the Reader and Writer objects got the right pointers.
  initializeAPI: (cb) ->
    @reader = new Reader(@databaseAsJson, @header)
    return cb()