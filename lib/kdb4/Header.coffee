# keepass.io
#
# Created by Pascal Mathis at 10.12.2013
# License: GPLv3 (Please see LICENSE for more information)

constants = require('./constants')
helpers = require('../util/helpers')
errors = require('../util/errors')
pypackjs = require('../util/pypackjs')

module.exports = class Header
  # Definition of all valid KDB4 header fields
  # with their IDs. To automatically unpack a field with
  # PyPackJS as soon as 'setField' was called, specify
  # a 'type'. This can be useful to automatically extract
  # integers and other things from the header without having
  # to mess around for yourself with some buffers.
  HEADER_FIELDS =
    0: { name: 'EndOfHeader' }
    1: { name: 'Comment' }
    2: { name: 'CipherID' }
    3: { name: 'CompressionFlags', type: '<I' }
    4: { name: 'MasterSeed' }
    5: { name: 'TransformSeed' }
    6: { name: 'TransformRounds', type: '<q' }
    7: { name: 'EncryptionIV' }
    8: { name: 'ProtectedStreamKey' }
    9: { name: 'StreamStartBytes' }
    10: { name: 'InnerRandomStreamID' }

  # Tries to read the KDB4 header from the given buffer / raw database
  # file. If the header should be invalid, a DatabaseError will be thrown.
  # After this function has fully executed, you are able to access any header
  # field. This function can be called as often as you like, but the header gets
  # resetted each time.
  read: (@rawDatabase, cb) ->
    @header = {}
    currentOffset = constants.HEADER_OFFSET

    while(true)
      # Read header field ID
      fieldID = helpers.readBuffer(@rawDatabase, currentOffset, 1, 'b')
      currentOffset += 1

      # Check if header field with read ID exists, and if not, throw an error
      if not HEADER_FIELDS[fieldID]?
        return cb(throw new errors.DatabaseError('Unknown header field found with ID: ' + fieldID))

      # Get the length of the field
      fieldLength = helpers.readBuffer(@rawDatabase, currentOffset, 2, 'h')
      currentOffset += 2
      if fieldLength > 0
        fieldData = helpers.readBuffer(@rawDatabase, currentOffset, fieldLength, fieldLength + 'A')
        currentOffset += fieldLength
        @setField(fieldID, fieldData)

      # Abort when end of header is reached (ID 0)
      if fieldID is 0
        @headerLength = currentOffset
        break

    return cb()

  # Resolves a field ID given by its name. For example,
  # 'EndOfHeader' will be resolved to field ID 0.
  resolveName: (fieldID) ->
    for keyID, field of HEADER_FIELDS
      if field.name is fieldID
        return keyID
    return undefined

  # Returns the length of the database header
  getLength: ->
    return @headerLength

  # Gets the header field with the given ID. It will throw an
  # error if an invalid field ID was given. Instead of a field ID,
  # the name of the field can also be given.
  getField: (fieldID) ->
    # If field ID is not numeric, search for a field with the given name
    if not isFinite(fieldID)
      fieldID = @resolveName(fieldID)

    # Check if given header field ID is valid and exists
    if not HEADER_FIELDS[fieldID]?
      return cb(throw new errors.DatabaseError('Unknown header field given with ID: ' + fieldID))

    return @header[fieldID]

  # Sets the header field with the given ID. If the header field
  # is defined with a custom 'type', the given value will be automatically
  # unpacked by PyPackJS and then stored in the field. It will throw an
  # error if an invalid field ID was given.
  setField: (fieldID, fieldData) ->
    # If field ID is not numeric, search for a field with the given name
    if not isFinite(fieldID)
      fieldID = @resolveName(fieldID)

    # Check if given header field ID is valid and exists
    if not HEADER_FIELDS[fieldID]?
      return cb(throw new errors.DatabaseError('Unknown header field given with ID: ' + fieldID))

    if not HEADER_FIELDS[fieldID].type?
      @header[fieldID] = fieldData
    else
      @header[fieldID] = pypackjs.unpack(HEADER_FIELDS[fieldID].type, fieldData, 0)[0]