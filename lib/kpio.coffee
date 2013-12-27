# keepass.io
#
# Created by Pascal Mathis at 04.12.2013
# License: GPLv3 (Please see LICENSE for more information)

fs = require('fs')
async = require('async')
crypto = require('crypto')
BaseCredential = require('./credentials/BaseCredential')
Kdb4Database = require('./kdb4/Database')
constants = require('./constants')
errors = require('./util/errors')
helpers = require('./util/helpers')

module.exports = class KeePassIO
  # As you might already know, this is the class constructor. It
  # should not mess around at all with the password database and
  # the only reason for its existance is to initialize some class
  # attributes.
  constructor: (@databasePath) ->
    @credentials = []

  # Adds another credentials object to the KPIO instance.
  # These credentials will be used for loading and saving
  # the current database. It does not matter at all in which
  # order you are specifying the credentials, because each
  # credential module has a given priority.
  #
  # This method only accepts class instances which are based
  # on the class BaseCredential. Otherwise an error will be thrown.
  # Remember that credentials will not be checked until the database
  # gets loaded.
  addCredential: (credentialObject) ->
    unless credentialObject instanceof BaseCredential
      throw new errors.ParameterError('`addCredential` can only handle class instances based on `BaseCredential`.')
    @credentials.push credentialObject

  loadDatabase: (cb) ->
    # Check if a valid callback was given
    unless cb instanceof Function
      throw new errors.ParameterError('`loadDatabase` expects a callback function.')

    # Process some tasks one by one. If an error
    # should occur, it will be directly forwarded
    # to the callback function.
    async.waterfall([
      (cb) => @loadFromFile(cb)
      (cb) => @checkSignatures(cb)
      (cb) => @buildCompositeHash(cb)
      (cb) => @instantiateDatabase(cb)
    ], (err) => cb(err, @database.api))

  # Tries to load the database from the file system.
  # The database can not be specified, it will be read
  # from the private class attribute databasePath.
  loadFromFile: (cb) ->
    try
      @rawDatabase = fs.readFileSync(@databasePath)
      return cb()
    catch err
      return cb(new errors.IOError(err))

  # Check if the loaded database file contains valid
  # KeePass signatures. If not, the file is most likely
  # corrupt, not a keepass database file at all or an
  # unsupported version.
  checkSignatures: (cb) ->
    readSignatures = helpers.getDatabaseSignature(@rawDatabase)

    # Check if the base signature exists and is valid
    if readSignatures[0] isnt constants.BASE_SIGNATURE
      return cb(new errors.DatabaseError('The specified database file contains an invalid base signature.'))

    # Check if the database version is supported
    if readSignatures[1] isnt constants.KDB4_VERSION_SIGNATURE
      return cb(new errors.DatabaseError('Sorry, the version of your database file is not supported yet.'))

    return cb()

  # Builds the composite hash which can be used to
  # unlock the KeePass database. It is created by joining
  # all credential keys together (in the right order!) and
  # hashing them with SHA256. Because there is no way for our
  # module to tell if the 'current' hash is valid, we will always
  # start with generating the composite hash from scratch.
  buildCompositeHash: (cb) ->
    # Get all credential modules with their key and priority
    sortedCredentials = []
    for credential in @credentials
      sortedCredentials.push(
        priority: credential.getPriority(),
        key: credential.getKey()
      )

    # Sort them by priority in ascending order
    sortedCredentials.sort((a, b) ->
      helpers.sortBy('priority', a, b, false)
    )

    # Join keys together and hash them with SHA256 to build the composite hash
    compositeKeyArray = []
    compositeKeyArray.push(sortedCredential.key) for sortedCredential in sortedCredentials

    @compositeHash = crypto
      .createHash('sha256')
      .update(compositeKeyArray.join(''), 'binary')
      .digest('binary')

    if constants.DUMP_KEYS then console.log 'Composite hash: ' + new Buffer(@compositeHash, 'binary').toString('hex')
    return cb()

  # Instantiates the database object which has an appropiate version
  # for the loaded KeePass database. As soon as the object was instantiated,
  # a first complete 'read' of the database will be made.
  instantiateDatabase: (cb) ->
    @database = new Kdb4Database(@rawDatabase, @compositeHash)
    @database.read(cb)