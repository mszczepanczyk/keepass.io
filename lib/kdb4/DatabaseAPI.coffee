# keepass.io
#
# Created by Pascal Mathis at 10.12.2013
# License: GPLv3 (Please see LICENSE for more information)

SpahQL = require('spahql')
SalsaStream = require('./SalsaStream')
errors = require('../util/errors')

module.exports = class DatabaseAPI
  # Constructs a new instance of a KDB4 database reader.
  constructor: (@database, @header) ->
    @spahqlDb = SpahQL.db(@database)
    @unprotectPasswords()

  # Returns the JSON representation of the KeePass database.
  # This method pays attention to strict-pointer-equality,
  # so any changes you make to this object will directly
  # modify the internal database. (Which you are able to
  # save later on)
  getJson: ->
    return @database

  # Tries to find a node with the given UUID. The node will be
  # returned in its JSON representation. Again, strict-
  # pointer-equality is guaranteed. If the UUID does not exist,
  # null will be returned.
  findNodeByUuid: (uuid) ->
    return @spahqlDb.select('//*[/UUID == "' + uuid + '"]').value() ? null

  # Unprotects all passwords in the database. Basically, this method
  # executes an recursive search through the database, looking for attributes
  # where 'Protected' is set to 'True'.
  #
  # All of them will be unprotected with the Salsa20 stream cipher and
  # the 'Protected' flag will be set to 'False'. Remember to protect
  # the database again before saving any changes.
  unprotectPasswords: ->
    salsaStream = new SalsaStream(@header.getField('ProtectedStreamKey').toString('binary'))

    protectedEntries = @spahqlDb.select('//Value/[//Protected == "True"]')
    for protectedEntry in protectedEntries
      if not protectedEntry.value._? then continue
      protectedEntry.value._ = salsaStream.unprotect(protectedEntry.value._)
      protectedEntry.value.$.Protected = false