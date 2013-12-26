# keepass.io
#
# Created by Pascal Mathis at 10.12.2013
# License: GPLv3 (Please see LICENSE for more information)

SpahQL = require('spahql')
SalsaStream = require('./SalsaStream')
errors = require('../util/errors')

class KPNode
  constructor: (@node, @rootNode) ->
    @cache = []

  # Returns the UUID of the current node
  uuid: -> return @node.select('/UUID/0').value()

  # Returns all groups which the node contains
  groups: ->
    # For better performance, the results of this method will be cached.
    if @cache.groups? then return @cache.groups

    @cache.groups = []
    groupCount = @node.select('/*/Group').length - 1
    for groupIndex in [0..groupCount]
      @cache.groups.push(new KPGroup(@node.select('/' + groupIndex + '/Group/0'), @rootNode))

    return @cache.groups

  # Returns all entries which the node contains
  entries: ->
    # For better performance, the results of this method will be cached.
    if @cache.entries? then return @cache.entries

    @cache.entries = []
    entryCount = @node.select('/Entry/*').length - 1
    for entryIndex in [0..entryCount]
      @cache.entries.push(new KPEntry(@node.select('/Entry/' + entryIndex), @rootNode))

    return @cache.entries

class KPGroup extends KPNode

class KPEntry extends KPNode
  # Returns a field which matches the given field name. If no
  # field exists with that name, 'null' will be returned. If
  # the field was/is protected, the unprotected string will
  # be returned.
  field: (fieldName) ->
    @rootNode.set('fieldName', fieldName)
    fieldData = @node.select('/String/*[/Key/0 == $/fieldName]')

    if (fieldValue = fieldData.value().Value?[0])
      if fieldValue._? and fieldValue.$? and not fieldValue.$.Protected
        return fieldValue._
      else
        return fieldValue
    else
      return null

  # Returns all fields of the entry with their name and value.
  fields: ->
    result = {}
    fieldNames = @node.select('/String/*/Key/0').values()
    for fieldName in fieldNames
      result[fieldName] = @field(fieldName)

    return result

module.exports = class Reader extends KPNode
  # Constructs a new instance of a KDB4 database reader.
  constructor: (database, @header) ->
    @db = SpahQL.db(database)
    @unprotectPasswords()

    super(@db.select('/KeePassFile/Root'), @db)

  # Unprotects all passwords in the database. Basically, this method
  # executes an recursive search through the database, looking for attributes
  # where 'Protected' is set to 'True'.
  #
  # All of them will be unprotected with the Salsa20 stream cipher and
  # the 'Protected' flag will be set to 'False'. Remember to protect
  # the database again before saving any changes.
  unprotectPasswords: ->
    salsaStream = new SalsaStream(@header.getField('ProtectedStreamKey').toString('binary'))

    protectedEntries = @db.select('//String/*/Value/0[/*/Protected == "True"]')
    for protectedEntry in protectedEntries
      protectedEntry.value._ = salsaStream.unprotect(protectedEntry.value._)
      protectedEntry.value.$.Protected = false