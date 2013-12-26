# keepass.io
#
# Created by Pascal Mathis at 10.12.2013
# License: GPLv3 (Please see LICENSE for more information)

SpahQL = require('spahql')
SalsaStream = require('./SalsaStream')
errors = require('../util/errors')

# TODO: Add LOADS of documentation

class KPNode
  constructor: (@node, @reader) ->
    @cache = []

  uuid: -> return @node.select('/UUID/0').value()

  groups: ->
    if @cache.groups? then return @cache.groups

    @cache.groups = []
    groupCount = @node.select('/*/Group').length - 1
    for groupIndex in [0..groupCount]
      @cache.groups.push(new KPGroup(@node.select('/' + groupIndex + '/Group/0'), @reader))

    return @cache.groups

  entries: ->
    if @cache.entries? then return @cache.entries

    @cache.entries = []
    entryCount = @node.select('/Entry/*').length - 1
    for entryIndex in [0..entryCount]
      @cache.entries.push(new KPEntry(@node.select('/Entry/' + entryIndex), @reader))

    return @cache.entries

class KPGroup extends KPNode

class KPEntry extends KPNode
  field: (fieldName) ->
    @reader.db.set('fieldName', fieldName)
    fieldData = @node.select('/String/*[/Key/0 == $/fieldName]')

    if (fieldValue = fieldData.value().Value?[0])
      if fieldValue._? and fieldValue.$? and not fieldValue.$.Protected
        return fieldValue._
      else
        return fieldValue
    else
      return null

  fields: ->
    result = {}
    fieldNames = @node.select('/String/*/Key/0').values()
    for fieldName in fieldNames
      result[fieldName] = @field(fieldName)

    return result

module.exports = class Reader extends KPNode
  constructor: (database, @parent) ->
    @db = SpahQL.db(database)
    @unprotectPasswords()

    super(@db.select('/KeePassFile/Root'), this)

  unprotectPasswords: ->
    salsaStream = new SalsaStream(@parent.header.getField('ProtectedStreamKey').toString('binary'))

    protectedEntries = @db.select('//String/*/Value/0[/*/Protected == "True"]')
    for protectedEntry in protectedEntries
      protectedEntry.value._ = salsaStream.unprotect(protectedEntry.value._)
      protectedEntry.value.$.Protected = false