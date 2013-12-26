# keepass.io
#
# Created by Pascal Mathis at 10.12.2013
# License: GPLv3 (Please see LICENSE for more information)

SpahQL = require('spahql')
errors = require('../util/errors')

class KPNode
  constructor: (@node, @rootNode) ->
    @cache = []

  uuid: -> return @node.select('/UUID/0').value()

  groups: ->
    if @cache.groups? then return @cache.groups

    @cache.groups = []
    groupCount = @node.select('/*/Group').length - 1
    for groupIndex in [0..groupCount]
      @cache.groups.push(new KPGroup(@node.select('/' + groupIndex + '/Group/0'), @rootNode))

    return @cache.groups

  entries: ->
    if @cache.entries? then return @cache.entries

    @cache.entries = []
    entryCount = @node.select('/Entry/*').length - 1
    for entryIndex in [0..entryCount]
      @cache.entries.push(new KPEntry(@node.select('/Entry/' + entryIndex), @rootNode))

    return @cache.entries

class KPGroup extends KPNode

class KPEntry extends KPNode
  field: (fieldName) ->
    @rootNode.set('fieldName', fieldName)
    fieldData = @node.select('/String/*[/Key/0 == $/fieldName]').value()
    return fieldData.Value?[0] ? null

  fields: ->
    return @node.select('/String').value()

module.exports = class Reader extends KPNode
  constructor: (database) ->
    @db = SpahQL.db(database)
    super(@db.select('/KeePassFile/Root'), @db)