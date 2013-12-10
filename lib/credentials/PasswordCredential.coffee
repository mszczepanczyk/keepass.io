# keepass.io
#
# Created by Pascal Mathis at 04.12.2013
# License: GPLv3 (Please see LICENSE for more information)

crypto = require('crypto')
BaseCredential = require('./BaseCredential')

module.exports = class PasswordCredential extends BaseCredential
  getPriority: -> 10
  constructor: (@rawPassword) ->

  getKey: ->
    hashedPassword = crypto
      .createHash('sha256')
      .update(@rawPassword, 'binary')
      .digest('binary')
    return hashedPassword
