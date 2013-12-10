# keepass.io
#
# Created by Pascal Mathis at 04.12.2013
# License: GPLv3 (Please see LICENSE for more information)

fs = require('fs')
crypto = require('crypto')
errors = require('../util/errors')
BaseCredential = require('./BaseCredential')

module.exports = class KeyfileCredential extends BaseCredential
  getPriority: -> 20

  constructor: (keyfilePath) ->
    try
      @rawKeyfile = fs.readFileSync(keyfilePath).toString()
    catch err
      throw new errors.IOError(err.message)

  getKey: ->
    # TODO: Could be a bit more failsafe...
    key = @rawKeyfile.match(/<Data>(.*?)<\/Data>/)[1]
    key = new Buffer(key, 'base64').toString('binary')
    return key