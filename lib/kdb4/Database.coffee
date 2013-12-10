# keepass.io
#
# Created by Pascal Mathis at 10.12.2013
# License: GPLv3 (Please see LICENSE for more information)

async = require('async')
errors = require('../util/errors')
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
    ], (err) -> cb(err))