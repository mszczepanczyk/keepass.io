# keepass.io
#
# Created by Pascal Mathis at 04.12.2013
# License: GPLv3 (Please see LICENSE for more information)

util = require('util')

# A list of error classes which should be generated
errorClasses = [
  'CredentialError',
  'NotImplementedError',
  'IOError',
  'ParameterError',
  'DatabaseError'
]

# KPIOError is the base class for all other errors from keepass.io
KPIOError = (msg, constr) ->
  Error.captureStackTrace(this, constr || this)
  this.message = msg || 'Error'
util.inherits(KPIOError, Error)
KPIOError::name = 'KPIOError'

# Generate error classes based on KPIOError
((errorName) ->
  errorFn = exports[errorName] = (msg) ->
    errorFn.super_.call(this, msg, this.constructor)
  util.inherits(errorFn, KPIOError)
  errorFn::name = errorName
)(errorName) for errorName in errorClasses