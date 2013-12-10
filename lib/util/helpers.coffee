# keepass.io
#
# Created by Pascal Mathis at 04.12.2013
# License: GPLv3 (Please see LICENSE for more information)

PyPackJS = require('./pypackjs')

exports.readBuffer = readBuffer = (buffer, offset, length, type) ->
  if not type then type = 'I'
  slicedBuffer = buffer.slice(offset, offset + length)
  return PyPackJS.unpack('<' + type, slicedBuffer, 0)[0]

exports.getDatabaseSignature = getDatabaseSignature = (buffer) ->
  return [readBuffer(buffer, 0, 4), readBuffer(buffer, 4, 4)]

exports.sortBy = (key, a, b, r) ->
  r = if r then 1 else -1
  return -1*r if a[key] > b[key]
  return +1*r if a[key] < b[key]
  return 0