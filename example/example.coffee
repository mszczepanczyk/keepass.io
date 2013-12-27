# keepass.io
#
# Created by Pascal Mathis at 04.12.2013
# License: GPLv3 (Please see LICENSE for more information)

path = require('path')
kpio = require('../lib')

db = new kpio.KeePassIO(path.join(__dirname, 'test.kdbx'))
db.addCredential(new kpio.PasswordCredential('123456'))
db.loadDatabase((err, api) ->
  # If an error occured, you should "handle" it immediately
  if err then throw err

  console.log(api.getJson())
  console.log(api.findNodeByUuid('TGCQ5xfOoUCV+yLGGCxM8g=='))
)