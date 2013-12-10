# keepass.io
#
# Created by Pascal Mathis at 04.12.2013
# License: GPLv3 (Please see LICENSE for more information)

path = require('path')
kpio = require('../lib')

kpion = require('../native/build/Release/kpion.node')
crypto = require('crypto')

db = new kpio.KeePassIO(path.join(__dirname, 'KeePass.kdbx'))
db.addCredential(new kpio.KeyfileCredential(path.join(__dirname, 'KeePass.key')))
db.addCredential(new kpio.PasswordCredential('123456'))
db.loadDatabase((err) ->
  # If an error occured, you should throw it immediately
  if err then throw err

  # Now you can start working with the KeePass database :)
)