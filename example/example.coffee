# keepass.io
#
# Created by Pascal Mathis at 04.12.2013
# License: GPLv3 (Please see LICENSE for more information)

path = require('path')
kpio = require('../lib')

#db = new kpio.KeePassIO(path.join(__dirname, 'KeePass.kdbx'))
#db.addCredential(new kpio.KeyfileCredential(path.join(__dirname, 'KeePass.key')))
#db.addCredential(new kpio.PasswordCredential('testdebugtest'))

db = new kpio.KeePassIO(path.join(__dirname, 'test.kdbx'))
db.addCredential(new kpio.PasswordCredential('123456'))
db.loadDatabase((err) ->
  # If an error occured, you should "handle" it immediately
  if err then throw err

  # Now you can start working with the KeePass database :)
  groups = db.reader.groups()
  for group in groups
    for entry in group.entries()
      console.log(entry.fields())
      console.log(entry.field('Title'))

)