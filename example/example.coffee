# keepass.io
#
# Created by Pascal Mathis at 04.12.2013
# License: GPLv3 (Please see LICENSE for more information)

path = require('path')
kpio = require('../lib')

db = new kpio.KeePassIO(path.join(__dirname, 'test.kdbx'))
db.addCredential(new kpio.PasswordCredential('123456'))
db.loadDatabase((err) ->
  # If an error occured, you should "handle" it immediately
  if err then throw err

  # Now you can start working with the KeePass database :)
  recursive = (group) ->
    console.log('Group name: ' + group.node.value().Name)

    for entry in group.entries()
      console.log('Entry UUID: ' + entry.uuid())
      console.log('Entry Title: ' + entry.field('Title'))
      console.log('Entry Password: ' + entry.field('Password'))
      console.log(entry.fields())

    recursive(group) for group in group.groups()

  groups = db.reader.groups()
  recursive(group) for group in groups
)