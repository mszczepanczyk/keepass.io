# keepass.io
#
# Created by Pascal Mathis at 10.12.2013
# License: GPLv3 (Please see LICENSE for more information)

module.exports =
  # Header offset (12 bytes)
  HEADER_OFFSET: 12

  # KeePass Salsa20 initialization vector
  SALSA20_IV: [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A]