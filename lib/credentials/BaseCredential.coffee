# keepass.io
#
# Created by Pascal Mathis at 04.12.2013
# License: GPLv3 (Please see LICENSE for more information)

errors = require('../util/errors')

module.exports = class BaseCredential
  # Each credential module should specifiy its own
  # priority. When loading or saving the database, the
  # credentials will be ordered against this property.
  # Example:
  #
  # 10  PasswordCredential
  # 20  KeyfileCredential
  #
  # How the composite key will be generated: PasswordCredential + KeyfileCredential
  getPriority: -> throw new errors.NotImplementedError('`getPriority` must be implemented by each credential module')

  # Each credential module should specify its own method
  # which returns its key. The key which this method returns
  # should be usable within the composite key and will be joined
  # together with other credentials in order of their priority. (see above)
  getKey: -> throw new errors.NotImplementedError('`getKey` must be implemented by each credential module')