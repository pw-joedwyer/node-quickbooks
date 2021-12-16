/**
 * @file Node.js client for QuickBooks V3 API
 * @name node-quickbooks
 * @author Michael Cohen <michael_cohen@intuit.com>
 * @license ISC
 * @copyright 2014 Michael Cohen
 */

var request   = require('request'),
    uuid      = require('uuid'),
    debug     = require('request-debug'),
    util      = require('util'),
    formatISO = require('date-fns/fp/formatISO'),
    _         = require('underscore'),
    Promise   = require('bluebird'),
    version   = require('./package.json').version,
    jxon      = require('jxon');

module.exports = QuickBooks

QuickBooks.APP_CENTER_BASE = 'https://appcenter.intuit.com';
QuickBooks.V3_ENDPOINT_BASE_URL = 'https://sandbox-quickbooks.api.intuit.com/v3/company/';
QuickBooks.QUERY_OPERATORS = ['=', 'IN', '<', '>', '<=', '>=', 'LIKE'];
QuickBooks.TOKEN_URL = 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer';
QuickBooks.REVOKE_URL = 'https://developer.api.intuit.com/v2/oauth2/tokens/revoke';

var OAUTH_ENDPOINTS = {
  '1.0a': function (callback) {
    callback({
      REQUEST_TOKEN_URL: 'https://oauth.intuit.com/oauth/v1/get_request_token',
      ACCESS_TOKEN_URL: 'https://oauth.intuit.com/oauth/v1/get_access_token',
      APP_CENTER_URL: QuickBooks.APP_CENTER_BASE + '/Connect/Begin?oauth_token=',
      RECONNECT_URL: QuickBooks.APP_CENTER_BASE + '/api/v1/connection/reconnect',
      DISCONNECT_URL: QuickBooks.APP_CENTER_BASE + '/api/v1/connection/disconnect'
    });
  },

  '2.0': function (callback, discoveryUrl) {
    var NEW_ENDPOINT_CONFIGURATION = {};
    request({
      url: discoveryUrl,
      headers: {
        Accept: 'application/json'
      }
    }, function (err, res) {
      if (err) {
        console.log(err);
        return err;
      }

      var json;
      try {
          json = JSON.parse(res.body);
      } catch (error) {
          console.log(error);
          return error;
      }
      NEW_ENDPOINT_CONFIGURATION.AUTHORIZATION_URL = json.authorization_endpoint;;
      NEW_ENDPOINT_CONFIGURATION.TOKEN_URL = json.token_endpoint;
      NEW_ENDPOINT_CONFIGURATION.USER_INFO_URL = json.userinfo_endpoint;
      NEW_ENDPOINT_CONFIGURATION.REVOKE_URL = json.revocation_endpoint;
      callback(NEW_ENDPOINT_CONFIGURATION);
    });
  }
};

OAUTH_ENDPOINTS['1.0'] = OAUTH_ENDPOINTS['1.0a'];

/**
 * Sets endpoints per OAuth version
 *
 * @param version - 1.0 for OAuth 1.0a, 2.0 for OAuth 2.0
 * @param useSandbox - true to use the OAuth 2.0 sandbox discovery document, false (or unspecified, for backward compatibility) to use the prod discovery document.
 */
QuickBooks.setOauthVersion = function (version, useSandbox) {
  version = (typeof version === 'number') ? version.toFixed(1) : version;
  QuickBooks.version = version;
  var discoveryUrl = useSandbox ? 'https://developer.intuit.com/.well-known/openid_sandbox_configuration/' : 'https://developer.api.intuit.com/.well-known/openid_configuration/';
  OAUTH_ENDPOINTS[version](function (endpoints) {
    for (var k in endpoints) {
      QuickBooks[k] = endpoints[k];
    }
  }, discoveryUrl);
};

QuickBooks.setOauthVersion('1.0');

/**
 * Node.js client encapsulating access to the QuickBooks V3 Rest API. An instance
 * of this class should be instantiated on behalf of each user accessing the api.
 *
 * @param consumerKey - application key
 * @param consumerSecret  - application password
 * @param token - the OAuth generated user-specific key
 * @param tokenSecret - the OAuth generated user-specific password
 * @param realmId - QuickBooks companyId, returned as a request parameter when the user is redirected to the provided callback URL following authentication
 * @param useSandbox - boolean - See https://developer.intuit.com/v2/blog/2014/10/24/intuit-developer-now-offers-quickbooks-sandboxes
 * @param debug - boolean flag to turn on logging of HTTP requests, including headers and body
 * @param minorversion - integer to set minorversion in request
 * @constructor
 */
function QuickBooks(consumerKey, consumerSecret, token, tokenSecret, realmId, useSandbox, debug, minorversion, oauthversion, refreshToken) {
  var prefix = _.isObject(consumerKey) ? 'consumerKey.' : '';
  this.consumerKey = eval(prefix + 'consumerKey');
  this.consumerSecret = eval(prefix + 'consumerSecret');
  this.token = eval(prefix + 'token');
  this.tokenSecret = eval(prefix + 'tokenSecret');
  this.realmId = eval(prefix + 'realmId');
  this.useSandbox = eval(prefix + 'useSandbox');
  this.debug = eval(prefix + 'debug');
  this.endpoint = this.useSandbox
    ? QuickBooks.V3_ENDPOINT_BASE_URL
    : QuickBooks.V3_ENDPOINT_BASE_URL.replace('sandbox-', '');
  this.minorversion = eval(prefix + 'minorversion') || 4;
  this.oauthversion = eval(prefix + 'oauthversion') || '1.0a';
  this.refreshToken = eval(prefix + 'refreshToken') || null;
  if (!eval(prefix + 'tokenSecret') && this.oauthversion !== '2.0') {
    throw new Error('tokenSecret not defined');
  }
}

/**
 *
 * Use the refresh token to obtain a new access token.
 *
 *
 */

QuickBooks.prototype.refreshAccessToken = function(callback) {
    var auth = (new Buffer(this.consumerKey + ':' + this.consumerSecret).toString('base64'));

    var postBody = {
        url: QuickBooks.TOKEN_URL,
        headers: {
            Accept: 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: 'Basic ' + auth,
        },
        form: {
            grant_type: 'refresh_token',
            refresh_token: this.refreshToken
        }
    };

    request.post(postBody, (function (e, r, data) {
        if (r && r.body) {
            var refreshResponse = JSON.parse(r.body);
            this.refreshToken = refreshResponse.refresh_token;
            this.token = refreshResponse.access_token;
            if (callback) callback(e, refreshResponse);
        } else {
            if (callback) callback(e, r, data);
        }
    }).bind(this));
};

/**
 * Use either refresh token or access token to revoke access (OAuth2).
 *
 * @param useRefresh - boolean - Indicates which token to use: true to use the refresh token, false to use the access token.
 * @param {function} callback - Callback function to call with error/response/data results.
 */
QuickBooks.prototype.revokeAccess = function(useRefresh, callback) {
    var auth = (new Buffer(this.consumerKey + ':' + this.consumerSecret).toString('base64'));
    var revokeToken = useRefresh ? this.refreshToken : this.token;
    var postBody = {
        url: QuickBooks.REVOKE_URL,
        headers: {
            Accept: 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: 'Basic ' + auth,
        },
        form: {
            token: revokeToken
        }
    };

    request.post(postBody, (function(e, r, data) {
        if (r && r.statusCode === 200) {
            this.refreshToken = null;
            this.token = null;
            this.realmId = null;
        }
        if (callback) callback(e, r, data);
    }).bind(this));
};

/**
 * Get user info (OAuth2).
 *
 * @param {function} callback - Callback function to call with error/response/data results.
 */
QuickBooks.prototype.getUserInfo = function(callback) {
  module.request(this, 'get', {url: QuickBooks.USER_INFO_URL}, null, callback);
};

/**
 * Batch operation to enable an application to perform multiple operations in a single request.
 * The following batch items are supported:
     create
     update
     delete
     query
 * The maximum number of batch items in a single request is 30.
 *
 * @param  {object} items - JavaScript array of batch items
 * @param  {function} callback - Callback function which is called with any error and list of BatchItemResponses
 */
QuickBooks.prototype.batch = function(items, callback) {
  module.request(this, 'post', {url: '/batch'}, {BatchItemRequest: items}, callback)
}

/**
 * The change data capture (CDC) operation returns a list of entities that have changed since a specified time.
 *
 * @param  {object} entities - Comma separated list or JavaScript array of entities to search for changes
 * @param  {object} since - JavaScript Date or string representation of the form '2012-07-20T22:25:51-07:00' to look back for changes until
 * @param  {function} callback - Callback function which is called with any error and list of changes
 */
QuickBooks.prototype.changeDataCapture = function(entities, since, callback) {
  var url = '/cdc?entities='
  url += typeof entities === 'string' ? entities : entities.join(',')
  url += '&changedSince='
  url += typeof since === 'string' ? since : formatISO(since)
  module.request(this, 'get', {url: url}, null, callback)
}

/**
 * Uploads a file as an Attachable in QBO, optionally linking it to the specified
 * QBO Entity.
 *
 * @param  {string} filename - the name of the file
 * @param  {string} contentType - the mime type of the file
 * @param  {object} stream - ReadableStream of file contents
 * @param  {object} entityType - optional string name of the QBO entity the Attachable will be linked to (e.g. Invoice)
 * @param  {object} entityId - optional Id of the QBO entity the Attachable will be linked to
 * @param  {function} callback - callback which receives the newly created Attachable
 */
QuickBooks.prototype.upload = function(filename, contentType, stream, entityType, entityId, callback) {
  var that = this
  var opts = {
    url: '/upload',
    formData: {
      file_content_01: {
        value: stream,
        options: {
          filename: filename,
          contentType: contentType
        }
      }
    }
  }
  module.request(this, 'post', opts, null, module.unwrap(function(err, data) {
    if (err || data[0].Fault) {
      (callback || entityType)(err || data[0], null)
    } else if (_.isFunction(entityType)) {
      entityType(null, data[0].Attachable)
    } else {
      var id = data[0].Attachable.Id
      that.update('attachable', {
        Id: id,
        SyncToken: '0',
        AttachableRef: [{
          EntityRef: {
            type: entityType,
            value: entityId + ''
          }
        }]
      }, function(err, data) {
        callback(err, data)
      })
    }
  }, 'AttachableResponse'))
}

/**
 * Retrieves the object from QuickBooks
 *
 * @param  {string} obj - The object to be retrieved
 * @param  {string} Id - The Id of persistent object
 * @param  {function} callback - Callback function which is called with any error and the persistent object
 */
QuickBooks.prototype.get = function(obj, id, callback) {
  promisify(module.read(this, obj, id, callback));
}

/**
 * Retrieves an ExchangeRate from QuickBooks
 *
 * @param  {object} options - An object with options including the required `sourcecurrencycode` parameter and optional `asofdate` parameter.
 * @param  {function} callback - Callback function which is called with any error and the ExchangeRate
 */
QuickBooks.prototype.getExchangeRate = function(options, callback) {
  var url = "/exchangerate";
  module.request(this, 'get', {url: url, qs: options}, null, callback)
}


/**
 * Retrieves the Estimate PDF from QuickBooks
 *
 * @param  {string} Id - The Id of persistent Estimate
 * @param  {function} callback - Callback function which is called with any error and the Estimate PDF
 */
QuickBooks.prototype.getEstimatePdf = function(id, callback) {
    module.read(this, 'Estimate', id + '/pdf', callback)
};

/**
 * Emails the Estimate PDF from QuickBooks to the address supplied in Estimate.BillEmail.EmailAddress
 * or the specified 'sendTo' address
 *
 * @param  {string} Id - The Id of persistent Estimate
 * @param  {string} sendTo - optional email address to send the PDF to. If not provided, address supplied in Estimate.BillEmail.EmailAddress will be used
 * @param  {function} callback - Callback function which is called with any error and the Estimate PDF
 */
QuickBooks.prototype.sendEstimatePdf = function(id, sendTo, callback) {
  var path = '/estimate/' + id + '/send'
  callback = _.isFunction(sendTo) ? sendTo : callback
  if (sendTo && ! _.isFunction(sendTo)) {
    path += '?sendTo=' + sendTo
  }
  module.request(this, 'post', {url: path}, null, module.unwrap(callback, 'Estimate'))
}

/**
 * Retrieves the Invoice PDF from QuickBooks
 *
 * @param  {string} Id - The Id of persistent Invoice
 * @param  {function} callback - Callback function which is called with any error and the Invoice PDF
 */
QuickBooks.prototype.getInvoicePdf = function(id, callback) {
  module.read(this, 'Invoice', id + '/pdf', callback)
}

/**
 * Emails the Invoice PDF from QuickBooks to the address supplied in Invoice.BillEmail.EmailAddress
 * or the specified 'sendTo' address
 *
 * @param  {string} Id - The Id of persistent Invoice
 * @param  {string} sendTo - optional email address to send the PDF to. If not provided, address supplied in Invoice.BillEmail.EmailAddress will be used
 * @param  {function} callback - Callback function which is called with any error and the Invoice PDF
 */
QuickBooks.prototype.sendInvoicePdf = function(id, sendTo, callback) {
  var path = '/invoice/' + id + '/send'
  callback = _.isFunction(sendTo) ? sendTo : callback
  if (sendTo && ! _.isFunction(sendTo)) {
    path += '?sendTo=' + sendTo
  }
  module.request(this, 'post', {url: path}, null, module.unwrap(callback, 'Invoice'))
}

/**
 * Emails the Purchase Order from QuickBooks to the address supplied in PurchaseOrder.POEmail.Address
 * or the specified 'sendTo' address
 *
 * @param  {string} Id - The Id of persistent Purchase Order
 * @param  {string} sendTo - optional email address to send the PDF to. If not provided, address supplied in PurchaseOrder.POEmail.Address will be used
 * @param  {function} callback - Callback function which is called with any error and the Invoice PDF
 */
QuickBooks.prototype.sendPurchaseOrder = function(id, sendTo, callback) {
  var path = '/purchaseorder/' + id + '/send'
  callback = _.isFunction(sendTo) ? sendTo : callback
  if (sendTo && ! _.isFunction(sendTo)) {
    path += '?sendTo=' + sendTo
  }
  module.request(this, 'post', {url: path}, null, module.unwrap(callback, 'PurchaseOrder'))
}

/**
 * Retrieves the SalesReceipt PDF from QuickBooks
 *
 * @param  {string} Id - The Id of persistent SalesReceipt
 * @param  {function} callback - Callback function which is called with any error and the SalesReceipt PDF
 */
QuickBooks.prototype.getSalesReceiptPdf = function(id, callback) {
  module.read(this, 'salesReceipt', id + '/pdf', callback)
}

/**
 * Emails the SalesReceipt PDF from QuickBooks to the address supplied in SalesReceipt.BillEmail.EmailAddress
 * or the specified 'sendTo' address
 *
 * @param  {string} Id - The Id of persistent SalesReceipt
 * @param  {string} sendTo - optional email address to send the PDF to. If not provided, address supplied in SalesReceipt.BillEmail.EmailAddress will be used
 * @param  {function} callback - Callback function which is called with any error and the SalesReceipt PDF
 */
QuickBooks.prototype.sendSalesReceiptPdf = function(id, sendTo, callback) {
  var path = '/salesreceipt/' + id + '/send'
  callback = _.isFunction(sendTo) ? sendTo : callback
  if (sendTo && ! _.isFunction(sendTo)) {
    path += '?sendTo=' + sendTo
  }
  module.request(this, 'post', {url: path}, null, module.unwrap(callback, 'SalesReceipt'))
}

/**
 * Voids the Invoice from QuickBooks
 *
 * @param  {object} idOrEntity - The persistent Invoice to be voided, or the Id of the Invoice, in which case an extra GET request will be issued to first retrieve the Invoice
 * @param  {function} callback - Callback function which is called with any error and the persistent Invoice
 */
QuickBooks.prototype.voidInvoice = function (idOrEntity, callback) {
    module.void(this, 'invoice', idOrEntity, callback)
}

/**
 * Voids QuickBooks version of Payment
 *
 * @param  {object} payment - The persistent Payment, including Id and SyncToken fields
 * @param  {function} callback - Callback function which is called with any error and the persistent Payment
 */
QuickBooks.prototype.voidPayment = function (payment, callback) {
    payment.void = true;
    payment.sparse = true;
    module.update(this, 'payment', payment, callback)
}

module.request = function(context, verb, options, entity, callback) {
  var url = context.endpoint + context.realmId + options.url
  if (options.url === QuickBooks.RECONNECT_URL || options.url == QuickBooks.DISCONNECT_URL || options.url === QuickBooks.REVOKE_URL || options.url === QuickBooks.USER_INFO_URL) {
    url = options.url
  }
  var opts = {
    url:     url,
    qs:      options.qs || {},
    headers: options.headers || {},
    json:    true
  }

  if (entity && entity.allowDuplicateDocNum) {
    delete entity.allowDuplicateDocNum;
    opts.qs.include = 'allowduplicatedocnum';
  }

  if (entity && entity.requestId) {
    opts.qs.requestid = entity.requestId;
    delete entity.requestId;
  }

  opts.qs.minorversion = opts.qs.minorversion || context.minorversion;
  opts.headers['User-Agent'] = 'node-quickbooks: version ' + version
  opts.headers['Request-Id'] = uuid.v1()
  opts.qs.format = 'json';
  if (context.oauthversion == '2.0'){
      opts.headers['Authorization'] =  'Bearer ' + context.token
  } else {
        opts.oauth = module.oauth(context);
  };
  if (options.url.match(/pdf$/)) {
    opts.headers['accept'] = 'application/pdf'
    opts.encoding = null
  }
  if (entity !== null) {
    opts.body = entity
  }
  if (options.formData) {
    opts.formData = options.formData
  }
  if ('production' !== process.env.NODE_ENV && context.debug) {
    debug(request)
  }
  request[verb].call(context, opts, function (err, res, body) {
    if ('production' !== process.env.NODE_ENV && context.debug) {
      console.log('invoking endpoint: ' + url)
      console.log(entity || '')
      console.log(JSON.stringify(body, null, 2));
    }
    if (callback) {
      if (err ||
          res.statusCode >= 300 ||
          (_.isObject(body) && body.Fault && body.Fault.Error && body.Fault.Error.length) ||
          (_.isString(body) && !_.isEmpty(body) && body.indexOf('<') === 0)) {
        callback(err || body, body, res)
      } else {
        callback(null, body, res)
      }
    }
  })
}

module.xmlRequest = function(context, url, rootTag, callback) {
  module.request(context, 'get', {url:url}, null, (err, body) => {
    var json =
        body.constructor === {}.constructor ? body :
            (body.constructor === "".constructor ?
                (body.indexOf('<') === 0 ? jxon.stringToJs(body)[rootTag] : body) : body);
    callback(json.ErrorCode === 0 ? null : json, json);
  })
}



QuickBooks.prototype.reconnect = function(callback) {
  module.xmlRequest(this, QuickBooks.RECONNECT_URL, 'ReconnectResponse', callback);
}

QuickBooks.prototype.disconnect = function(callback) {
  module.xmlRequest(this, QuickBooks.DISCONNECT_URL, 'PlatformResponse', callback);
}

/**
 * Finds all objects in QuickBooks, optionally matching the specified criteria
 *
 * @param  {string} objType - The object type to be persisted in QuickBooks
 * @param  {object} criteria - (Optional) String or single-valued map converted to a where clause of the form "where key = 'value'"
 * @param  {function} callback - Callback function which is called with any error and the list of objects
 */
 QuickBooks.prototype.query = function(criteria, callback) {
  module.query(this, objType, criteria).then(function(data) {
    (callback || criteria)(null, data)
  }).catch(function(err) {
    (callback || criteria)(err, err)
  })
}

/**
 * Creates the object in QuickBooks
 *
 * @param  {string} objType - The object type to be persisted in QuickBooks
 * @param  {object} obj - The unsaved object, to be persisted in QuickBooks
 * @param  {function} callback - Callback function which is called with any error and the persistent object
 */
 QuickBooks.prototype.create = function(objType, obj, callback) {
  module.create(this, objType, obj, callback)
}

/**
 * Updates QuickBooks version of object
 *
 * @param  {string} objType - The object type to be persisted in QuickBooks
 * @param  {object} obj - The persistent object, including Id and SyncToken fields
 * @param  {function} callback - Callback function which is called with any error and the persistent object
 */
 QuickBooks.prototype.update = function(objType, obj, callback) {
  module.update(this, objType, obj, callback)
}

/**
 * Deletes the object from QuickBooks
 *
 * @param  {string} objType - The object type to be deleted in QuickBooks
 * @param  {object} idOrEntity - The persistent object to be deleted, or the Id of the object, in which case an extra GET request will be issued to first retrieve the object
 * @param  {function} callback - Callback function which is called with any error and the status of the persistent object
 */
 QuickBooks.prototype.delete = function(objType, idOrEntity, callback) {
  module.delete(this, objType, idOrEntity, callback)
}

/**
 * Retrieves a Report from QuickBooks
 *
 * @param  {string} reportName - The report to be retrieved in QuickBooks
 * @param  {object} options - (Optional) Map of key-value pairs passed as options to the Report
 * @param  {function} callback - Callback function which is called with any error and the Report
 */
 QuickBooks.prototype.getReport = function(reportName, options, callback) {
  module.report(this, reportName, options, callback)
}

// **********************  CRUD Api **********************
module.create = function(context, entityName, entity, callback) {
  var url = '/' + entityName.toLowerCase()
  module.request(context, 'post', {url: url}, entity, module.unwrap(callback, entityName))
}

module.read = function(context, entityName, id, callback) {
  var url = '/' + entityName.toLowerCase()
  if (id) url = url + '/' + id
  module.request(context, 'get', {url: url}, null, module.unwrap(callback, entityName))
}

module.update = function(context, entityName, entity, callback) {
  if (_.isUndefined(entity.Id) ||
      _.isEmpty(entity.Id + '') ||
      _.isUndefined(entity.SyncToken) ||
      _.isEmpty(entity.SyncToken + '')) {
    if (entityName !== 'exchangerate') {
      throw new Error(entityName + ' must contain Id and SyncToken fields: ' +
          util.inspect(entity, {showHidden: false, depth: null}))
    }
  }
  if (! entity.hasOwnProperty('sparse')) {
    entity.sparse = true
  }
  var url = '/' + entityName.toLowerCase() + '?operation=update'
  var opts = {url: url}
  if (entity.void && entity.void.toString() === 'true') {
    opts.qs = { include: 'void' }
    delete entity.void
  }
  module.request(context, 'post', opts, entity, module.unwrap(callback, entityName))
}

module.delete = function(context, entityName, idOrEntity, callback) {
  var url = '/' + entityName.toLowerCase() + '?operation=delete'
  callback = callback || function() {}
  if (_.isObject(idOrEntity)) {
    module.request(context, 'post', {url: url}, idOrEntity, callback)
  } else {
    module.read(context, entityName, idOrEntity, function(err, entity) {
      if (err) {
        callback(err)
      } else {
        module.request(context, 'post', {url: url}, entity, callback)
      }
    })
  }
}

module.void = function (context, entityName, idOrEntity, callback) {
  var url = '/' + entityName.toLowerCase() + '?operation=void'
  callback = callback || function () { }
  if (_.isObject(idOrEntity)) {
    module.request(context, 'post', { url: url }, idOrEntity, callback)
  } else {
    module.read(context, entityName, idOrEntity, function (err, entity) {
      if (err) {
        callback(err)
      } else {
        module.request(context, 'post', { url: url }, entity, callback)
      }
    })
  }
}

// **********************  Query Api **********************
module.requestPromise = Promise.promisify(module.request)

module.query = function(context, entity, criteria) {

  // criteria is potentially mutated within this function -
  // so make a copy of it first
  if (! _.isFunction(criteria) && (_.isObject(criteria) || _.isArray(criteria))) {
    criteria = JSON.parse(JSON.stringify(criteria));
  }

  var url = '/query?query@@select * from ' + entity
  var count = function(obj) {
    for (var p in obj) {
      if (obj[p] && p.toLowerCase() === 'count') {
        url = url.replace('select \* from', 'select count(*) from')
        delete obj[p]
      }
    }
  }
  count(criteria)
  if (_.isArray(criteria)) {
    for (var i = 0; i < criteria.length; i++) {
      if (_.isObject(criteria[i])) {
        var j = Object.keys(criteria[i]).length
        count(criteria[i])
        if (j !== Object.keys(criteria[i]).length) {
          criteria.splice(i, i + 1)
        }
      }
    }
  }

  var fetchAll = false, limit = 1000, offset = 1
  if (_.isArray(criteria)) {
    var lmt = _.find(criteria, function(obj) {
      return obj.field && obj.field === 'limit'
    })
    if (lmt) limit = lmt.value
    var ofs = _.find(criteria, function(obj) {
      return obj.field && obj.field === 'offset'
    })
    if (! ofs) {
      criteria.push({field: 'offset', value: 1})
    } else {
      offset = ofs.value
    }
    var fa = _.find(criteria, function(obj) {
      return obj.field && obj.field === 'fetchAll'
    })
    if (fa && fa.value) fetchAll = true
  } else if (_.isObject(criteria)) {
    limit = criteria.limit = criteria.limit || 1000
    offset = criteria.offset = criteria.offset || 1
    if (criteria.fetchAll) fetchAll = true
  }

  if (criteria && !_.isFunction(criteria)) {
    url += module.criteriaToString(criteria) || ''
    url = url.replace(/%/g, '%25')
             .replace(/'/g, '%27')
             .replace(/=/g, '%3D')
             .replace(/</g, '%3C')
             .replace(/>/g, '%3E')
             .replace(/&/g, '%26')
             .replace(/#/g, '%23')
             .replace(/\\/g, '%5C')
             .replace(/\+/g, '%2B')
  }
  url = url.replace('@@', '=')

  return new Promise(function(resolve, reject) {
    module.requestPromise(context, 'get', {url: url}, null).then(function(data) {
      var fields = Object.keys(data.QueryResponse)
      var key = _.find(fields, function(k) { return k.toLowerCase() === entity.toLowerCase()})
      if (fetchAll) {
        if (data && data.QueryResponse && data.QueryResponse.maxResults === limit) {
          if (_.isArray(criteria)) {
            _.each(criteria, function(e) {
              if (e.field === 'offset') e.value = e.value + limit
            })
          } else if (_.isObject(criteria)) {
            criteria.offset = criteria.offset + limit
          }
          return module.query(context, entity, criteria).then(function(more) {
            data.QueryResponse[key] = data.QueryResponse[key].concat(more.QueryResponse[key] || [])
            data.QueryResponse.maxResults = data.QueryResponse.maxResults + (more.QueryResponse.maxResults || 0)
            data.time = more.time || data.time
            resolve(data)
          })
        } else {
          resolve(data)
        }
      } else {
        resolve(data)
      }
    }).catch(function(err) {
      reject(err)
    })
  })
}


// **********************  Report Api **********************
module.report = function(context, reportType, criteria, callback) {
  var url = '/reports/' + reportType
  if (criteria && typeof criteria !== 'function') {
    url += module.reportCriteria(criteria) || ''
  }
  module.request(context, 'get', {url: url}, null, typeof criteria === 'function' ? criteria : callback)
}


module.oauth = function(context) {
  return {
    consumer_key:    context.consumerKey,
    consumer_secret: context.consumerSecret,
    token:           context.token,
    token_secret:    context.tokenSecret
  }
}

module.isNumeric = function(n) {
  return ! isNaN(parseFloat(n)) && isFinite(n);
}

module.checkProperty = function(field, name) {
  return (field && field.toLowerCase() === name)
}

module.toCriterion = function(c) {
  var fields = _.keys(c)
  if (_.intersection(fields, ['field', 'value']).length === 2) {
    return {
      field: c.field,
      value: c.value,
      operator: c.operator || '='
    }
  } else {
    return fields.map(function(k) {
      return {
        field: k,
        value: c[k],
        operator: _.isArray(c[k]) ? 'IN' : '='
      }
    })
  }
}

module.criteriaToString = function(criteria) {
  if (_.isString(criteria)) return criteria.indexOf(' ') === 0 ? criteria : " " + criteria
  var cs = _.isArray(criteria) ? criteria.map(module.toCriterion) : module.toCriterion(criteria)
  var flattened = _.flatten(cs)
  var sql = '', limit, offset, desc, asc
  for (var i=0, l=flattened.length; i<l; i++) {
    var criterion = flattened[i];
    if (module.checkProperty(criterion.field, 'fetchall')) {
      continue
    }
    if (module.checkProperty(criterion.field, 'limit')) {
      limit = criterion.value
      continue
    }
    if (module.checkProperty(criterion.field, 'offset')) {
      offset = criterion.value
      continue
    }
    if (module.checkProperty(criterion.field, 'desc')) {
      desc = criterion.value
      continue
    }
    if (module.checkProperty(criterion.field, 'asc')) {
      asc = criterion.value
      continue
    }
    if (sql != '') {
      sql += ' and '
    }
    sql += criterion.field + ' ' + criterion.operator + ' '
    var quote = function(x) {
      return _.isString(x) ? "'" + x.replace(/'/g, "\\'") + "'" : x
    }
    if (_.isArray(criterion.value)) {
      sql += '(' + criterion.value.map(quote).join(',') + ')'
    } else {
      sql += quote(criterion.value)
    }
  }
  if (sql != '') {
    sql = ' where ' + sql
  }
  if (asc)  sql += ' orderby ' + asc + ' asc'
  if (desc) sql += ' orderby ' + desc + ' desc'
  sql += ' startposition ' + (offset || 1)
  sql += ' maxresults ' + (limit || 1000)
  return sql
}

module.reportCriteria = function(criteria) {
  var s = '?'
  for (var p in criteria) {
    s += p + '=' + criteria[p] + '&'
  }
  return s
}

module.capitalize = function(s) {
  return s.substring(0, 1).toUpperCase() + s.substring(1)
}

QuickBooks.prototype.capitalize = module.capitalize

module.pluralize = function(s) {
  var last = s.substring(s.length - 1)
  if (last === 's') {
    return s + "es"
  } else if (last === 'y') {
    return s.substring(0, s.length - 1) + "ies"
  } else {
    return s + 's'
  }
}

QuickBooks.prototype.pluralize = module.pluralize

module.unwrap = function(callback, entityName) {
  if (! callback) return function(err, data) {}
  return function(err, data) {
    if (err) {
      if (callback) callback(err)
    } else {
      var name = module.capitalize(entityName)
      if (callback) callback(err, (data || {})[name] || data)
    }
  }
}
