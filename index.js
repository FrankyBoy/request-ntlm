var _       = require('lodash');
var async   = require('async');
var request = require('request');
var ntlm    = require('./lib/ntlm');

var makeRequest = function(method, options, params, callback, pipeTarget) {

  var KeepAlive = require('agentkeepalive');
  if (options.url.toLowerCase().indexOf('https://') === 0) {
    KeepAlive = KeepAlive.HttpsAgent;
  }

  var keepaliveAgent = new KeepAlive();

  if (!options.workstation) options.workstation = '';
  if (!options.ntlm_domain) options.ntlm_domain = '';
  if (!options.headers    ) options.headers     = {};

  options.ntlm = options.ntlm || {};
  options.ntlm.strict = Boolean(options.ntlm.strict);

  function startAuth($) {
    var type1msg = ntlm.createType1Message(options);
    options.method = method;
    _.extend(options.headers, {
      'Connection': 'keep-alive',
      'Authorization': type1msg
    });
    options.agent = keepaliveAgent;
    request(options, $);
  }

  function requestComplete(res, body, $) {
    if (!res.headers['www-authenticate']) {
      return options.ntlm.strict
          ? $(new Error('www-authenticate not found on response of second request'))
          : $(null, res, body);
    }

    var type2msg;
    try {
      type2msg = ntlm.parseType2Message(res.headers['www-authenticate']);
    }
    catch (ex) {
      return $(ex);
    }

    var type3msg = ntlm.createType3Message(type2msg, options);
    options.method = method;
    _.extend(options.headers, {
      'Connection': 'keep-alive',
      'Authorization': type3msg
    });

    options.agent = keepaliveAgent;

    if (typeof params == "string")
      options.body = params;
    else
      options.json = params;

    if (pipeTarget) {
      request(options, $).pipe(pipeTarget);
    } else {
      request(options, $);
    }
  }

  async.waterfall([startAuth, requestComplete], callback);
};

exports.get     = _.partial(makeRequest, 'get');
exports.post    = _.partial(makeRequest, 'post');
exports.put     = _.partial(makeRequest, 'put');
exports.patch   = _.partial(makeRequest, 'patch');
exports.delete  = _.partial(makeRequest, 'delete');
