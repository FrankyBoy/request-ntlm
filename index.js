'use strict';

const request = require('request');
const ntlm    = require('./lib/ntlm');
const KeepAlive = require('agentkeepalive');

function makeRequest(method, options, params, callback, pipeTarget) {

  if (options.domain) {
    callback(new Error('Please use "ntlm_domain" instead of "domain" in options'));
    return;
  }
  let Agent = KeepAlive;
  if (options.url.toLowerCase().indexOf('https://') === 0) {
    Agent = KeepAlive.HttpsAgent;
  }

  const keepaliveAgent = new Agent();

  if (!options.workstation) options.workstation = '';
  if (!options.ntlm_domain) options.ntlm_domain = '';
  if (!options.headers) options.headers     = {};

  options.ntlm = options.ntlm || {};
  options.ntlm.strict = Boolean(options.ntlm.strict);

  function startAuth(callback2) {
    const type1msg = ntlm.createType1Message(options);
    options.method = method;
    Object.assign(options.headers, {
      Connection: 'keep-alive',
      Authorization: type1msg,
    });
    options.agent = keepaliveAgent;
    request(options, callback2);
  }

  function requestComplete(res, body, callback2) {
    if (!res.headers['www-authenticate']) {
      if (options.ntlm.strict) {
        callback2(new Error('www-authenticate not found on response of second request'));
      }
      else {
        callback2(null, res, body);
      }
      return;
    }

    const type2msg = ntlm.parseType2Message(res.headers['www-authenticate']);
    const type3msg = ntlm.createType3Message(type2msg, options);
    options.method = method;
    Object.assign(options.headers, {
      Connection: 'keep-alive',
      Authorization: type3msg,
    });

    options.agent = keepaliveAgent;

    if (typeof params === 'string')
    { options.body = params; }
    else
    { options.json = params; }

    if (pipeTarget) {
      request(options, callback2).pipe(pipeTarget);
    } else {
      request(options, callback2);
    }
  }
  startAuth((err, response, body) => requestComplete(response, body, callback));
}

module.exports = {
  get(options, params, callback, pipeTarget) {
    makeRequest('get', options, params, callback, pipeTarget);
  },
  post(options, params, callback, pipeTarget) {
    makeRequest('post', options, params, callback, pipeTarget);
  },
  put(options, params, callback, pipeTarget) {
    makeRequest('put', options, params, callback, pipeTarget);
  },
  patch(options, params, callback, pipeTarget) {
    makeRequest('patch', options, params, callback, pipeTarget);
  },
  delete(options, params, callback, pipeTarget) {
    makeRequest('delete', options, params, callback, pipeTarget);
  },
};
