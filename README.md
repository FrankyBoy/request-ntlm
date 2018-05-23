# Request-NTLM-lite

[![Build Status](https://travis-ci.org/jehy/request-ntlm-lite.svg?branch=master)](https://travis-ci.org/jehy/request-ntlm-lite)
[![dependencies Status](https://david-dm.org/jehy/request-ntlm-lite/status.svg)](https://david-dm.org/jehy/request-ntlm-lite)
[![devDependencies Status](https://david-dm.org/jehy/request-ntlm-lite/dev-status.svg)](https://david-dm.org/jehy/request-ntlm-lite?type=dev)

Module for authenticating with NTLM; An ntlm authentication wrapper for the Request module.

## Install with NPM

```
$ npm install --save-dev request-ntlm-lite
```

## Usage

```javascript
var ntlm = require('request-ntlm-lite');

var opts = {
  username: 'username',
  password: 'password',
  ntlm_domain: 'yourdomain',
  workstation: 'workstation',
  url: 'http://example.com/path/to/resource'
};
var json = {
  // whatever object you want to submit
};
ntlm.post(opts, json, function(err, response) {
  // do something
});
```

Requests can also be streamed:

```javascript
ntlm.get(opts, json, null, fs.createWriteStream('example.pdf'));
```

## Changes from original ([request-ntlm-continued](https://www.npmjs.com/package/request-ntlm-continued)):

* Less dependencies
* Refactor
