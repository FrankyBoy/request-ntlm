'use strict';

const should = require('should');
const request = require('../index.js');
const http = require('http');

describe('request-ntlm-lite', function () {

  function simpleGetRequest(options) {
    return (callback)=>{
      request.get(options, undefined, (err, res, body) => {
        should.not.exist(err);
        should.exist(res);
        should.exist(body);
        callback();
      });
    };
  }

  this.timeout(10000);

  describe('NTLM requests', () => {
    it('successfully execute a request against an NTLM server', (done) => {
      // fake ntlm server code from https://gist.github.com/Piot/3049352
      http.createServer((req, res) => {
        const auth = req.headers.authorization;
        let authString;
        if (auth && auth.substr(0, 4) === 'NTLM') {
          if (auth.length > 200) {
            res.end('Done');
            return;
          }
          authString = 'NTLM TlRMTVNTUAACAAAADAAMADAAAAABAoEAASNFZ4mrze8AAAAAAAAAAGIAYgA8AAAARA' +
            'BPAE0AQQBJAE4AAgAMAEQATwBNAEEASQBOAAEADABTAEUAUgBWAEUAUgAEABQAZABvAG0AYQBpAG4ALgBj' +
            'AG8AbQADACIAcwBlAHIAdgBlAHIALgBkAG8AbQBhAGkAbgAuAGMAbwBtAAAAAAA=';
        } else {
          authString = 'NTLM';
        }
        res.writeHead(401, {'WWW-Authenticate': authString});
        res.end();
      }).listen(8081);

      const options =
        {
          username: 'username',
          password: 'password',
          ntlm_domain: 'yourdomain',
          workstation: 'workstation',
          url: 'http://127.0.0.1:8081',
          strictSSL: false,
        };
      simpleGetRequest(options)(done);
    });
  });

  describe('non-NTLM requests', () => {

    const options = {
      username: 'username',
      password: 'password',
      ntlm_domain: 'yourdomain',
      workstation: 'workstation',
      url: 'https://www.google.com/search?q=ntlm',
      strictSSL: false,
    };

    it('successfully execute a request against a non-NTLM server', (done) => {
      simpleGetRequest(options)(done);
    });

    it('fails when requesting non-NTLM resource with `options.ntlm.strict`', (done) => {
      options.ntlm = {strict: true};
      request.get(options, undefined, (err) => {
        should.exist(err);
        done();
      });
    });
  });
});
