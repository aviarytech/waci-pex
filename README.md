This test suite is being used to tease out the proper incantation of verifiable credential calls to successfully create and verify a BBS+ selective disclosure derived credential.

The libraries under test are:

- [vc-js](https://github.com/digitalbazaar/vc-js)
  - this is an out of date version of @digitalbazaar/vc as the mattr suite does not work for the latest version
- [@transmute/vc.js](https://github.com/transmute-industries/verifiable-data)
- [@mattrglobal/jsonld-signatures-bbs](https://github.com/mattrglobal/jsonld-signatures-bbs)

The folder names have been given a `<issuer>`-`<deriver>`-`<verifier>` structure
