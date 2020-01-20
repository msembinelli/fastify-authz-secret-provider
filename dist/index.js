"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports["default"] = fastifyJwtSecret;

var _jwksRsa = _interopRequireWildcard(require("jwks-rsa"));

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) { var desc = Object.defineProperty && Object.getOwnPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : {}; if (desc.get || desc.set) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } } newObj["default"] = obj; return newObj; } }

var handleSigningKeyError = function handleSigningKeyError(err, cb) {
  // If we didn't find a match, can't provide a key.
  if (err && err.name === 'SigningKeyNotFoundError') {
    return cb(null);
  }

  return cb(err);
};

function fastifyJwtSecret(options) {
  if (options === null || options === undefined) {
    throw new _jwksRsa.ArgumentError('An options object must be provided when initializing fastifyJwtSecret');
  }

  var client = new _jwksRsa["default"](options);
  var onError = options.handleSigningKeyError || handleSigningKeyError;
  return function secretProvider(request, decoded, cb) {
    // if decoded is null, token is not present or is invalid
    if (!decoded) {
      return cb(new Error('Invalid token'), null);
    } // Only RS256 is supported.


    if (decoded.header.alg !== 'RS256') {
      return cb(new Error('Only RS256 is supported'), null);
    }

    client.getSigningKey(decoded.header.kid, function (err, key) {
      if (err) {
        return onError(err, function (newError) {
          return cb(newError, null);
        });
      } // Provide the key.


      return cb(null, key.publicKey || key.rsaPublicKey);
    });
  };
}

module.exports = fastifyJwtSecret;
//# sourceMappingURL=index.js.map