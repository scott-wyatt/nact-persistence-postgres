![NAct Logo](https://raw.githubusercontent.com/ncthbrt/nact/master/assets/logo.svg?sanitize=true)

# NAct Postgres Encryption
A postgres persistence plugin for NAct that allows for encrypting fields on a per persisted record type basis. This allows for security and compliance in Event Sourced systems.

> NOTE: This is Community Plugin and not officially supported by the Nact maintainers.

## Usage
When persisting an event, pass an `annotations` parameter with at least the key `encrypt` to aes-256 encrypt the value of the property. This also supports sha256, hmac, md5, and bcrypt encryption.

```
persist(msg, tags, {
    "encrypt": {
      "my_obj_prop": "aes",
      "my_nested_obj_prop.my_obj_prop": "sha256",
      "my_array_prop": "hmac",
      "my_string_prop": "bcrypt",
      "my_int_prop": "md5",
      "my_float_prop": "bcrypt6",
      "my_float_prop2": "bcrypt7",
      "my_float_prop3": "bcrypt8"
    }
})
```

The result will look similar to this:

```
  data: {
    {
      "my_not_encrypted_prop": "Hello World",
      "my_obj_prop": "\\xc30d04090302e305761f7309aaa67fd240012c6396acd2b7cfa9d559db640559711f72bdce19dbb9fe9545eebb8f32612929d7765e2dfee91655ad87e73d25ee1c9e43cb92f7e356061d9a798ae3bc8987"}
  }
``` 

Then, if the need to ever scramble the encryption key (Effectively "Forget" a value), call the `scrambleEncryption` function.  This will rotate the encryption key and make the property value unrecoverable. When the aggregated state is rebuilt, the scrambled value will be present while keeping the event journal intact.

Additionally, this plugin adds a `metadata` column, so that environment specific variables for an event/snapshot can be stored and retrieved.

```
persist(msg, [], {}, {
    "ip": "127.0.0.1"
})
```


<!-- Badges -->
[![Travis branch](https://img.shields.io/travis/scott-wyatt/nact-persistence-postgres-encrypted.svg?style=flat-square)](https://travis-ci.org/scott-wyatt/nact-persistence-postgres-encrypted)
[![Coveralls](https://img.shields.io/coveralls/scott-wyatt/nact-persistence-postgres-encrypted.svg?style=flat-square)](https://coveralls.io/github/scott-wyatt/nact-persistence-postgres-encrypted) [![Dependencies](https://david-dm.org/scott-wyatt/nact-persistence-postgres-encrypted.svg?branch=master&style=flat-square)](https://david-dm.org/scott-wyatt/nact-persistence-postgres-encrypted) 
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fscott-wyatt%2Fnact-persistence-postgres-encrypted.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2scott-wyatt%2Fnact-persistence-postgres-encrypted?ref=badge_shield)

[![npm](https://img.shields.io/npm/v/nact-persistence-postgres-encrypted.svg?style=flat-square)](https://www.npmjs.com/package/nact-persistence-postgres-encrypted) [![js-semistandard-style](https://img.shields.io/badge/code%20style-semistandard-blue.svg?style=flat-square)](https://github.com/Flet/semistandard) 


## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fscott-wyatt%2Fnact-persistence-postgres-encrypted.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fscott-wyatt%2Fnact-persistence-postgres-encrypted?ref=badge_large)
