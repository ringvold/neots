# neots (NeoOTS)

Inspired by https://github.com/sniptt-official/ots but also supports
ChaCha20-Poly1305 (ChaPoly) in addition to AES GCM.

Backend supporting ChaPoly and AES GCM: https://github.com/ringvold/ots

**TODO:**
- [x] Actually support expires flag (expiry is hard coded to 2 hours)


## Why ChaPoly?
Some people seems to prefer ChaCha20-Poly1305 (ChaPoly for short) over AES
GCM. It does not require hardware acceleration to be fast. It might be a bit
more secure, theoretically, maybe, but what do I know, I'm no expert. 🤷‍♂️

Here is some reading though:
- https://soatok.blog/2020/05/13/why-aes-gcm-sucks/
- https://crypto.stackexchange.com/a/70936
- https://en.wikipedia.org/wiki/Salsa20#ChaCha20_adoption

### Browser non-support and implications
Chapoly is not by the Web Crypto API and is supported by browsers so it can not
be encrypted or decrypted directly in the browser and is therefore a less secure
option as the server will at some point have had the secret, encrypted secret
and decryption key. If you are hosting the server yourself this might be less of
an issue, but worth considering when chosing cipher in this case.
