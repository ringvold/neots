# neots (NeoOTS)

Inspired by https://github.com/sniptt-official/ots but but implements 
ChaCha20-Poly1305 instead of AES GCM.

TODO:
[ ] Actually support expires flag (expiry is hard coded to 2 hours)
[ ] Implement config file compatible with `ots`

## Why Chacha20?
Some people seems to prefer ChaCha20-Poly1305 (ChaPoly for short) over AES 
GCM. It does not require hardware acceleration to be fast. It might be a bit 
more secure, theoretically, maybe, but what do I know, I'm no expert. 🤷‍♂️

Here is some reading though:
- https://soatok.blog/2020/05/13/why-aes-gcm-sucks/
- https://crypto.stackexchange.com/a/70936
- https://en.wikipedia.org/wiki/Salsa20#ChaCha20_adoption
