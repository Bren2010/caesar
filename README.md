# Caesar

An easy-to-use advanced cryptography library that lets you focus on writing applications that process data, not encrypted data.

### Install
```bash
npm install caesar
```

### Currently Implemented
1. Stream Ciphers (Confidential and/or Authenticated)
2. Deterministic Authenticated Encryption (SIV-CTR)
3. Disk Encryption (XTS)
4. Searchable Symmetric Encryption (Single-User and Multi-User, Ranked)
5. Commitments

## Where I Ramble for a Bit

A lot of security officials will tell web developers that if they need to type the letters 'AES' then they're doing cryptography wrong.  However, they rarely offer any actual secure options to help their audience complete that totally awesome NSA-proof application they've had in mind for the last couple of weeks.  Combine this with the recent "Secure, Decentralized, and Anonymous {Insert Word Here} for Everyone!" fetish, and there has been astonishing amount of cryptographic code written recently that is not only difficult to peer review, but often buried within an application's core instead of left somewhere conspicuous.  While this newfound affinity for cryptography is fantastic, not every one of these developers will want to dedicate the time and effort required to build a secure product before slapping on the label "It uses cryptography!"  Or, perhaps even more disconcertingly, not every one of these developers is aware of the true power of modern cryptography.

My goal in writing this library is to provide simple and easy-to-use interfaces to advanced cryptographic tools in such a way that someone with no prior knowledge of them can correctly integrate them in their own applications with as little effort as possible.  That way they can focus on what they love (developing) and I can focus on what I love (cryptography).

Some things that might be added in the future include:  user authentication, more complex key exchanges, zero-knowledge proofs, and homomorphic encryption schemes, poker.

I've tried to keep all of the code very well documented and write examples that concisely demonstrate proper use of the library.  If you encounter any problems or confusion while using the library, please [open an issue](https://github.com/Bren2010/caesar/issues) or [send me an email](https://github.com/Bren2010).
