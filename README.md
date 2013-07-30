Caesar
======

An easy-to-use advanced cryptography library that lets you focus on writing applications that process data, not encrypted data.

A lot of security officials will tell web developers that if they need to type the letters 'AES' then they're doing cryptography wrong.  However, they rarely offer any actual secure options to help their audience complete that totally awesome NSA-proof application they've had in mind for the last couple of weeks.  Combine this with the recent "Secure, Decentralized, and Anonymous {Insert Word Here} for Everyone!" fetish, and there has been astonishing amount of cryptographic code written recently.  While this newfound affinity for cryptography is fantastic, it poses the problem that not every one of these developers will want to dedicate the time and effort required to build a secure product before slapping on the label "It uses cryptography!"  Not to mention, very few developers are even aware of the capabilities of modern cryptography applied correctly, and both of these are problems I hope to help solve.

My goal in writing this library is to provide simple and easy-to-use interfaces to advanced cryptographic tools in such a way that someone with no prior knowledge of them can correctly implement them in their own applications with as little effort as possible.  That way they can focus on what they love (developing) and I can focus on what I love (cryptography).

Currently only a few kinds of encryption and authentication are supported, however more complex tools will be added as time goes on.  Some things that might be added in the future include:  user authentication, more complex key exchanges, searchable encryption, zero-knowledge proofs, and homomorphic encryption schemes.
