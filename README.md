Swift
=====

Instant Multisig Bitcoin Payments


This is the backend protocol for Swift, the instant multisig Bitcoin payments system.

I want to keep everything open source to maximize the transparency of Swift operations.  In particular, I want to prove that Swift cannot steal user's bitcoins (because we only store 1 out of 2 subkeys).


TO DO

I need to separate Buterin's python code from mine.  In other words, I need to segregate basic functionality from Swift-specific things.

Integrate this backend code with a DB.

Fix bugs with logarithmic splitting of Bitcoin

Much much more.





Thanks to
Vitalik Buterin for his python library for a lot of the core functionality.  Creating public addresses, private keys, and raw transactions is possible due to his library.
