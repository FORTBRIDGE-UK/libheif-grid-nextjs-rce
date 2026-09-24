# Security notice

This private repository contains working exploit code for an isolated,
version-pinned research target. Use it only on systems you own or are
explicitly authorised to test.

The PoC uploads a shared object, corrupts a native image-processing worker and
normally terminates the target process after sending its callback. It is not a
safe availability test.
