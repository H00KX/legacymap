# legacymap
A port of drvmap (which is effectively a rootkit loader) for earlier versions of Windows.

The *vast* majority of this project is composed of the incredible work of [wlan](https://github.com/not-wlan). I simply rewrote parts of it to provide verbose feedback and error checking, and adapted pieces that previously only worked on Win 10.

# What this is
* This uses Capcom's vulnerable signed driver to manually map an arbitrary unsigned driver into memory.
* Tested and works on Windows 8.1. Untested on all other versions but I would expect compatibility from 7 and up.
* This is a tool to learn from. Read it, rewrite it, and appreciate the beauty of Windows internals.

# What this isn't
* A virus. This does nothing but what you make it.

The decision to allow known vulnerable drivers to have free access to the kernel is one made by Microsoft.
This will potentially be caught by antimalware purely due to the use of the word "Capcom", but often not.

People asking me how to make their videogame cheat won't get a response.<br />
Anyone willing to ask open questions and with a desire to learn will get my enthusiastic help.
