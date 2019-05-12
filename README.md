# legacymap
A port of [drvmap](https://github.com/not-wlan/drvmap) (which is effectively a rootkit loader) for earlier versions of Windows.

The *vast* majority of this project is composed of the incredible work of [wlan](https://github.com/not-wlan). I simply rewrote parts of it to provide verbose feedback and error checking, and adapted pieces that previously only worked on Win 10.

# What this is
* This uses Capcom's vulnerable signed driver to manually map an arbitrary unsigned driver into memory.
* Tested and works on Windows 8.1. Untested on all other versions but I would expect compatibility from 7 and up.
* This is a tool to learn from. Read it, rewrite it, and appreciate the beauty of Windows internals.

# What this isn't
* Tested with imports via ordinals. If you need to use them, I'm pretty sure you're smarter than I am anyway.
* A virus. This does nothing but what you make it.

The decision to allow known vulnerable drivers to have free access to the kernel was one made by Microsoft.<br/>
Win10 is a slight improvement as Secure Boot probably blocks these at boot time.<br />
This will potentially be caught by antimalware purely due to the use of the word "Capcom", but often not.
