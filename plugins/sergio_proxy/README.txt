ABOUT SERGIO PROXY
=========================
Sergio Proxy (a Super Effective Recorder of Gathered Inputs and Outputs) is an
HTTP proxy that was written in Python for the Twisted framework. It's
not anything new (many people have done this before, and better), but I wanted
to learn how it's done and this seemed a good way to go about doing it. As this
started out as a quest to develop a better way of attacking an SMB challenge hash
vulnerability, I have implemented that as one of my included MITM attacks. I also
included the classic Upsidedownternet attack for more fun.

Hopefully I will be adding some more unique features in the near future when
I get time. Until then, this is all GPL, so feel free to modify and distribute
as you see fit.


RELEASE NOTES
=========================
This is alpha software. No, seriously. I'm not talking Google's "oh, this might
break once or twice if you use it for years." No, I mean seriously alpha, as in
the bugs you will encounter will make you start screaming "WTF, is this man the
worst coder to have ever wasted space on the Earth?" Yes, that bad. Hopefully,
with your bug reports and some more of my time, it will get more stable. But
until then, you have been warned.

In a similar vein, there are already some known issues with this software that
I would ask you not to waste my time reporting. I have listed a couple of known
bugs below: PLEASE READ THEM BEFORE YOU SUBMIT REPORTS.

DEPENDENCIES
========================
twisted.web Python library
PIL if you want upsidedownternet to work
arpspoof or ettercap if you want to use ArpSpoof plugin
Python (obviously)


USAGE
========================
Running sergio-proxy with -h will print out all the available options.

Also see the example argument files in the examples folder. These can be
used as follows:
./sergio-proxy --myoption1 --myoption2  @file1.args @file2.args ...

TODO
========================
* HTTP/1.1 Support - this will involve modifying twisted itself, so don't hold
your breath for this any time soon.

* Actual SSL support (rather than just trying to strip). Could be awhile...

* Add more attacks, obviously


KNOWN BUGS
========================
Upsidedownternet
Some versions of  PIL in the Ubuntu repo's have a bug that causes parsing
of PNG files. You have been warned. The patch available below can fix this:
https://bugs.launchpad.net/ubuntu/+source/python-imaging/+bug/383228

FOUND BUGS? GOT PATCHES?
========================
Send them to me at supernothing AT spareclockcycles DOT org. 
