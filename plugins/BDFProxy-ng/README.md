#The Backdoor Factory Proxy NextGen (BDFProxy-ng) v0.1
bdfproxy-ng is a fork and review of the original BDFProxy (https://github.com/secretsquirrel/BDFProxy)

#WARNING
##This is an experimental and unsupported fork. It uses libarchive that suffers from various bugs that could lead to a remote exploit.
##If you want to use a stable, supported and (almost) bug free version please use the official repo.


##What's new
- added support for deb files (Debian and Ubuntu)
- added support for ar and xz archives
- added support for mime types instead of headers
- got rid of various libraries to handle different archive types in favor of only one (`libarchive-c`)
- refactored the code, added more robust checks
- changed the copyright: now it's GPL3!

##Why forking
I felt the code needed a proper redesign to be able to add more features.
Plus, I didn't like the copyright of the original project :)

##How to install
You need to install the python packages listed in `requirements.txt` (hint: `sudo pip install -r requirements.txt`). Before doing that, you need to install `libarchive-dev` from your packet manager. (`sudo apt-get install libarchive-dev` on Debian/Ubuntu).

##How to use
Simply type `sudo python bdf_proxy.py`. For more information, refers to the original Readme file on the official BDFProxy repo.

##Depends:

	Pefile - most recent
	ConfigObj  
	mitmProxy - Kali Build .10
	BDF - most current
	Capstone (part of BDF)