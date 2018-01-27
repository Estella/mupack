# mupack (public build)

![mupack](https://rebote.net/linkage/mupack2_1.PNG)
![mupack](https://rebote.net/linkage/mupack2_2.PNG)


This is a small executable packer that I have been working on and off for some time. 
There is some bugs:

Known bugs:
* Incompatibility with shared.dll of foobar2000.
* No load config directory support.

mupack3 is developed in private and is designed to fix these issues and many others, so don't expect a public release at all.
Virus scanners now scan for mupack2, making it somewhat useless now (thanks to people that abused it). 
Which is why hence a private version for me exists, to pack my own demoscene and other prods.

Source code might be useful for people who want to read how to develop a packer in mostly C though. 
mupack3 is a rewrite using modern C++ using proper PE parsing libraries as well as modern compilers.
