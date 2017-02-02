DPARSER
=======

A r2 core plugin to read struct and its member from the DWARF structure.

Requirements:
-------------

 - libdwarf (currently, it is preferred to use `r2pm -i libdwarf`)
 - sdb

Compilation:
------------

```make && make install```

Usage:
------

Currently it works like a simple r2 core plugin.

```
iddi  path_to_file_having_dwarf_info
idd   structname [offset]
iddj  structname [offset]                // Output in JSON format
iddv  structname.member1.submember2      // Print value of submember2 struct which is a member of member1 struct
idda  structname.member1.submember2      // Print address of submember2 struct which is a member of member1 struct
iddlg                                    // Print flags in r2 format for all global variables
iddlf                                    // Print flags in r2 format for all functions
```

Known problems:
---------------

+ Might fail while using with other libdwarf versions
+ Problem in compilation because of libdwarf and sdb source path

Please file an issue if you find any other issue.

Things to do:
-------------

 - C format output (`iddd`)
 - Print type and size for structure or any of its member (`iddt`)

License:
--------

GPL
