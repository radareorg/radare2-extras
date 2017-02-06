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
iddd  structname[.members]*              // Print C-Type declaration
```

Known problems:
---------------

+ Might fail while using with other libdwarf versions
+ Problem in compilation because of libdwarf and sdb source path

Please file an issue if you find any

Things to do:
-------------

 - Print type and size for structure or any of its member (`iddt`)
 - Long description of strucutre (`idddl`) (Instead of printing structures as `struct name var_name;`, it should print the nested definition of `struct name`)
 - Improve array output. GDB prints it in a more nicer way for situation like array of structs
 - Allow printing of array fields. For example: `struct->field[2]`
 - Issue with setting flags for stubs (they should be named differently)

License:
--------

GPL
