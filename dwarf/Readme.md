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
?:dwarf init path_to_file_having_dwarf_info
?:dwarf structname [offset]
?:dwarfj structname [offset]                // Output in JSON format
```

Known problems:
---------------

+ Might fail while using with other libdwarf versions
+ Problem in compilation because of libdwarf and sdb source path

Please file an issue if you find any other issue.

Things to do:
-------------

 - C format output
 - use `idd*` instead of `?:dwarf`
 - Access specific member of a structure using either `structname->membername` or `structname.membername` (also recursively like `structname->anotherstruct.membername`)
 - print a pointer to be able to use it with r2 native cmds (example: ``pd 20 @ `?:dwarf struct->another_struct.field` `` and ``wx 1010 @ `?:dwarf struct->another_struct.field` ``)

License:
--------

GPL
