Radare2 Integration with Minecraft
==================================

This directory contains the compiled r2pipe JAR to
use it from the Javascript extension of Minecraft.

Scriptcraft is a mod of Minecraft that allows to
interact with minecraft using Javascript, additionally,
this `r2mc.js` script imports the r2pipe API to spawn
an r2 instance and allows to execute commands in that
instance and get the results into Minecraft.

Scriptcraft can run on top of Canarymod or Bukkit.

I've mainly tested it on CM, but should work fine with the other.

--pancake

Startup
-------
* Get CanaryMod JAR file and copy it in this directory
* Make a `plugins` directory and copy the scriptcraft.jar inside
* Execute the `run.sh` script
* Load the minecraft console and use the r2pipe API from there
* ...
* Profit

Media
-----
* https://www.youtube.com/watch?v=dSABgYBO43g
* https://www.youtube.com/watch?v=VSKnGbK1qwQ

Dependencies:
-------------
* Minecraft https://minecraft.net/
* Scriptcraft http://scriptcraftjs.org/
* CanaryMod http://canarymod.net/
