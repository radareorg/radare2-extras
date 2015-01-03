	+-------------------------+
	|  .-----.                | radare2-extras package
	|  | .-· |                | contains  a collection
	|  | | --| extras         | of plugins for radare2
	|  `-·---'                |
	+-------------------------+              --pancake

radare2-extras
==============
That repository contain extra plugins and related code that
can't be (or it shouldnt) be distributed with radare2. We
must keep some consistency and logic to make that repo not
conflict with the main repo and make everything clear to
avoid confusion to users.

Actually this repo only contained deprecated/unused/dead
plugins from r1. I would keep all the code, even if its not
compiling, for historical reasons. and practicity, if anyone
needs to bring it back to life like the BEA one. also we may
move the GNU plugins as soon as we get the capstone one fully
tested/ready to replace all those dupped plugs.

stuff likeBEA diasm plugin, other frontend apps like bincrowd
and such. Those old plugins are not really old. in fact.. 

aka code that needs extra deps? -> yep

Also, this repository must be useful to newcomers who want to
use r2 for his barely used arch like PSOSVM or other personal
projects to commit his work in there. We must keep the r2
source as short and concise as possible, and reduce the
amount of unnecessary plugins to reduce the installation and
keep it usable for 99% of users.

in all fairness, i see yara more and more in the wild. and
it would be nice having it the main r2 :/

Building
========
I would suggest adding a separate configure script for each
module to avoid making a single huge configure to handle all
the code in there. Mostly because it requires extra
dependencies, git submodules and other black magic.

As soon as we get this repo working i'll push all distributions
and packagers to add it. In fact, i think that we should define
more subpackages for each extra plugin for example:
    
	radare2-extras-yara -> yara plugin

I see your point, but they're small, having theme in main r2
could be nice. This way distros can just make r2 package with 0
dependencies. and install the -yara package with dynamic linkage
to libyara (yara2 or yara3) without much conflicts.

do you care about zero deps r2? i thought zero deps were only
for hard to reach platforms.

yes. r2 is and must be zero dep. its important or portability
this will be better for packagers.

in addition we should add sys/*.sh files t fetch and build such
plugins to allow git users to get that ready easily do we really
want sys/*.sh ? what about just saying, well you need lib**4 lib***[5-6] ...
wouldn't this be better? is it about spoon feeding the user?

we could still provide one-liners to help them. We should keep
different versioning numbers for each plugin.. i think that we
should do something like this:

	radare2-extras-yara3-0.9.9-0.1
	[pkgname] [modname] [r2version] [modversion]

Those plugins will be installed in (and loaded from):
    
    /usr/lib/radare2-extras/${version}

Do we need a radare2-extra-regressions then?
I would just add the tests inside the radare2-extras/libr/core/p/yara/t/
for example.. and just make those tests run from inside that
repo, no need to add more repos because those plugins would be
pretty contained.

What about checking all the tests right away?

Also maybe the plugins depend on some r2 behavior, that has
been broken, and we need to test for that jenkins should run
those tests don't know much about jenkins, so i won't say much.
just hoping it covers all our bases.
