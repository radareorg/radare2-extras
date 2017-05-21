import r2pipe
import sys
import os

if len(sys.argv) < 2:
    print "Usage: $pimp command [arguments]"
    exit(1)

r2 = r2pipe.open()
args = " ".join(sys.argv[1:]).translate(None, "!\"#$%%&'()*+,-./:;<=>?@[\]^_`{|}~")

r2.cmd("#!python -e " + "_r2_plugin_args = '{}'".format(args))
r2.cmd("#!python {}/pimp.py".format(os.path.dirname(os.path.realpath(__file__))))
r2.cmd("#!python -e " + "del _r2_plugin_args")
