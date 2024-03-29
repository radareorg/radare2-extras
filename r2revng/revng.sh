#!/bin/bash
export BASH=/usr/bin/bash
cat > a.out
. /revng/environment
revng artifact --analyze --progress decompile-to-single-file $@ a.out | revng ptml --color
