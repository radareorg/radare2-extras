#!/bin/sh
# Hardcoded OSX PATH

JAVA_HOME="/Library/Internet Plug-Ins/JavaAppletPlugin.plugin/Contents/Home"
CLASSPATH="${PWD}"
CANARYMOD="CanaryMod-1.8.0-1.2.0-SNAPSHOT-shaded.jar"

export CLASSPATH
export JAVA_HOME

java -cp "r2pipe.jar:${CANARYMOD}" net.canarymod.Main
