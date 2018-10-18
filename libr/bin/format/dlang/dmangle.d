import core.demangle;
import std.stdio;
import std.conv;
import std.string;
extern (C) const(char)* dlangDemangle(const(char)* str) {
       return str.to!string().demangle ().toStringz();
       //return demangle (str.to!string()).toStringz();
}
 /*
void main() {
       auto str = D_DEMANGLE("_D1a1bFiZi");
       writeln (str);
}
*/
