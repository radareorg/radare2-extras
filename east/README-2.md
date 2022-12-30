# VESIL

## Description

V library to provide high level analysis on top of esil

## Usage

See the `main.v` and run it with `make`.

## Known bugs

There are some r2 instances that arent killed somehow by v-r2pipe

## Random

```
paπcake, [3/29/2022 7:03 PM]
typedef struct {
        char *name;
        void *ref;
} Symbol;

// hook memory reads to find access to variables
// hook register names to track transfers of symbols
"0,rax,:="
:= will trigger reg_write, if 'rax' is associated to a symbol then we can name that operation
   for example if rax is associated to the symbol containing the return value of a function
   the esil box can create that symbol and handle the function call expression like foo = call()
   symbols can be invalidated at any time and their meaning can change backwards.

using esilbox;

int main() {
        Symbol *argc = r_esil_box_symbol_new ("argc", "rbp,10,-");

        EsilBox *eb = r_esil_box_new ();
        r_esil_box_add_symbol (eb, argc);
        r_esil_box_set_address (eb, 0x8048000);
        do {
                r_esil_box_step (eb);
        } white (r_esil_box_running (eb));

//      eb := esilbox.new()
//      eb.set_address(0x80488)
//      eb.step()
}
```
