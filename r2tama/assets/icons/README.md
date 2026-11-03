These eight unmodified 22×18 PNG pictograms come from:

https://github.com/StefanBauwens/Tamagotchi-Emulator-Pebble/tree/b0d3a8691459541de2693d52ed30234cf07c18dd/Tamagotchi/resources/images

Files 1.png through 8.png, in hardware icon order:
food, light, game, medicine, toilet, status, discipline, attention.

`scripts/build-icons.py` packs their black, opaque pixels into the embedded
`icons.inc.c` rows. The runtime needs no image library or external assets.
