#!/usr/bin/env node

const jadx = require('./jadx');
const r2pipe = require('r2pipe');

async function main (argv) {
  const r2arg = (argv.length > 2 && argv[2][0] !== '-') ? argv[2] : undefined;
  let r2 = r2pipe.openSync(r2arg);
  try {
    r2.cmd('af');
    const info = r2.cmdj('ij');
    const fileName = info.core.file;
    const fcn = r2.cmdj('afij');
    if (!fileName.endsWith('.dex')) {
      throw new Error('Sorry, this is not a DEX file');
    }
    const fcnOffset = (fcn && fcn.length > 0) ? fcn[0].offset : 0;
    let mode = 'all';
    if (argv.length > 2) {
      argv = argv.slice(1);
    }
    if (argv[1] && argv[1][0] === '-') {
      mode = argv[1].substring(1);
    }
    if (fileName) {
      try {
        const res = await jadx.decompile(fileName, mode, fcnOffset);
        if (mode.startsWith('r')) {
          for (let line of res.split('\n')) {
            if (line.trim().length > 0) {
              r2.cmd(line);
            }
          }
        } else {
          console.log(res);
        }
        return res;
      } catch (e) {
        throw e;
      }
    } else {
      throw new Error('Cannot find function');
    }
  } catch (e) {
    console.error('Oops', e, e.output ? e.output.toString() : '');
    throw e;
  } finally {
    r2.quit();
  }
}

if (process.argv.length < 3) {
  if (!r2pipe.isAvailable()) {
    console.error('Usage: r2jadx [file] # or run it from inside r2');
    process.exit(1);
  }
}

switch (process.argv[2]) {
  case '-h':
    console.error('Usage: !*r2jadx [-mode]');
    console.error('Setup: e cmd.pdc=!*r2jadx');
    console.error('Modes: -r2 = r2 output');
    console.error(' -a   = show decompilation of all the classes');
    console.error(' -c   = decompile current class');
    console.error(' -f   = decompile current function');
    console.error(' -r   = load all decompilation output as comments (ll)');
    console.error(' -r2  = load all decompilation output as comments (hl)');
    console.error(' -ahl = all high level decompilation');
    console.error(' -all = all low level decompilation');
    console.error(' -hl = high level decompilation');
    console.error(' -ll = low level decompilation');
    process.exit(0);
}

main(process.argv)
  .then((res) => {
    console.log(res);
    process.exit(0);
  })
  .catch((err) => {
    console.error(err);
    process.exit(0);
  });
