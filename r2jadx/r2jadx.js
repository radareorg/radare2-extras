#!/usr/bin/env node

const jadx = require('./jadx');
const r2pipe = require('r2pipe-promise');

async function main (argv) {
  const r2arg = (argv.length > 2 && argv[2][0] !== '-') ? argv[2] : undefined;
  const r2 = await (r2arg ? r2pipe.open(r2arg) : r2pipe.open());
  try {
    await r2.cmd('af');
    const info = await r2.cmdj('ij');
    const fileName = info.core.file;
    const fcn = await r2.cmdj('afij');
    if (!fileName.endsWith('.dex')) {
      throw new Error('This is not a DEX file');
    }
    if (fcn.length !== 1) {
      console.error('Press ^C');
      await r2.quit();
      throw new Error('Cannot find a function in here');
    }
    const fcnOffset = fcn[0].offset;
    let mode = 'r2';
    if (argv.length > 2) {
      argv = argv.slice(1);
    }
    if (fcnOffset && fileName) {
      if (argv[1] && argv[1][0] === '-') {
        mode = argv[1].substring(1);
      }
      try {
        const res = await jadx.decompile(fileName, mode, fcnOffset);
        console.log(res);
        if (mode === 'r2') {
          for (let line of res.split(/\n/)) {
            await r2.cmd(line);
          }
        }
        return res;
      } catch (e) {
        throw e;
      }
    } else {
      throw new Error('Cannot find function');
    }
  } catch (e) {
    console.error('Oops', e);
    throw e;
  } finally {
    console.error('Press ^C');
    await r2.quit();
  }
}

if (process.argv.length < 3) {
  if (!r2pipe.isAvailable()) {
    console.error('Usage: r2jadx [file] # or run it from inside r2');
    process.exit(1);
  }
}

if (!jadx.check()) {
  console.error('Invalid version of jadx. We need >= 1.x');
  process.exit(1);
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
