#!/usr/bin/env node

const glob = require('glob');
const fs = require('fs');

if (process.argv.length != 3) {
  console.error('Oops');
  process.exit(1);
} 
const target = process.argv[2];

function processClass(data) {
  if (data.methods) {
    for (let method  of data.methods) {
      let lastOffset = method.offset;
      console.log('CCu base64:' + Buffer.from(method.name).toString('base64') + ' @ ' + method.offset);
      for (let line of method.lines) {
        // TODO: use CL console.error('CL ' + line.offset + ' base64:' + line.code);
        console.log('CCu base64:' + Buffer.from(line.code).toString('base64') + ' @ ' + (line.offset || lastOffset));
        if (line.offset) {
          lastOffset = line.offset;
        }
      }
    }
  }
}

glob(target + '/**/*.json', (err, files) => {
  if (err) {
    throw err;
  }
  files.forEach((fileName) => {
    try {
      const data = JSON.parse(fs.readFileSync(fileName));
      processClass (data);
      if (data['inner-classes']) {
        for (let klass of data['inner-classes']) {
          processClass (klass);
        }
      }
    } catch (e) {
      console.error('' + fileName + ': ' + e);
    }
  });
});
