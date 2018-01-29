#!/usr/bin/env node

const fs = require('fs');
if (process.argv.length > 2) {
  walkTheLines(process.argv[2]);
} else {
  console.error('Usage: r2crash.js [crashlog]');
  process.exit(1);
}

function walkTheLines(file) {
  const lines = fs.readFileSync(file).toString().split('\n');
  lines.forEach(walkLine);
}

// global state is bad
var threadId = 0;
var mode = '';

function walkLine(line) {
  switch (mode) {
  case 'thread-state':
    mode = parseThreadState(line);
    break;
  default:
    if (line.startsWith('Crashed Thread')) {
      const threadId = +line.substring(20).trim().split(/ /)[0];
      console.error("# tid", threadId);
    }
    break;
  }
  if (line.startsWith('Thread ') && line.indexOf('Thread State') !== -1) {
    mode = 'thread-state';
  }
}

function parseThreadState(line) {
  if (line.trim() === '') {
    return '';
  }
  const regpairs = line.replace(/: /g,':').replace(/\ \ */g,' ').trim().split(/ /);
  for (let rp of regpairs) {
    const rv = rp.split(':');
    console.log('ar', rv[0], '=', rv[1]);
  }
  return 'thread-state';
}
