#!/usr/bin/env node

const execSync = require('child_process').execSync;
const shellEscape = require('shell-escape');
const path = require('path');
const fs = require('fs');

function toPaddedHexString (num, len) {
  const str = parseInt(num).toString(16);
  return '0x' + ('0'.repeat(len - str.length) + str);
}

function walkSync (dir, arr) {
  if (arguments.length === 1) {
    arr = [];
  }
  if (!fs.lstatSync(dir).isDirectory()) {
    return dir;
  }
  const files = fs.readdirSync(dir).map(f => walkSync(path.join(dir, f), arr));
  arr.push(...files);
  return arr;
}

const walk = async (dir, filelist = []) => {
  const files = fs.readdirSync(dir);

  for (var file of files) {
    const filepath = path.join(dir, file);
    const stat = await fs.stat(filepath);

    if (stat.isDirectory()) {
      filelist = await walk(filepath, filelist);
    } else {
      filelist.push(file);
    }
  }

  return filelist;
};

function processMethod (data, mode, offset, method) {
  function comment (addr, line) {
    if (mode === 'c' || mode === 'cat') {
      // console.error(data.name);
      // console.log(data.source);
if (!data.source) {
return '';
}
      let lastOffset = parseInt(method.offset);
      if (mode === 'cat' || (mode === 'c' && addr === lastOffset)) {
        const source = data.source.replace('.json', '.java');
        const fileData = fs.readFileSync(source);
        return fileData.toString('utf8');
      }
      return '';
    }

    if (mode === 'f') {
      let lastOffset = parseInt(method.offset);
      if (addr === lastOffset) {
        return toPaddedHexString(addr, 8) + '  ' + line + '\n';
      }
      return '';
    }
    const b64line = Buffer.from(line).toString('base64');
    if (b64line.length > 2048) {
      return 'CCu toolong @ ' + addr + '\n';
    }
    return 'CCu base64:' + b64line + ' @ ' + addr + '\n';
  }
  let lastOffset = parseInt(method.offset);
  if (mode === 'all' || mode === 'ahl') {
    // decompile selected method with offset + text format
    let res = '\n' + toPaddedHexString(method.offset, 8) + '  ' + method.name + ':\n';
    for (let line of method.lines) {
      res += toPaddedHexString(line.offset || lastOffset, 8) + '  ' + line.code + '\n';
      if (line.offset) {
        lastOffset = line.offset;
      }
    }
    return res;
  }
  if (mode === 'r') {
    offset = 0;
    mode = 'r2';
  }

  if (mode === 'll' || mode === 'hl') {
    // decompile given method for r2
    let res = '';
    if (offset === lastOffset) {
      return processMethod(data, 'r2', offset, method);
    }
    for (let line of method.lines) {
      if (parseInt(line.offset) === offset - 16) {
        res += processMethod(data, 'r2', offset, method);
      }
    }
    return res;
  }

  // mode === 'r2'
  let res = comment(parseInt(method.offset) + 16, method.name);
  for (let line of method.lines) {
    // TODO: use CL console.error('CL ' + line.offset + ' base64:' + line.code);
    const addr = parseInt(line.offset || lastOffset);
    res += comment(addr, line.code.trim());
    // 'CCu base64:' + Buffer.from(line.code).toString('base64') + ' @ ' + parseInt(line.offset || lastOffset) + '\n';
    if (line.offset) {
      lastOffset = line.offset;
    }
  }
  return res;
}

function processClass (data, mode, offset) {
  offset = parseInt(offset);
  let res = '';
  if (data.methods) {
    for (let method of data.methods) {
      switch (mode) {
        case 'a':
        case 'c':
        case 'f':
        case 'cat':
        case 'r':
        case 'r2':
        case 'all':
        case 'ahl':
        case 'll':
        case 'hl':
          res += processMethod(data, mode, offset, method);
          break;
        default:
          res += 'Invalid mode ' + mode + '\n';
          break;
      }
    }
  }
  return res;
}

function dex2path (target) {
  return target + '.d';
}

async function crawl (target, mode, arg) {
  // console.log('crawling', arguments);
  switch (mode) {
    case 'f':
      return crawlFiles(path.join(target, 'hl'), mode, arg);
    case 'c':
      return crawlFiles(path.join(target, 'hl'), 'c', arg);
    case 'a':
      return crawlFiles(path.join(target, 'hl'), 'cat', arg);
    case 'r':
      return crawlFiles(path.join(target, 'll'), mode, arg);
    case 'r2':
      return crawlFiles(path.join(target, 'hl'), mode, arg);
    case 'll':
      return crawlFiles(path.join(target, 'll'), mode, arg);
    case 'hl':
      return crawlFiles(path.join(target, 'hl'), mode, arg);
    case 'ahl':
      return crawlFiles(path.join(target, 'hl'), mode, arg);
    case 'all':
      return crawlFiles(path.join(target, 'll'), mode, arg);
    case 'cat':
      return crawlFiles(path.join(target, 'cat'), mode, arg);
    case '?':
    case 'h':
    case 'help':
    default:
      return 'Usage: !*r2jadx ([filename])[ll,hl,all,ahl,cat,help]';
  }
}

async function crawlFiles (target, mode, arg) {
  const ext = 'json'; // (mode === 'cat' || mode === 'c') ? 'java' : 'json';

  // console.error('FINDUS', target);
  const files = walkSync(target).filter(_ => (_.endsWith && _.endsWith(ext)));
  let res = '';
  for (let fileName of files) {
    try {
      if (mode === 'cat') {
        const fileData = fs.readFileSync(fileName.replace('.json', '.java'));
        res += fileData;
      } else {
        const fileData = fs.readFileSync(fileName);
        const data = JSON.parse(fileData);
        res += processClass(data, mode, arg);
        if (data['inner-classes']) {
          for (let klass of data['inner-classes']) {
            klass.source = fileName;
            res += processClass(klass, mode, arg);
          }
        }
      }
    } catch (e) {
      console.error('' + fileName + ': ' + e);
    }
  }
  return res;
}

async function decompile (target, mode, arg) {
  const outdir = dex2path(target);
  if (!fs.existsSync(outdir)) {
    if (!check()) {
      console.error('Invalid version of jadx. We need >= 1.x');
      process.exit(1);
    }
    const options = { }; // stderr: 'inherit' };

    try {
      console.error('jadx: Performing the low level decompilation...');
      const cmd = [ 'r2pm', '-r', 'jadx', '--output-format', 'json', '-f', '-d', path.join(outdir, 'll'), target ];
      execSync(shellEscape(cmd, options));
    } catch (e) {
    }

    try {
      console.error('jadx: Performing the high level decompilation...');
      const cmd = [ 'r2pm', '-r', 'jadx', '--show-bad-code', '--output-format', 'java', '-d', path.join(outdir, 'hl'), target ];
      execSync(shellEscape(cmd, options));
    } catch (e) {
    }

    try {
      console.error('jadx: Constructing the high level jsons...');
      const cmd = [ 'r2pm', '-r', 'jadx', '--show-bad-code', '--output-format', 'json', '-d', path.join(outdir, 'hl'), target ];
      execSync(shellEscape(cmd, options));
    } catch (e) {
    }
  }
  return crawl(outdir, mode, arg);
}

function check () {
  const cmd = [ 'r2pm', '-r', 'jadx', '--version' ];
  const res = execSync(shellEscape(cmd, {})).toString('utf8');
  return res.startsWith('1');
}

module.exports = {
  crawl: crawl,
  dex2path: dex2path,
  decompile: decompile,
  check: check
};
