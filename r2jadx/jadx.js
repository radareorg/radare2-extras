#!/usr/bin/env node

const execSync = require('child_process').execSync;
const shellEscape = require('shell-escape');
const path = require('path');
const fs = require('fs');

function walkSync (dir, arr) {
  if (arguments.length === 1) {
    arr = [];
  }
  if (!fs.lstatSync(dir).isDirectory()) return dir;
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
  let lastOffset = parseInt(method.offset);
  if (mode === 'll' || mode === 'hl') {
    let res = ''; // method.offset + '  ' + method.name + '\n';
    if (offset === lastOffset) {
      return processMethod(data, 'all', offset, method);
    }
    for (let line of method.lines) {
      if (parseInt(line.offset) === offset - 16) {
        return processMethod(data, 'all', offset, method);
      }
    }
    return res;
  }
  if (mode === 'all' || mode === 'ahl') {
    let res = '\n' + method.offset + '  ' + method.name + ':\n';
    for (let line of method.lines) {
      res += (line.offset || lastOffset) + '  ' + line.code + '\n';
      if (line.offset) {
        lastOffset = line.offset;
      }
    }
    return res;
  }

  let res = 'CCu base64:' + Buffer.from(method.name).toString('base64') + ' @ ' + method.offset + '\n';
  for (let line of method.lines) {
    // TODO: use CL console.error('CL ' + line.offset + ' base64:' + line.code);
    res += 'CCu base64:' + Buffer.from(line.code).toString('base64') + ' @ ' + (line.offset || lastOffset) + '\n';
    if (line.offset) {
      lastOffset = line.offset;
    }
  }
  return res;
}

function processClass (data, mode, offset) {
  let res = '';
  if (data.methods) {
    for (let method of data.methods) {
      switch (mode) {
        case 'cat':
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
  console.log('crawling', arguments);
  switch (mode) {
    case 'r2':
      return crawlFiles(path.join(target, 'hl'), mode, arg);
    case 'all':
      return crawlFiles(path.join(target, 'll'), mode, arg);
    case 'll':
      return crawlFiles(path.join(target, 'll'), mode, arg);
    case 'ahl':
      return crawlFiles(path.join(target, 'hl'), mode, arg);
    case 'hl':
      return crawlFiles(path.join(target, 'hl'), mode, arg);
    case 'cat':
      return crawlFiles(path.join(target, 'cat'), mode, arg);
    case '?':
    case 'h':
    case 'help':
    default:
      return 'Usage: !*r2jadx ([filename])[ll,hl,cat,help]';
  }
}

async function crawlFiles (target, mode, arg) {
  let ext = 'json';
  switch (mode) {
    case 'cat':
      ext = 'java';
      break;
  }
  console.error('FINDUS', target);
  const files = walkSync(target).filter(_ => (_.endsWith && _.endsWith(ext)));
  let res = '';
  for (let fileName of files) {
    try {
      const fileData = fs.readFileSync(fileName);
      if (mode === 'cat') {
        res += fileData;
      } else {
        const data = JSON.parse(fileData);
        res += processClass(data, mode, arg);
        if (data['inner-classes']) {
          for (let klass of data['inner-classes']) {
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
    const options = { }; // stderr: 'inherit' };

    console.error('jadx: Performing the low level decompilation...');
    let cmd = [ 'r2pm', '-r', 'jadx',
      '--output-format', 'json', '--illegal-access=warn',
      '-f', '-d', path.join(outdir, 'll'), target ];
    execSync(shellEscape(cmd, options));

    console.error('jadx: Performing the high level decompilation...');
    cmd = [ 'r2pm', '-r', 'jadx', '--illegal-access=warn', '-d', path.join(outdir, 'hl'), target ];
    execSync(shellEscape(cmd, options));

    console.error('jadx: Constructing the high level jsons...');
    cmd = [ 'r2pm', '-r', 'jadx', '--illegal-access=warn', '--output-format', 'json',
      '-d', path.join(outdir, 'hl'), target ];
    execSync(shellEscape(cmd, options));
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
