const r2pipe = require('r2pipe-promise');
const prompt = require('prompt-sync')();

let r2 = null;

function re(x) {
  return x[(Math.random()*x.length)|0];
}

function pdargs(w, ocmd) {
  const byt = w.before('bytes');
  const ins = w.before('instructions') || w.before('ops');
  const at = w.after('at');
  let res = '';
  let cmd = ocmd;
  if (w.have('function')) {
    cmd = 'pdf';
  } else if (byt) {
    cmd = ins? 'pD': 'px';
    res = ' ' + byt;
  } else {
    if (!cmd) cmd = 'pd';
    if (ins) {
      res = ' ' + ins;
    }
  }
  if (at) {
    res += '@ ' + at;
  }
  return cmd + res;
}

async function run(input) {
  const w = new Api(input);
  const askPlease = w.have('please');
  if (w.first('please')) {
    w.shift();
  }
  const search = w.first('find') || w.first('search');
  if (search) {
    return 'I am not able to find anything yet';
  }
  const print = w.first('list') || w.first('view') || w.first('show') || w.first('print');
  if (print) {
    const extra = pdargs(w);
    const type = w.second() || '';
    switch (type) {
    case '':
      return 'What are you looking for?';
    case 'imports':
      return r2.cmd('ii');
    case 'flag':
      return r2.cmd('f~' + w.after(type));
    case 'regs':
    case 'registers':
      return r2.cmd('dr=');
    case 'functions':
      return r2.cmd('afl');
    case 'function':
      if (w.have('code')) return r2.cmd(extra);
      return r2.cmd('afi');
    case 'symbols':
      return r2.cmd('is');
    case 'hex':
      return r2.cmd(pdargs(w, 'px'));
    }
    return r2.cmd(extra);
  }
  if (w.first('code')) {
    return r2.cmd('pd 10');
  }
  if (w.first('analyze')) {
    const target = w.after('analyze');
    const everything = w.have('everything');
    if (everything) {
      return await r2.cmd('aaa');
    }
    if (w.have('symbols')) {
      return await r2.cmd('aas');
    }
    if (w.contains('emula')) {
      return await r2.cmd('aae');
    }
    return r2.cmd('af');
  }
  if (w.first('decompile')) {
    return r2.cmd(pdargs(w, 'pdd'));
  }
  if (w.first('count')) {
    const target = w.after('count');
    switch (target) {
    case 'functions':
      return await r2.cmd('aflc');
    case 'symbols':
      return await r2.cmd('is~?');
    case 'imports':
      return await r2.cmd('ii~?');
    default:
      return 'Expect: symbols|imports|functions';
    }
  }
  if (w.have('help')) {
    if (askPlease) {
      return re(['No pleasing in here']);
    }
    return re(['You cannot escape', 'Try to follow the conversation']);
  }
  if (w.have('what')) {
    return 'Try list, show, version, count, list, analyze, print';
  }
  if (w.first('show') && w.second('version')) {
    return (await r2.cmd('?V')).trim();
  }
  if (w.first('version')) {
    return (await r2.cmd('?V')).trim();
  }
  if (w.contains('thanks')) {
    return re(['You are welcome', 'No problem']);
  }
  if (w.first('hi') || w.first('hello')) {
    return re(['How are you?', 'Hello back!', 'Welcome r2home!']);
  }
  if (w.first('hack')) {
    return re(['HACK THE PLANET!']);
  }
  if (w.first('lol')) {
    return re(['This was not funny.', 'Hahahh, indeed', 'L O L']);
  }
  if (w.isQuestion()) {
    return re(['Why are you asking?','I dont know the answer', 'Explain it to me again']);
  }
  if (w.first('ok') || w.first('yes') || w.first('no') || w.first('maybe')) {
    return re(['Ssssht. Dont answer now, wait until the end.', 'I dont care', 'Are you sure?', 'Dont insist on that']);
  }
  // console.error(words);
  return re(['Sorry?', 'Uhm.. Are you sure?','What do you mean?']);
}

async function parse(input) {
  switch (input) {
  case 'Bye!':
  case 'bye!':
  case 'bye':
  case 'quit':
  case 'q':
    process.exit(0);
  case '':
    return '';
  }
  return run(input);
}

async function main() {
  r2 = await r2pipe.open('/bin/ls'); 
  await r2.cmd('b 32');
  console.log(await r2.cmd('?E Welcome lazy human'));
  while (true) {
    try {
      const input = prompt('> ');
      let res = await parse(input);
      res = res.trim();
      if (res.indexOf('\n') === -1) {
        res = await r2.cmd("?E " + res);
      }
      if (res) {
        console.log(res);
      }
    } catch (e) {
      console.error(e);
    }
  }
  return '';
}

main().then(console.log).catch(console.error);

///
class Api {
  constructor(input) {
    this.source = input.trim();
    this.input = this.source.toLowerCase().replace(/,/g, ' ');
    this.ws = this.input.split(' ');
  }
  contains(w) {
    return this.input.indexOf(w) !== -1;
  }
  first(w) {
    if (this.ws.length > 0) {
      return w? this.ws[0] === w: ws[0];
    }
    return undefined;
  }
  second(w) {
    if (this.ws.length > 1) {
      return w? (this.ws[1] === w): this.ws[1];
    }
    return undefined;
  }
  have(x) {
    return this.ws.indexOf(x) !== -1;
  }
  after(x) {
    const b = this.ws.indexOf(x);
    if (b >= 0) {
      return this.ws[b + 1];
    }
    return undefined;
  }
  before(x) {
    const b = this.ws.indexOf(x);
    if (b > 0) {
      return this.ws[b - 1];
    }
    return undefined;
  }
  shift() {
    const ws = this.ws.slice(1);
    this.ws = ws;
  }
  isQuestion() {
    return this.input.endsWith('?');
  }
  isExclamation() {
    return this.input.endsWith('!');
  }
  bytes() {
    return +this.before('bytes');
  }
}

