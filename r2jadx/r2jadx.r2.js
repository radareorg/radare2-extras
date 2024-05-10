// r2js rewrite of the original nodejs's r2jadx -- 2023-2024
// -- pancake -- this is far from complete, contribs are welcome

function nospace(d) {
	if (d.indexOf(' ') !== -1) {
		throw new Error("Path cant contain spaces");
	}
	return d;
}

function directoryExists(d) {
	const directory = r2.cmd("'!!test -d " + nospace(d) + " && echo exists").trim();
	return directory === 'exists';
}

function runCmd(c) {
	const cmdline = c.join(" ");
	console.log(cmdline);
	r2.cmd("'!" + cmdline);
}

function toPaddedHexString (num, len) {
	const str = parseInt(num).toString(16);
	return '0x' + ('0'.repeat(len - str.length) + str);
}

function pathJoin(...args) {
	return args.join('/');
}

function readFile(f) {
	return r2.cmd("cat "+ f);
}

function dex2path (target) {
	return target + '.d';
}

function walkSync(dir, arr) {
	if (arguments.length === 1) {
		arr = [];
	}
	const files = r2.cmd('!!find '+dir+' -type f');
	return files.trim().split(/\n/g);
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
				const fileData = readFile(source);
				return fileData.toString('utf8');
			}
			return '';
		}
		if (line == '') {
			return '';
		}
		if (mode === 'f') {
			let lastOffset = parseInt(method.offset);
			if (addr === lastOffset) {
				return toPaddedHexString(addr, 8) + '  ' + line + '\n';
			}
			return '';
		}
		line = line.replaceAll("\t", "  ");
		line = line.replaceAll("\r", "");
		line = line.replaceAll("\n", "");
		line = line.replaceAll(/[^ -~]+/g, "");
		line = line.replaceAll(/^SourceFile:\d+ /g, "");
		const b64line = b64(line);
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

function r2jadxCrawlFiles(target, mode, arg) {
	const ext = 'json'; // (mode === 'cat' || mode === 'c') ? 'java' : 'json';

	// console.error('FINDUS', target);
	const files = walkSync(target).filter(_ => (_.endsWith && _.endsWith(ext)));
	let res = '';
	for (let fileName of files) {
		try {
			if (mode === 'cat') {
				const fileData = readFile(fileName.replace('.json', '.java'));
				res += fileData;
			} else {
				const fileData = readFile(fileName);
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

function r2jadxCrawl(target, mode, arg) {
	// console.log('crawling', arguments);
	switch (mode) {
	case 'cn':
	case 'f':
		return r2jadxCrawlFiles(pathJoin(target, 'hl'), mode, arg);
	case 'c':
		return r2jadxCrawlFiles(pathJoin(target, 'hl'), 'c', arg);
	case 'a':
		return r2jadxCrawlFiles(pathJoin(target, 'hl'), 'cat', arg);
	case 'r':
		return r2jadxCrawlFiles(pathJoin(target, 'll'), mode, arg);
	case 'r2':
		return r2jadxCrawlFiles(pathJoin(target, 'hl'), mode, arg);
	case 'll':
		return r2jadxCrawlFiles(pathJoin(target, 'll'), mode, arg);
	case 'hl':
		return r2jadxCrawlFiles(pathJoin(target, 'hl'), mode, arg);
	case 'ahl':
		return r2jadxCrawlFiles(pathJoin(target, 'hl'), mode, arg);
	case 'all':
		return r2jadxCrawlFiles(pathJoin(target, 'll'), mode, arg);
	case 'cat':
		return r2jadxCrawlFiles(pathJoin(target, 'cat'), mode, arg);
	case '?':
	case 'h':
	case 'help':
	default:
		return 'Usage: r2jadx ([filename])[ll,hl,all,ahl,cat,help]';
	}
}

function r2jadxDecompile(target, mode, arg) {
	const outdir = dex2path(target);
	if (!directoryExists (outdir)) {
		console.error('jadx: Performing the low level decompilation...');
		runCmd([ 'r2pm', '-r', 'jadx', '--output-format', 'json', '-m', 'simple', '-d', pathJoin(outdir, 'll'), target ]);
		runCmd([ 'r2pm', '-r', 'jadx', '--output-format', 'java', '-m', 'simple', '-d', pathJoin(outdir, 'll'), target ]);
		console.error('jadx: Performing the high level decompilation...');
		runCmd([ 'r2pm', '-r', 'jadx', '--show-bad-code', '--output-format', 'java', '-d', pathJoin(outdir, 'hl'), target ]);
		console.error('jadx: Constructing the high level jsons...');
		runCmd([ 'r2pm', '-r', 'jadx', '--show-bad-code', '--output-format', 'json', '-d', pathJoin(outdir, 'hl'), target ]);
	}
  	return r2jadxCrawl(outdir, mode, arg);
}

function r2jadxMain(argv) {
	function helpMessage() {
		console.error('Usage: r2jadx [-mode]');
		console.error('Setup: e cmd.pdc=r2jadx');
		console.error(' -r   = import low level decompilation as comments');
		console.error(' -r2  = import high level decompilation as comments');
		console.error('----------------------------------');
		console.error(' -cn  = show current classname');
		console.error(' -a   = show decompilation of all the classes');
		console.error(' -c   = decompile current class');
		console.error(' -f   = decompile current function');
		console.error(' -ahl = all high level decompilation');
		console.error(' -all = all low level decompilation');
		console.error(' -hl  = high level decompilation');
		console.error(' -ll  = low level decompilation');
	}
	// console.log(argv);
	const r2arg = (argv.length > 0 && argv[0][0] !== '-') ? argv[0] : undefined;
	// console.log(r2arg);
	if (r2arg == '' || r2arg === '?' || r2arg == '-h') {
		helpMessage();
		return;
	}
	try {
		r2.cmd('af');
		const info = r2.cmdj('ij');
		const fileName = info.core.file;
		const fcn = r2.cmdj('afij');
		if (!fileName.endsWith('.dex')) {
			throw new Error('Sorry, this is not a DEX file');
		}
		if (!fileName) {
			throw new Error('Cannot find function');
		}
		const fcnOffset = (fcn && fcn.length > 0) ? fcn[0].offset : 0;
		let mode = 'all';
		if (argv[0][0] === '-') {
			mode = argv[0].substring(1);
		}
		const res = r2jadxDecompile(fileName, mode, fcnOffset);
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
		console.error('Oops', e, e.output ? e.output.toString() : '');
		throw e;
	}
}

function r2jadxBegin() {
//	console.log("WIP: r2jadx plugin is highly experimental and not yet usable, please contribute");
	r2.unload("core", "r2jadx");
	r2.plugin("core", function() {
		function coreCall(cmd) {
			if (cmd.startsWith("r2jadx")) {
				const argv = cmd.substring(6).trim().split(' ');
				r2jadxMain(argv);
				return true;
			}
			return false;
		}
		return {
			"name": "r2jadx",
			"license": "MIT",
			"desc": "jadx decompiler for radare2",
			"call": coreCall
		};
	});
}
r2jadxBegin();
