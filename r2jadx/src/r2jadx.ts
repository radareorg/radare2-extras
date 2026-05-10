// r2js rewrite of the original nodejs's r2jadx -- 2023-2024
// -- pancake -- this is far from complete, contribs are welcome

declare function b64(data: string): string;

interface R2CorePlugin {
	name: string;
	license: string;
	desc: string;
	call: (cmd: string) => boolean;
}

interface R2Api {
	cmd: (cmd: string) => string;
	cmdj: <T = unknown>(cmd: string) => T;
	plugin: (type: string, factory: () => R2CorePlugin) => void;
	unload: (type: string, name: string) => void;
}

declare const r2: R2Api;

type Offset = string | number | undefined;

interface JadxLine {
	offset?: Offset;
	code: string;
}

interface JadxMethod {
	offset: Offset;
	name: string;
	lines?: JadxLine[];
}

interface JadxClass {
	name?: string;
	source?: string;
	methods?: JadxMethod[];
	"inner-classes"?: JadxClass[];
}

interface R2Info {
	core: {
		file: string;
	};
}

interface R2FunctionInfo {
	offset: number;
}

function nospace(d: string): string {
	if (d.indexOf(" ") !== -1) {
		throw new Error("Path cant contain spaces");
	}
	return d;
}

function directoryExists(d: string): boolean {
	const directory = r2.cmd("'!!test -d " + nospace(d) + " && echo exists").trim();
	return directory === "exists";
}

function runCmd(c: string[]): void {
	const cmdline = c.join(" ");
	console.log(cmdline);
	r2.cmd("'!" + cmdline);
}

function parseOffset(value: Offset): number {
	return parseInt(String(value));
}

function toPaddedHexString(num: Offset, len: number): string {
	const str = parseOffset(num).toString(16);
	return "0x" + ("0".repeat(len - str.length) + str);
}

function pathJoin(...args: string[]): string {
	return args.join("/");
}

function readFile(f: string): string {
	return r2.cmd("cat " + f);
}

function dex2path(target: string): string {
	return target + ".d";
}

function walkSync(dir: string): string[] {
	const files = r2.cmd("!!find " + dir + " -type f").trim();
	return files.length > 0 ? files.split(/\n/g) : [];
}

function processClass(data: JadxClass, mode: string, offset: Offset): string {
	const classOffset = parseOffset(offset);
	let res = "";
	if (data.methods) {
		for (const method of data.methods) {
			switch (mode) {
			case "a":
			case "c":
			case "f":
			case "cat":
			case "r":
			case "r2":
			case "all":
			case "ahl":
			case "ll":
			case "hl":
				res += processMethod(data, mode, classOffset, method);
				break;
			default:
				res += "Invalid mode " + mode + "\n";
				break;
			}
		}
	}
	return res;
}

function processMethod(data: JadxClass, mode: string, offset: number, method: JadxMethod): string {
	function comment(addr: number, line: string): string {
		if (mode === "c" || mode === "cat") {
			if (!data.source) {
				return "";
			}
			const lastOffset = parseOffset(method.offset);
			if (mode === "cat" || (mode === "c" && addr === lastOffset)) {
				const source = data.source.replace(".json", ".java");
				const fileData = readFile(source);
				return fileData.toString();
			}
			return "";
		}
		if (line === "") {
			return "";
		}
		if (mode === "f") {
			const lastOffset = parseOffset(method.offset);
			if (addr === lastOffset) {
				return toPaddedHexString(addr, 8) + "  " + line + "\n";
			}
			return "";
		}
		line = line.replaceAll("\t", "  ");
		line = line.replaceAll("\r", "");
		line = line.replaceAll("\n", "");
		line = line.replaceAll(/[^ -~]+/g, "");
		line = line.replaceAll(/^SourceFile:\d+ /g, "");
		const b64line = b64(line);
		if (b64line.length > 2048) {
			return "CCu toolong @ " + addr + "\n";
		}
		return "CCu base64:" + b64line + " @ " + addr + "\n";
	}

	let lastOffset = parseOffset(method.offset);
	const lines = method.lines || [];
	if (mode === "all" || mode === "ahl") {
		let res = "\n" + toPaddedHexString(method.offset, 8) + "  " + method.name + ":\n";
		for (const line of lines) {
			res += toPaddedHexString(line.offset || lastOffset, 8) + "  " + line.code + "\n";
			if (line.offset) {
				lastOffset = parseOffset(line.offset);
			}
		}
		return res;
	}
	if (mode === "r") {
		offset = 0;
		mode = "r2";
	}

	if (mode === "ll" || mode === "hl") {
		let res = "";
		if (offset === lastOffset) {
			return processMethod(data, "r2", offset, method);
		}
		for (const line of lines) {
			if (parseOffset(line.offset) === offset - 16) {
				res += processMethod(data, "r2", offset, method);
			}
		}
		return res;
	}

	let res = comment(parseOffset(method.offset) + 16, method.name);
	for (const line of lines) {
		const addr = parseOffset(line.offset || lastOffset);
		res += comment(addr, line.code.trim());
		if (line.offset) {
			lastOffset = parseOffset(line.offset);
		}
	}
	return res;
}

function r2jadxCrawlFiles(target: string, mode: string, arg: Offset): string {
	const ext = "json";
	const files = walkSync(target).filter((_) => (_.endsWith && _.endsWith(ext)));
	let res = "";
	for (const fileName of files) {
		try {
			if (mode === "cat") {
				const fileData = readFile(fileName.replace(".json", ".java"));
				res += fileData;
			} else {
				const fileData = readFile(fileName);
				const data = JSON.parse(fileData) as JadxClass;
				res += processClass(data, mode, arg);
				if (data["inner-classes"]) {
					for (const klass of data["inner-classes"]) {
						klass.source = fileName;
						res += processClass(klass, mode, arg);
					}
				}
			}
		} catch (e) {
			console.error("" + fileName + ": " + e);
		}
	}
	return res;
}

function r2jadxCrawl(target: string, mode: string, arg: Offset): string {
	switch (mode) {
	case "cn":
	case "f":
		return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, arg);
	case "c":
		return r2jadxCrawlFiles(pathJoin(target, "hl"), "c", arg);
	case "a":
		return r2jadxCrawlFiles(pathJoin(target, "hl"), "cat", arg);
	case "r":
		return r2jadxCrawlFiles(pathJoin(target, "ll"), mode, arg);
	case "r2":
		return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, arg);
	case "ll":
		return r2jadxCrawlFiles(pathJoin(target, "ll"), mode, arg);
	case "hl":
		return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, arg);
	case "ahl":
		return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, arg);
	case "all":
		return r2jadxCrawlFiles(pathJoin(target, "ll"), mode, arg);
	case "cat":
		return r2jadxCrawlFiles(pathJoin(target, "cat"), mode, arg);
	case "?":
	case "h":
	case "help":
	default:
		return "Usage: r2jadx ([filename])[ll,hl,all,ahl,cat,help]";
	}
}

function r2jadxDecompile(target: string, mode: string, arg: Offset): string {
	const outdir = dex2path(target);
	if (!directoryExists(outdir)) {
		console.error("jadx: Performing the low level decompilation...");
		runCmd([ "r2pm", "-r", "jadx", "--output-format", "json", "-m", "simple", "-d", pathJoin(outdir, "ll"), target ]);
		runCmd([ "r2pm", "-r", "jadx", "--output-format", "java", "-m", "simple", "-d", pathJoin(outdir, "ll"), target ]);
		console.error("jadx: Performing the high level decompilation...");
		runCmd([ "r2pm", "-r", "jadx", "--show-bad-code", "--output-format", "java", "-d", pathJoin(outdir, "hl"), target ]);
		console.error("jadx: Constructing the high level jsons...");
		runCmd([ "r2pm", "-r", "jadx", "--show-bad-code", "--output-format", "json", "-d", pathJoin(outdir, "hl"), target ]);
	}
	return r2jadxCrawl(outdir, mode, arg);
}

function r2jadxMain(argv: string[]): string | undefined {
	function helpMessage(): void {
		console.error("Usage: r2jadx [-mode]");
		console.error("Setup: e cmd.pdc=r2jadx");
		console.error(" -r   = import low level decompilation as comments");
		console.error(" -r2  = import high level decompilation as comments");
		console.error("----------------------------------");
		console.error(" -cn  = show current classname");
		console.error(" -a   = show decompilation of all the classes");
		console.error(" -c   = decompile current class");
		console.error(" -f   = decompile current function");
		console.error(" -ahl = all high level decompilation");
		console.error(" -all = all low level decompilation");
		console.error(" -hl  = high level decompilation");
		console.error(" -ll  = low level decompilation");
	}

	const firstArg = argv[0] || "";
	if (firstArg === "" || firstArg === "?" || firstArg === "-h") {
		helpMessage();
		return undefined;
	}
	try {
		r2.cmd("af");
		const info = r2.cmdj<R2Info>("ij");
		const fileName = info.core.file;
		const fcn = r2.cmdj<R2FunctionInfo[]>("afij");
		if (!fileName.endsWith(".dex")) {
			throw new Error("Sorry, this is not a DEX file");
		}
		if (!fileName) {
			throw new Error("Cannot find function");
		}
		const fcnOffset = (fcn && fcn.length > 0) ? fcn[0].offset : 0;
		let mode = "all";
		if (firstArg[0] === "-") {
			mode = firstArg.substring(1);
		}
		const res = r2jadxDecompile(fileName, mode, fcnOffset);
		if (mode.startsWith("r")) {
			for (const line of res.split("\n")) {
				if (line.trim().length > 0) {
					r2.cmd(line);
				}
			}
		} else {
			console.log(res);
		}
		return res;
	} catch (e) {
		const error = e as { output?: { toString: () => string } };
		console.error("Oops", e, error.output ? error.output.toString() : "");
		throw e;
	}
}

function r2jadxBegin(): void {
	r2.unload("core", "r2jadx");
	r2.plugin("core", function() {
		function coreCall(cmd: string): boolean {
			if (cmd.startsWith("r2jadx")) {
				const argv = cmd.substring(6).trim().split(" ");
				r2jadxMain(argv);
				return true;
			}
			return false;
		}
		return {
			name: "r2jadx",
			license: "MIT",
			desc: "jadx decompiler for radare2",
			call: coreCall
		};
	});
}

r2jadxBegin();
