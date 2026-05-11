import type { JadxClass, JadxMethod, R2JadxContext } from "./types";
import { R2JADX_HELP, r2jadxConfig } from "./config";
import { b64encode } from "./r2api";
import {
	dex2path,
	directoryExists,
	parseOffset,
	pathJoin,
	readFile,
	runCmd,
	walkSync,
} from "./util";
import {
	r2jadxDisplayAddressLine,
	r2jadxDisplayLine,
	r2jadxDisplayPrefix,
	r2jadxIndentLine,
} from "./format";

function processClass(data: JadxClass, mode: string, context: R2JadxContext): string {
	const methods = data.methods || [];
	if (mode === "c") {
		return r2jadxClassMatches(data, context) ? r2jadxReadClassSource(data) : "";
	}
	let res = "";
	for (const method of methods) {
		switch (mode) {
		case "a":
		case "f":
		case "cat":
		case "r":
		case "r2":
		case "all":
		case "ahl":
		case "ll":
		case "hl":
			res += processMethod(data, mode, context, method);
			break;
		default:
			res += "Invalid mode " + mode + "\n";
			break;
		}
	}
	return res;
}

function r2jadxReadClassSource(data: JadxClass): string {
	if (!data.source) {
		return "";
	}
	const source = readFile(data.source.replace(".json", ".java")).toString();
	return r2jadxConfig.addr ? r2jadxAddressClassSource(data, source) : source;
}

function r2jadxSanitizeName(name: string): string {
	return name.replace(/[^A-Za-z0-9_]+/g, "_").replace(/^_+|_+$/g, "");
}

function r2jadxMethodLineOffsets(method: JadxMethod): number[] {
	const offsets = [ parseOffset(method.offset) ];
	for (const line of method.lines || []) {
		if (line.offset) {
			offsets.push(parseOffset(line.offset));
		}
	}
	return offsets.filter((offset) => !isNaN(offset));
}

function r2jadxMethodContainsOffset(method: JadxMethod, offset: number): boolean {
	const offsets = r2jadxMethodLineOffsets(method);
	if (offsets.length === 0) {
		return false;
	}
	const min = Math.min(...offsets);
	const max = Math.max(...offsets);
	return offset >= min && offset <= max + 16;
}

function r2jadxClassMatches(data: JadxClass, context: R2JadxContext): boolean {
	for (const method of data.methods || []) {
		if (r2jadxMethodMatches(data, method, context)) {
			return true;
		}
	}
	return false;
}

function r2jadxNormalizeSourceLine(line: string, className: string): string {
	let normalized = line.trim();
	if (className.length > 0) {
		normalized = normalized.replaceAll(className + ".", "");
	}
	normalized = normalized.replace(/\b[A-Za-z_$][A-Za-z0-9_$]*\.(?=[A-Z_])/g, "");
	return normalized.replace(/\s+/g, " ");
}

function r2jadxFindSourceLine(lines: string[], needle: string, start: number, className: string, used?: Set<number>): number {
	const trimmedNeedle = needle.trim();
	if (trimmedNeedle.length === 0) {
		return -1;
	}
	const normalizedNeedle = r2jadxNormalizeSourceLine(trimmedNeedle, className);
	for (let i = start; i < lines.length; i++) {
		if (used && used.has(i)) {
			continue;
		}
		const trimmedLine = lines[i].trim();
		const normalizedLine = r2jadxNormalizeSourceLine(trimmedLine, className);
		if (trimmedLine === trimmedNeedle || normalizedLine === normalizedNeedle) {
			return i;
		}
		if (normalizedLine.length > 0 && normalizedNeedle.length > 0 &&
			(normalizedLine.indexOf(normalizedNeedle) !== -1 || normalizedNeedle.indexOf(normalizedLine) !== -1)) {
			return i;
		}
		if (trimmedLine === trimmedNeedle + " {" || normalizedLine === normalizedNeedle + " {") {
			return i;
		}
	}
	return -1;
}

function r2jadxFindClosingBrace(lines: string[], start: number): number {
	for (let i = start; i < lines.length; i++) {
		if (lines[i].trim() === "}") {
			return i;
		}
	}
	return -1;
}

function r2jadxAddressClassSource(data: JadxClass, source: string): string {
	const lines = source.replace(/\r/g, "").split("\n");
	const addresses = new Array<number | undefined>(lines.length);
	let cursor = 0;
	const className = data.name || "";
	const used = new Set<number>();
	for (const method of data.methods || []) {
		const methodOffset = parseOffset(method.offset);
		let methodStart = cursor;
		for (const declarationLine of (method.declaration || "").split("\n")) {
			const lineIndex = r2jadxFindSourceLine(lines, declarationLine, cursor, className, used);
			if (lineIndex !== -1) {
				addresses[lineIndex] = methodOffset;
				used.add(lineIndex);
				cursor = lineIndex + 1;
				methodStart = Math.min(methodStart, lineIndex);
			}
		}
		let lastOffset = methodOffset;
		let lastLineIndex = cursor;
		for (const line of method.lines || []) {
			if (line.offset) {
				lastOffset = parseOffset(line.offset);
			}
			const lineIndex = r2jadxFindSourceLine(lines, line.code, methodStart, className, used);
			if (lineIndex !== -1) {
				addresses[lineIndex] = lastOffset;
				used.add(lineIndex);
				lastLineIndex = Math.max(lastLineIndex, lineIndex);
			}
		}
		const closeIndex = r2jadxFindClosingBrace(lines, lastLineIndex + 1);
		if (closeIndex !== -1) {
			addresses[closeIndex] = lastOffset;
			used.add(closeIndex);
			cursor = closeIndex + 1;
		}
	}
	return lines.map((line, index) => r2jadxDisplayAddressLine(addresses[index], line)).join("\n");
}

function r2jadxMethodMatches(data: JadxClass, method: JadxMethod, context: R2JadxContext): boolean {
	if (r2jadxMethodContainsOffset(method, context.offset)) {
		return true;
	}
	const functionName = context.functionName;
	if (functionName.length === 0) {
		return false;
	}
	const className = data.name || "";
	const packageName = data.package || "";
	const qualifiedName = packageName.length > 0 ? packageName + "." + className : className;
	const classTokens = [
		r2jadxSanitizeName(className),
		r2jadxSanitizeName(qualifiedName),
	].filter((token) => token.length > 0);
	if (!classTokens.some((token) => functionName.indexOf("L" + token) !== -1 || functionName.indexOf(token) !== -1)) {
		return false;
	}
	const methodToken = r2jadxSanitizeName(method.name);
	return methodToken.length > 0 && (
		functionName.indexOf(".method." + methodToken) !== -1 ||
		functionName.indexOf("_" + methodToken + "_") !== -1
	);
}

function r2jadxFormatMethod(method: JadxMethod): string {
	let res = "";
	const offset = parseOffset(method.offset);
	const declaration = (method.declaration || method.name).trim().split("\n");
	for (let i = 0; i < declaration.length; i++) {
		const suffix = i === declaration.length - 1 ? " {" : "";
		res += r2jadxDisplayAddressLine(offset, declaration[i] + suffix) + "\n";
	}
	let lastOffset = offset;
	for (const line of method.lines || []) {
		if (!line.code || line.code.length === 0) {
			continue;
		}
		if (line.offset) {
			lastOffset = parseOffset(line.offset);
		}
		res += r2jadxDisplayAddressLine(lastOffset, r2jadxIndentLine(line.code, 1)) + "\n";
	}
	res += r2jadxDisplayAddressLine(lastOffset, "}") + "\n";
	return res;
}

function processMethod(data: JadxClass, mode: string, context: R2JadxContext, method: JadxMethod): string {
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
			return "";
		}
		line = line.replaceAll("\t", "  ");
		line = line.replaceAll("\r", "");
		line = line.replaceAll("\n", "");
		line = line.replaceAll(/[^ -~]+/g, "");
		line = line.replaceAll(/^SourceFile:\d+ /g, "");
		const b64line = b64encode(line);
		if (b64line.length > 2048) {
			return "CCu toolong @ " + addr + "\n";
		}
		return "CCu base64:" + b64line + " @ " + addr + "\n";
	}

	let lastOffset = parseOffset(method.offset);
	const lines = method.lines || [];
	if (mode === "f") {
		return r2jadxMethodMatches(data, method, context) ? r2jadxFormatMethod(method) : "";
	}
	if (mode === "all" || mode === "ahl") {
		let res = "\n" + r2jadxDisplayPrefix(parseOffset(method.offset)) + method.name + ":\n";
		for (const line of lines) {
			const lineOffset = parseOffset(line.offset || lastOffset);
			res += r2jadxDisplayPrefix(lineOffset) + r2jadxDisplayLine(line.code) + "\n";
			if (line.offset) {
				lastOffset = parseOffset(line.offset);
			}
		}
		return res;
	}
	if (mode === "r") {
		mode = "r2";
	}

	if (mode === "ll" || mode === "hl") {
		let res = "";
		if (context.offset === lastOffset) {
			return processMethod(data, "r2", context, method);
		}
		for (const line of lines) {
			if (parseOffset(line.offset) === context.offset - 16) {
				res += processMethod(data, "r2", context, method);
			}
		}
		return res;
	}

	let res = comment(parseOffset(method.offset) + 16, method.name);
	for (const line of lines) {
		const addr = parseOffset(line.offset || lastOffset);
		const code = mode === "f" ? line.code : line.code.trim();
		res += comment(addr, code);
		if (line.offset) {
			lastOffset = parseOffset(line.offset);
		}
	}
	return res;
}

function r2jadxCrawlFiles(target: string, mode: string, context: R2JadxContext): string {
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
				data.source = fileName;
				res += processClass(data, mode, context);
				if (data["inner-classes"]) {
					for (const klass of data["inner-classes"]) {
						klass.source = fileName;
						res += processClass(klass, mode, context);
					}
				}
			}
		} catch (e) {
			console.error("" + fileName + ": " + e);
		}
	}
	return res;
}

function r2jadxCrawl(target: string, mode: string, context: R2JadxContext): string {
	switch (mode) {
	case "cn":
	case "f":
		return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, context);
	case "c":
		return r2jadxCrawlFiles(pathJoin(target, "hl"), "c", context);
	case "a":
		return r2jadxCrawlFiles(pathJoin(target, "hl"), "cat", context);
	case "r":
		return r2jadxCrawlFiles(pathJoin(target, "ll"), mode, context);
	case "r2":
		return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, context);
	case "ll":
		return r2jadxCrawlFiles(pathJoin(target, "ll"), mode, context);
	case "hl":
		return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, context);
	case "ahl":
		return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, context);
	case "all":
		return r2jadxCrawlFiles(pathJoin(target, "ll"), mode, context);
	case "cat":
		return r2jadxCrawlFiles(pathJoin(target, "cat"), mode, context);
	case "?":
	case "h":
	case "help":
	default:
		return R2JADX_HELP;
	}
}

export function r2jadxEnsureDecompiled(target: string): string {
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
	return outdir;
}

export function r2jadxDecompile(target: string, mode: string, context: R2JadxContext): string {
	const outdir = r2jadxEnsureDecompiled(target);
	return r2jadxCrawl(outdir, mode, context);
}
