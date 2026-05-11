import type { JadxClass, JadxMethod, R2JadxContext } from "./types";
import { R2JADX_HELP, r2jadxConfig } from "./config";
import { b64encode } from "./r2api";
import {
	dex2path,
	fileExists,
	parseOffset,
	pathJoin,
	readFile,
	runCmd,
	toPaddedHexString,
	walkSync,
	writeFile,
} from "./util";
import {
	r2jadxDisplayAddressLine,
	r2jadxDisplayLine,
	r2jadxDisplayPrefix,
	r2jadxIndentLine,
} from "./format";

interface R2JadxXrefRecord {
	kind: "class" | "method";
	target: string;
	addr: number;
	scope: string;
	line: string;
}

interface R2JadxXrefSymbol {
	kind: "class" | "method";
	target: string;
	min: number;
	max: number;
}

interface R2JadxXrefIndex {
	version: number;
	symbols: R2JadxXrefSymbol[];
	records: R2JadxXrefRecord[];
}

interface R2JadxJsonLine {
	str: string;
	offset?: number;
}

interface R2JadxMappingClass {
	json?: string;
	methods?: Array<{ offset?: string | number }>;
}

interface R2JadxMapping {
	classes?: R2JadxMappingClass[];
}

const r2jadxImportCache: Record<string, string[]> = {};

function processClass(data: JadxClass, mode: string, context: R2JadxContext): string {
	if (mode === "p") {
		return r2jadxClassMatches(data, context) ? r2jadxPackageLine(data) : "";
	}
	if (mode === "ci") {
		return r2jadxClassMatches(data, context) ? r2jadxImportLines(data, true) : "";
	}
	const methods = data.methods || [];
	if (mode === "dc*") {
		if (!r2jadxClassMatches(data, context)) {
			return "";
		}
		return methods.map((method) => processMethod(data, "dc*", context, method)).join("");
	}
	if (mode === "dc") {
		return r2jadxClassMatches(data, context) ? r2jadxReadClassSource(data) : "";
	}
	let res = "";
	for (const method of methods) {
		switch (mode) {
		case "a":
		case "d":
		case "dj":
		case "d*":
		case "cat":
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

function r2jadxClassOffset(data: JadxClass): number {
	const offsets = (data.methods || []).map((method) => parseOffset(method.offset)).filter((offset) => !isNaN(offset));
	return offsets.length > 0 ? Math.min(...offsets) : 0;
}

function r2jadxQualifiedClassName(data: JadxClass): string {
	const className = data.name || "";
	const packageName = data.package || "";
	if (packageName.length > 0 && className.indexOf(packageName + ".") === 0) {
		return className;
	}
	return packageName.length > 0 && className.length > 0 ? packageName + "." + className : className;
}

function r2jadxRecord(addr: number, fields: Record<string, string | number>): string {
	let res = toPaddedHexString(addr, 8);
	for (const key of Object.keys(fields)) {
		res += "\t" + key + "\t" + String(fields[key]);
	}
	return res + "\n";
}

function r2jadxImportPackage(importName: string): string {
	const trimmed = importName.replace(/\.\*$/, "");
	const lastDot = trimmed.lastIndexOf(".");
	return lastDot === -1 ? "" : trimmed.slice(0, lastDot);
}

function r2jadxClassImports(data: JadxClass): string[] {
	if (data.imports) {
		return data.imports.slice().sort();
	}
	if (!data.source) {
		return [];
	}
	if (r2jadxImportCache[data.source]) {
		return r2jadxImportCache[data.source];
	}
	const source = readFile(data.source.replace(".json", ".java")).toString();
	const imports = new Set<string>();
	for (const line of source.split(/\r?\n/g)) {
		const match = line.trim().match(/^import\s+(?:static\s+)?([^;]+);$/);
		if (match) {
			imports.add(match[1]);
		}
	}
	r2jadxImportCache[data.source] = Array.from(imports).sort();
	return r2jadxImportCache[data.source];
}

function r2jadxPackageLine(data: JadxClass): string {
	return toPaddedHexString(r2jadxClassOffset(data), 8) + "\t" + (data.package || "") + "\t" + r2jadxQualifiedClassName(data) + "\n";
}

function r2jadxImportLines(data: JadxClass, brief: boolean): string {
	let res = "";
	for (const importName of r2jadxClassImports(data)) {
		if (brief) {
			res += toPaddedHexString(r2jadxClassOffset(data), 8) + "\t" + importName + "\n";
			continue;
		}
		res += r2jadxRecord(r2jadxClassOffset(data), {
			"kind": "import",
			"package": data.package || "",
			"class": r2jadxQualifiedClassName(data),
			"import": importName,
			"import_package": r2jadxImportPackage(importName),
		});
	}
	return res;
}

function r2jadxCompactLine(line: string): string {
	return line.trim().replace(/\s+/g, " ");
}

function r2jadxXrefScope(data: JadxClass, method: JadxMethod): string {
	return r2jadxQualifiedClassName(data) + "." + method.name;
}

function r2jadxFindCurrentClass(classes: JadxClass[], context: R2JadxContext): JadxClass | undefined {
	return classes.find((data) => r2jadxClassMatches(data, context));
}

function r2jadxFindCurrentMethod(data: JadxClass | undefined, context: R2JadxContext): JadxMethod | undefined {
	if (!data) {
		return undefined;
	}
	return (data.methods || []).find((method) => r2jadxMethodMatches(data, method, context));
}

function r2jadxShortClassName(data: JadxClass): string {
	const name = data.name || "";
	return name.split(".").pop() || name;
}

function r2jadxMethodKey(data: JadxClass, method: JadxMethod): string {
	return r2jadxQualifiedClassName(data) + "." + method.name;
}

function r2jadxClassMaps(classes: JadxClass[]): {
	byQualified: Record<string, JadxClass>,
	byShort: Record<string, JadxClass[]>,
} {
	const byQualified: Record<string, JadxClass> = {};
	const byShort: Record<string, JadxClass[]> = {};
	for (const data of classes) {
		const qualifiedName = r2jadxQualifiedClassName(data);
		const shortName = r2jadxShortClassName(data);
		if (qualifiedName.length > 0) {
			byQualified[qualifiedName] = data;
		}
		if (shortName.length > 0) {
			byShort[shortName] = byShort[shortName] || [];
			byShort[shortName].push(data);
		}
	}
	return { byQualified, byShort };
}

function r2jadxResolveClassName(name: string, source: JadxClass, byQualified: Record<string, JadxClass>, byShort: Record<string, JadxClass[]>): JadxClass | undefined {
	if (byQualified[name]) {
		return byQualified[name];
	}
	for (const importName of r2jadxClassImports(source)) {
		if (importName === name || importName.endsWith("." + name)) {
			return byQualified[importName];
		}
		if (importName.endsWith(".*") && byQualified[importName.slice(0, -1) + name]) {
			return byQualified[importName.slice(0, -1) + name];
		}
	}
	const packageName = source.package || "";
	if (packageName.length > 0 && byQualified[packageName + "." + name]) {
		return byQualified[packageName + "." + name];
	}
	const matches = byShort[name] || [];
	return matches.length === 1 ? matches[0] : undefined;
}

function r2jadxHasMethod(data: JadxClass, methodName: string): boolean {
	return (data.methods || []).some((method) => method.name === methodName);
}

function r2jadxAddXref(records: R2JadxXrefRecord[], seen: Set<string>, record: R2JadxXrefRecord): void {
	const key = record.kind + "\t" + record.target + "\t" + record.addr + "\t" + record.scope + "\t" + record.line;
	if (!seen.has(key)) {
		seen.add(key);
		records.push(record);
	}
}

function r2jadxIndexClassRef(records: R2JadxXrefRecord[], seen: Set<string>, source: JadxClass, target: JadxClass, addr: number, scope: string, line: string): void {
	if (source === target) {
		return;
	}
	r2jadxAddXref(records, seen, {
		kind: "class",
		target: r2jadxQualifiedClassName(target),
		addr,
		scope,
		line,
	});
}

function r2jadxIndexMethodRef(records: R2JadxXrefRecord[], seen: Set<string>, target: JadxClass, methodName: string, addr: number, scope: string, line: string): void {
	if (!r2jadxHasMethod(target, methodName)) {
		return;
	}
	r2jadxAddXref(records, seen, {
		kind: "method",
		target: r2jadxQualifiedClassName(target) + "." + methodName,
		addr,
		scope,
		line,
	});
}

function r2jadxIndexXrefLine(records: R2JadxXrefRecord[], seen: Set<string>, source: JadxClass, method: JadxMethod, line: string, addr: number, byQualified: Record<string, JadxClass>, byShort: Record<string, JadxClass[]>): void {
	const compactLine = r2jadxCompactLine(line);
	if (compactLine.length === 0) {
		return;
	}
	const scope = r2jadxXrefScope(source, method);
	const qualifiedClassRe = /\b(?:[a-z_$][A-Za-z0-9_$]*\.)+[A-Z_$][A-Za-z0-9_$]*\b/g;
	const shortClassRe = /\b[A-Z_$][A-Za-z0-9_$]*\b/g;
	const callRe = /\b((?:[A-Za-z_$][A-Za-z0-9_$]*\.)*[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g;
	const bareCallRe = /(^|[^A-Za-z0-9_$\.])([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g;
	let match: RegExpExecArray | null;
	while ((match = qualifiedClassRe.exec(compactLine))) {
		const target = r2jadxResolveClassName(match[0], source, byQualified, byShort);
		if (target) {
			r2jadxIndexClassRef(records, seen, source, target, addr, scope, compactLine);
		}
	}
	while ((match = shortClassRe.exec(compactLine))) {
		const target = r2jadxResolveClassName(match[0], source, byQualified, byShort);
		if (target) {
			r2jadxIndexClassRef(records, seen, source, target, addr, scope, compactLine);
		}
	}
	while ((match = callRe.exec(compactLine))) {
		const target = r2jadxResolveClassName(match[1], source, byQualified, byShort);
		if (target) {
			r2jadxIndexClassRef(records, seen, source, target, addr, scope, compactLine);
			r2jadxIndexMethodRef(records, seen, target, match[2], addr, scope, compactLine);
		}
	}
	while ((match = bareCallRe.exec(compactLine))) {
		r2jadxIndexMethodRef(records, seen, source, match[2], addr, scope, compactLine);
	}
}

function r2jadxBuildXrefSymbols(classes: JadxClass[]): R2JadxXrefSymbol[] {
	const symbols: R2JadxXrefSymbol[] = [];
	for (const data of classes) {
		const classOffsets: number[] = [];
		for (const method of data.methods || []) {
			const range = r2jadxMethodRange(method);
			if (!isNaN(range.min) && !isNaN(range.max)) {
				classOffsets.push(range.min, range.max);
			}
		}
		if (classOffsets.length > 0) {
			symbols.push({
				kind: "class",
				target: r2jadxQualifiedClassName(data),
				min: Math.min(...classOffsets),
				max: Math.max(...classOffsets),
			});
		}
		for (const method of data.methods || []) {
			const range = r2jadxMethodRange(method);
			if (!isNaN(range.min) && !isNaN(range.max)) {
				symbols.push({
					kind: "method",
					target: r2jadxMethodKey(data, method),
					min: range.min,
					max: range.max,
				});
			}
		}
	}
	return symbols;
}

function r2jadxBuildXrefIndex(classes: JadxClass[]): R2JadxXrefIndex {
	const records: R2JadxXrefRecord[] = [];
	const seen = new Set<string>();
	const maps = r2jadxClassMaps(classes);
	for (const source of classes) {
		const scope = r2jadxQualifiedClassName(source);
		for (const importName of r2jadxClassImports(source)) {
			const target = maps.byQualified[importName];
			if (target) {
				r2jadxIndexClassRef(records, seen, source, target, r2jadxClassOffset(source), scope, "import " + importName);
			}
		}
		for (const method of source.methods || []) {
			let lastOffset = parseOffset(method.offset);
			for (const line of method.lines || []) {
				if (line.offset) {
					lastOffset = parseOffset(line.offset);
				}
				r2jadxIndexXrefLine(records, seen, source, method, line.code || "", lastOffset, maps.byQualified, maps.byShort);
			}
		}
	}
	return {
		version: 1,
		symbols: r2jadxBuildXrefSymbols(classes),
		records: records.sort((a, b) => a.target === b.target ? a.addr - b.addr : a.target.localeCompare(b.target)),
	};
}

function r2jadxXrefIndexPath(target: string): string {
	return pathJoin(target, "r2jadx-xrefs.json");
}

function r2jadxReadXrefIndex(indexFile: string): R2JadxXrefIndex | undefined {
	if (!fileExists(indexFile)) {
		return undefined;
	}
	const data = readFile(indexFile).trim();
	try {
		if (data.length === 0) {
			return undefined;
		}
		const parsed = JSON.parse(data) as R2JadxXrefIndex;
		return parsed.version === 1 && Array.isArray(parsed.symbols) && Array.isArray(parsed.records) ? parsed : undefined;
	} catch (e) {
		return undefined;
	}
}

function r2jadxLoadXrefIndex(target: string, classes: JadxClass[]): R2JadxXrefIndex {
	const indexFile = r2jadxXrefIndexPath(target);
	const cached = r2jadxReadXrefIndex(indexFile);
	if (cached) {
		return cached;
	}
	const records = r2jadxBuildXrefIndex(classes);
	writeFile(indexFile, JSON.stringify(records));
	return records;
}

function r2jadxXrefSymbol(index: R2JadxXrefIndex, context: R2JadxContext): R2JadxXrefSymbol | undefined {
	const methods = index.symbols.filter((symbol) => symbol.kind === "method" && context.offset >= symbol.min && context.offset <= symbol.max);
	if (methods.length > 0) {
		return methods[0];
	}
	return index.symbols.find((symbol) => symbol.kind === "class" && context.offset >= symbol.min && context.offset <= symbol.max);
}

function r2jadxXrefLinesFromIndex(index: R2JadxXrefIndex, context: R2JadxContext): string {
	const target = r2jadxXrefSymbol(index, context);
	if (!target) {
		return "";
	}
	let res = "";
	for (const record of index.records) {
		if (record.kind === target.kind && record.target === target.target) {
			res += toPaddedHexString(record.addr, 8) + "\t" + record.scope + "\t" + record.line + "\n";
		}
	}
	return res;
}

function r2jadxXrefLines(target: string, classes: JadxClass[], context: R2JadxContext): string {
	return r2jadxXrefLinesFromIndex(r2jadxLoadXrefIndex(target, classes), context);
}

function r2jadxMappedClassFile(target: string, context: R2JadxContext): string | undefined {
	const mapping = JSON.parse(readFile(pathJoin(target, "sources", "mapping.json"))) as R2JadxMapping;
	let best: { offset: number, file: string } | undefined;
	for (const klass of mapping.classes || []) {
		for (const method of klass.methods || []) {
			const offset = parseOffset(method.offset);
			if (!isNaN(offset) && klass.json && offset <= context.offset && (!best || offset > best.offset)) {
				best = { offset, file: pathJoin(target, "sources", klass.json) };
			}
		}
	}
	return best ? best.file : undefined;
}

function r2jadxMappingFile(outdir: string, level: string): string {
	return pathJoin(outdir, level, "sources", "mapping.json");
}

function r2jadxDirectClassFiles(target: string, context: R2JadxContext): string[] {
	try {
		const mapped = r2jadxMappedClassFile(target, context);
		if (mapped) {
			return [ mapped ];
		}
	} catch (e) {
	}
	const classes: string[] = [];
	const descriptor = context.functionName.match(/L([^;]+);/);
	if (descriptor) {
		classes.push(descriptor[1]);
	}
	const methodName = context.functionName.match(/([A-Za-z_$][A-Za-z0-9_$.]+)\.(?:method\.)?[A-Za-z_$<][A-Za-z0-9_$<>]*/);
	if (methodName) {
		classes.push(methodName[1].replace(/\./g, "/"));
	}
	const files: string[] = [];
	for (const className of classes) {
		const normalized = className.replace(/^L/, "").replace(/;$/, "").replace(/\./g, "/");
		files.push(pathJoin(target, "sources", normalized + ".json"));
		files.push(pathJoin(target, normalized + ".json"));
	}
	return Array.from(new Set(files)).filter(fileExists);
}

function r2jadxReadClasses(fileName: string): JadxClass[] {
	const fileData = readFile(fileName);
	const data = JSON.parse(fileData) as JadxClass;
	data.source = fileName;
	const classes = [ data ];
	if (data["inner-classes"]) {
		for (const klass of data["inner-classes"]) {
			klass.source = fileName;
			classes.push(klass);
		}
	}
	return classes;
}

function r2jadxProcessClassFile(fileName: string, mode: string, context: R2JadxContext): string {
	let res = "";
	for (const klass of r2jadxReadClasses(fileName)) {
		res += processClass(klass, mode, context);
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

function r2jadxMethodRange(method: JadxMethod): { min: number, max: number } {
	const offsets = r2jadxMethodLineOffsets(method);
	if (offsets.length === 0) {
		const offset = parseOffset(method.offset);
		return { min: offset, max: offset };
	}
	return { min: Math.min(...offsets), max: Math.max(...offsets) + 16 };
}

function r2jadxMethodContainsOffset(method: JadxMethod, offset: number): boolean {
	const range = r2jadxMethodRange(method);
	return offset >= range.min && offset <= range.max;
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

function r2jadxMethodLines(method: JadxMethod): R2JadxJsonLine[] {
	const lines: R2JadxJsonLine[] = [];
	const offset = parseOffset(method.offset);
	const declaration = (method.declaration || method.name).trim().split("\n");
	for (let i = 0; i < declaration.length; i++) {
		const suffix = i === declaration.length - 1 ? " {" : "";
		lines.push({ str: declaration[i] + suffix, offset });
	}
	let lastOffset = offset;
	for (const line of method.lines || []) {
		if (!line.code || line.code.length === 0) {
			continue;
		}
		if (line.offset) {
			lastOffset = parseOffset(line.offset);
		}
		lines.push({ str: r2jadxIndentLine(line.code, 1), offset: lastOffset });
	}
	lines.push({ str: "}" });
	return lines;
}

function r2jadxFormatMethodJson(method: JadxMethod): string {
	return JSON.stringify({ lines: r2jadxMethodLines(method) });
}

function processMethod(data: JadxClass, mode: string, context: R2JadxContext, method: JadxMethod): string {
	function comment(addr: number, line: string): string {
		if (mode === "dc" || mode === "cat") {
			if (!data.source) {
				return "";
			}
			const lastOffset = parseOffset(method.offset);
			if (mode === "cat" || (mode === "dc" && addr === lastOffset)) {
				const source = data.source.replace(".json", ".java");
				const fileData = readFile(source);
				return fileData.toString();
			}
			return "";
		}
		if (line === "") {
			return "";
		}
		if (mode === "d") {
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
	if (mode === "d") {
		return r2jadxMethodMatches(data, method, context) ? r2jadxFormatMethod(method) : "";
	}
	if (mode === "dj") {
		return r2jadxMethodMatches(data, method, context) ? r2jadxFormatMethodJson(method) : "";
	}
	if (mode === "d*" && !r2jadxMethodMatches(data, method, context)) {
		return "";
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
	if (mode === "ll" || mode === "hl") {
		let res = "";
		if (context.offset === lastOffset) {
			return processMethod(data, "d*", context, method);
		}
		for (const line of lines) {
			if (parseOffset(line.offset) === context.offset - 16) {
				res += processMethod(data, "d*", context, method);
			}
		}
		return res;
	}

	let res = comment(parseOffset(method.offset) + 16, method.name);
	for (const line of lines) {
		const addr = parseOffset(line.offset || lastOffset);
		const code = mode === "d" ? line.code : line.code.trim();
		res += comment(addr, code);
		if (line.offset) {
			lastOffset = parseOffset(line.offset);
		}
	}
	return res;
}

function r2jadxCrawlFiles(target: string, mode: string, context: R2JadxContext): string {
	const ext = "json";
	const xrefIndexFile = r2jadxXrefIndexPath(target);
	if (mode === "x") {
		const cached = r2jadxReadXrefIndex(xrefIndexFile);
		if (cached) {
			return r2jadxXrefLinesFromIndex(cached, context);
		}
	}
	if (mode === "dc" || mode === "dc*" || mode === "ci" || mode === "d" || mode === "dj" || mode === "d*" || mode === "p") {
		for (const fileName of r2jadxDirectClassFiles(target, context)) {
			try {
				const directRes = r2jadxProcessClassFile(fileName, mode, context);
				if (directRes.length > 0) {
					return directRes;
				}
			} catch (e) {
				console.error("" + fileName + ": " + e);
			}
		}
		return "";
	}
	const files = walkSync(target).filter((_) => (_.endsWith && _.endsWith(ext) && _ !== xrefIndexFile && !_.endsWith("/mapping.json")));
	let res = "";
	const classes: JadxClass[] = [];
	for (const fileName of files) {
		try {
			if (mode === "cat") {
				const fileData = readFile(fileName.replace(".json", ".java"));
				res += fileData;
			} else {
				classes.push(...r2jadxReadClasses(fileName));
			}
		} catch (e) {
			console.error("" + fileName + ": " + e);
		}
	}
	if (mode === "pl") {
		const packages: Record<string, { addr: number, count: number }> = {};
		for (const data of classes) {
			const packageName = data.package || "";
			const addr = r2jadxClassOffset(data);
			const entry = packages[packageName] || { addr, count: 0 };
			entry.addr = Math.min(entry.addr, addr);
			entry.count++;
			packages[packageName] = entry;
		}
		for (const packageName of Object.keys(packages).sort()) {
			res += r2jadxRecord(packages[packageName].addr, { "kind": "package", "package": packageName, "classes": packages[packageName].count });
		}
		return res;
	}
	if (mode === "pi") {
		const current = classes.find((data) => r2jadxClassMatches(data, context));
		context.packageName = current ? current.package || "" : context.packageName || "";
		const packageImports: Record<string, { addr: number, count: number }> = {};
		for (const data of classes) {
			if ((data.package || "") !== (context.packageName || "")) {
				continue;
			}
			for (const importName of r2jadxClassImports(data)) {
				const entry = packageImports[importName] || { addr: r2jadxClassOffset(data), count: 0 };
				entry.addr = Math.min(entry.addr, r2jadxClassOffset(data));
				entry.count++;
				packageImports[importName] = entry;
			}
		}
		for (const importName of Object.keys(packageImports).sort()) {
			res += r2jadxRecord(packageImports[importName].addr, {
				"kind": "package_import",
				"package": context.packageName || "",
				"import": importName,
				"import_package": r2jadxImportPackage(importName),
				"classes": packageImports[importName].count,
			});
		}
		return res;
	}
	if (mode === "x") {
		return r2jadxXrefLines(target, classes, context);
	}
	for (const data of classes) {
		if (mode === "i") {
			res += r2jadxImportLines(data, false);
		} else {
			res += processClass(data, mode, context);
		}
	}
	return res;
}

function r2jadxCrawl(target: string, mode: string, context: R2JadxContext): string {
	switch (mode) {
	case "cn":
	case "p":
	case "ci":
	case "d":
	case "dj":
	case "d*":
	case "x":
		return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, context);
	case "i":
	case "pi":
	case "pl":
		return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, context);
	case "dc":
		return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, context);
	case "dc*":
		return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, context);
	case "a":
		return r2jadxCrawlFiles(pathJoin(target, "hl"), "cat", context);
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

function r2jadxNeedsHighJson(mode: string): boolean {
	return mode !== "ll" && mode !== "all";
}

function r2jadxNeedsHighJava(mode: string): boolean {
	return mode === "a" || mode === "dc" || mode === "cat";
}

function r2jadxNeedsLowJson(mode: string): boolean {
	return mode === "ll" || mode === "all";
}

function r2jadxHasHighJava(outdir: string): boolean {
	try {
		const mapping = JSON.parse(readFile(r2jadxMappingFile(outdir, "hl"))) as R2JadxMapping;
		for (const klass of mapping.classes || []) {
			if (klass.json) {
				return fileExists(pathJoin(outdir, "hl", "sources", klass.json.replace(/\.json$/, ".java")));
			}
		}
	} catch (e) {
	}
	return false;
}

export function r2jadxEnsureDecompiled(target: string, mode = "d"): string {
	const outdir = dex2path(target);
	if (r2jadxNeedsLowJson(mode) && !fileExists(r2jadxMappingFile(outdir, "ll"))) {
		console.error("jadx: Performing the low level json decompilation...");
		runCmd([ "r2pm", "-r", "jadx", "--output-format", "json", "-m", "simple", "-d", pathJoin(outdir, "ll"), target ]);
	}
	if (r2jadxNeedsHighJava(mode) && !r2jadxHasHighJava(outdir)) {
		console.error("jadx: Performing the high level decompilation...");
		runCmd([ "r2pm", "-r", "jadx", "--show-bad-code", "--output-format", "java", "-d", pathJoin(outdir, "hl"), target ]);
	}
	if (r2jadxNeedsHighJson(mode) && !fileExists(r2jadxMappingFile(outdir, "hl"))) {
		console.error("jadx: Constructing the high level jsons...");
		runCmd([ "r2pm", "-r", "jadx", "--show-bad-code", "--output-format", "json", "-d", pathJoin(outdir, "hl"), target ]);
	}
	return outdir;
}

export function r2jadxDecompile(target: string, mode: string, context: R2JadxContext): string {
	const outdir = r2jadxEnsureDecompiled(target, mode);
	return r2jadxCrawl(outdir, mode, context);
}
