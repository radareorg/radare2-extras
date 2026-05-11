import type { JadxClass, Offset } from "./types";
import { r2jadxDisplayLine } from "./format";
import { parseOffset, readFile, toPaddedHexString, walkSync } from "./util";

function r2jadxQualifiedClassName(data: JadxClass): string {
	const className = data.name || "";
	const packageName = data.package || "";
	if (packageName.length > 0 && className.indexOf(packageName + ".") === 0) {
		return className;
	}
	return packageName.length > 0 && className.length > 0 ? packageName + "." + className : className;
}

function r2jadxSearchLine(query: string, addr: Offset, scope: string, line: string): string {
	if (line.indexOf(query) === -1) {
		return "";
	}
	const offset = parseOffset(addr);
	const prefix = isNaN(offset) ? "            " : toPaddedHexString(offset, 8) + "  ";
	return prefix + scope + ": " + r2jadxDisplayLine(line).trim() + "\n";
}

function r2jadxSearchClass(data: JadxClass, query: string): string {
	let res = "";
	const className = r2jadxQualifiedClassName(data);
	if (className.length === 0) {
		return "";
	}
	if (data.declaration) {
		res += r2jadxSearchLine(query, undefined, className, data.declaration);
	}
	for (const field of data.fields || []) {
		res += r2jadxSearchLine(query, undefined, className + "." + field.name, field.declaration || field.name);
	}
	for (const method of data.methods || []) {
		const methodScope = className + "." + method.name;
		res += r2jadxSearchLine(query, method.offset, methodScope, method.declaration || method.name);
		let lastOffset = method.offset;
		for (const line of method.lines || []) {
			if (line.offset) {
				lastOffset = line.offset;
			}
			res += r2jadxSearchLine(query, lastOffset, methodScope, line.code || "");
		}
	}
	for (const klass of data["inner-classes"] || []) {
		res += r2jadxSearchClass(klass, query);
	}
	return res;
}

export function r2jadxSearch(target: string, query: string): string {
	const files = walkSync(target).filter((_) => (_.endsWith && _.endsWith(".json") && !_.endsWith("/mapping.json")));
	let res = "";
	for (const fileName of files) {
		try {
			const fileData = readFile(fileName);
			const data = JSON.parse(fileData) as JadxClass;
			res += r2jadxSearchClass(data, query);
		} catch (e) {
			console.error("" + fileName + ": " + e);
		}
	}
	return res;
}
