import type { Offset } from "./types";
import { r2cmd, r2fdump, r2fload } from "./r2api";

export function nospace(d: string): string {
	if (d.indexOf(" ") !== -1) {
		throw new Error("Path cant contain spaces");
	}
	return d;
}

export function directoryExists(d: string): boolean {
	const directory = r2cmd("'!!test -d " + nospace(d) + " && echo exists").trim();
	return directory === "exists";
}

export function fileExists(f: string): boolean {
	const file = r2cmd("'!!test -f " + nospace(f) + " && echo exists").trim();
	return file === "exists";
}

export function runCmd(c: string[]): void {
	const cmdline = c.join(" ");
	console.log(cmdline);
	r2cmd("'!" + cmdline);
}

export function parseOffset(value: Offset): number {
	return parseInt(String(value));
}

export function toPaddedHexString(num: Offset, len: number): string {
	const str = parseOffset(num).toString(16);
	return "0x" + ("0".repeat(len - str.length) + str);
}

export function pathJoin(...args: string[]): string {
	return args.join("/");
}

export function readFile(f: string): string {
	return r2fload(nospace(f));
}

export function writeFile(f: string, data: string): void {
	if (!r2fdump(data, nospace(f))) {
		throw new Error("Cannot write file: " + f);
	}
}

export function dex2path(target: string): string {
	return target + ".d";
}

export function walkSync(dir: string): string[] {
	const files = r2cmd("!!find " + dir + " -type f").trim();
	return files.length > 0 ? files.split(/\n/g) : [];
}
