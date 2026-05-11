import { r2jadxConfig } from "./config";
import { r2cmd } from "./r2api";
import { toPaddedHexString } from "./util";

export function r2jadxDisplayLine(line: string): string {
	line = line.replaceAll("\t", "  ");
	line = line.replaceAll("\r", "");
	line = line.replaceAll("\n", "");
	return r2jadxConfig.indent ? line : line.trim();
}

export function r2jadxDisplayPrefix(addr: number): string {
	return r2jadxConfig.addr ? toPaddedHexString(addr, 8) + "  " : "";
}

export function r2jadxDisplayUnknownPrefix(): string {
	return r2jadxConfig.addr ? " ".repeat(12) : "";
}

export function r2jadxDisplayAddressLine(addr: number | undefined, line: string): string {
	const prefix = addr === undefined ? r2jadxDisplayUnknownPrefix() : r2jadxDisplayPrefix(addr);
	return prefix + line;
}

export function r2jadxIndentLine(line: string, level: number): string {
	const code = r2jadxDisplayLine(line);
	if (code.length === 0) {
		return "";
	}
	return " ".repeat(level * 4) + code;
}

function r2jadxEscapeQuotedArg(value: string): string {
	return value.replace(/\\/g, "\\\\").replace(/"/g, "\\\"");
}

function r2jadxColorCode(line: string): string {
	const leadingMatch = line.match(/^\s*/);
	const leading = leadingMatch ? leadingMatch[0] : "";
	const code = line.substring(leading.length);
	if (code.length === 0) {
		return line;
	}
	const colored = r2cmd("?e \"" + r2jadxEscapeQuotedArg(code) + "\"~:))");
	return leading + colored.replace(/\n$/, "");
}

function r2jadxColorLine(line: string): string {
	const addressMatch = line.match(/^(0x[0-9a-fA-F]+\s+)(.*)$/);
	if (addressMatch) {
		return addressMatch[1] + r2jadxColorCode(addressMatch[2]);
	}
	return r2jadxColorCode(line);
}

function r2jadxShouldColor(mode: string): boolean {
	switch (mode) {
	case "a":
	case "cat":
	case "d":
	case "dc":
	case "all":
	case "ahl":
	case "s":
		return r2jadxConfig.color;
	}
	return false;
}

export function r2jadxFormatOutput(output: string, mode: string): string {
	if (!r2jadxShouldColor(mode)) {
		return output;
	}
	return output.split("\n").map(r2jadxColorLine).join("\n");
}
