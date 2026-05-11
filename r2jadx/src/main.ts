import type { R2FunctionInfo, R2Info, R2JadxContext } from "./types";
import {
	R2JADX_HELP,
	r2jadxEvalConfig,
	r2jadxIsHelpArg,
	r2jadxListConfig,
	r2jadxWithAddr,
} from "./config";
import { r2cmd, r2cmdj, r2plugin, r2unload } from "./r2api";
import { r2jadxDecompile, r2jadxEnsureDecompiled } from "./jadx";
import { r2jadxFormatOutput } from "./format";
import { dex2path, nospace, pathJoin, runCmd } from "./util";
import { r2jadxSearch } from "./search";

function r2jadxClearCache(target: string): void {
	runCmd([ "rm", "-rf", nospace(dex2path(target)) ]);
}

export function r2jadxMain(argv: string[]): string | undefined {
	const firstArg = argv[0] || "";
	if (r2jadxIsHelpArg(firstArg)) {
		console.error(R2JADX_HELP);
		return undefined;
	}
	if (firstArg === "-e") {
		const configArg = argv.slice(1).join(" ").trim();
		if (configArg.length > 0) {
			r2jadxEvalConfig(configArg);
		} else {
			r2jadxListConfig();
		}
		return undefined;
	}
	try {
		r2cmd("af");
		const info = r2cmdj<R2Info>("ij");
		const fileName = info.core.file;
		const fcn = r2cmdj<R2FunctionInfo[]>("afij");
		if (!fileName.endsWith(".dex")) {
			throw new Error("Sorry, this is not a DEX file");
		}
		if (!fileName) {
			throw new Error("Cannot find function");
		}
		const currentFunction = (fcn && fcn.length > 0) ? fcn[0] : undefined;
		const context: R2JadxContext = {
			offset: currentFunction ? currentFunction.offset : 0,
			functionName: currentFunction && currentFunction.name ? currentFunction.name : "",
			fileName: currentFunction && currentFunction.file ? currentFunction.file : "",
		};
		let mode = "all";
		if (firstArg[0] === "-") {
			mode = firstArg.substring(1);
		}
		if (mode === "C") {
			r2jadxClearCache(fileName);
			return undefined;
		}
		const searchText = argv.slice(1).join(" ").trim();
		if (mode === "s") {
			if (searchText.length === 0) {
				console.error("Usage: r2jadx -s text");
				return undefined;
			}
			const res = r2jadxSearch(pathJoin(r2jadxEnsureDecompiled(fileName), "hl"), searchText);
			console.log(r2jadxFormatOutput(res, mode));
			return res;
		}
		const res = r2jadxDecompile(fileName, mode, context);
		if (mode.startsWith("r")) {
			for (const line of res.split("\n")) {
				if (line.trim().length > 0) {
					r2cmd(line);
				}
			}
		} else {
			console.log(r2jadxFormatOutput(res, mode));
		}
		return res;
	} catch (e) {
		const error = e as { output?: { toString: () => string } };
		console.error("Oops", e, error.output ? error.output.toString() : "");
		throw e;
	}
}

function r2jadxPdCommand(cmd: string): void {
	const flags = cmd.substring(4).trim();
	if (flags.indexOf("?") !== -1) {
		console.error(R2JADX_HELP);
		return;
	}
	if (flags.indexOf("*") !== -1) {
		r2jadxMain([ "-r2" ]);
		return;
	}
	if (flags.indexOf("=") !== -1 || flags.indexOf("a") !== -1) {
		r2jadxMain([ "-a" ]);
		return;
	}
	r2jadxWithAddr(flags.indexOf("o") !== -1, () => r2jadxMain([ "-f" ]));
}

export function r2jadxBegin(): void {
	r2unload("core", "r2jadx");
	r2plugin("core", function() {
		function coreCall(cmd: string): boolean {
			if (cmd.startsWith("r2jadx")) {
				const argv = cmd.substring(6).trim().split(" ");
				r2jadxMain(argv);
				return true;
			}
			if (cmd.startsWith("pd:j")) {
				r2jadxPdCommand(cmd);
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
