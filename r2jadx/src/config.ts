export interface R2JadxConfig {
	addr: boolean;
	color: boolean;
	indent: boolean;
}

interface R2JadxConfigHandler {
	get: () => string;
	set: (value: string) => boolean;
}

export const r2jadxConfig: R2JadxConfig = {
	addr: false,
	color: true,
	indent: true,
};

export const R2JADX_HELP = `Usage: r2jadx [-mode]
Setup: e cmd.pdc=pd:j
Alias: pd:j, pd:jo
 -r   = import low level decompilation as comments
 -r2  = import high level decompilation as comments
 -e   = display or change plugin config
 -C   = clear jadx cache directory for the current DEX
----------------------------------
 -cn  = show current classname
 -a   = show decompilation of all the classes
 -c   = decompile current class
 -f   = decompile current function
 -s   = search decompiled code for text
 -ahl = all high level decompilation
 -all = all low level decompilation
 -hl  = high level decompilation
 -ll  = low level decompilation`;

function parseBoolean(value: string): boolean | undefined {
	switch (value.toLowerCase()) {
	case "1":
	case "true":
	case "yes":
	case "on":
		return true;
	case "0":
	case "false":
	case "no":
	case "off":
		return false;
	}
	return undefined;
}

function boolConfigHandler(key: keyof R2JadxConfig): R2JadxConfigHandler {
	return {
		get: () => String(r2jadxConfig[key]),
		set: (value: string): boolean => {
			const parsed = parseBoolean(value);
			if (parsed === undefined) {
				console.error("Invalid boolean value: " + value);
				return false;
			}
			r2jadxConfig[key] = parsed;
			return true;
		}
	};
}

const r2jadxConfigHandlers: Record<string, R2JadxConfigHandler> = {
	"addr": boolConfigHandler("addr"),
	"color": boolConfigHandler("color"),
	"indent": boolConfigHandler("indent"),
};

export function r2jadxIsHelpArg(arg: string): boolean {
	switch (arg) {
	case "":
	case "?":
	case "h":
	case "help":
	case "-h":
	case "-help":
	case "--help":
		return true;
	}
	return false;
}

export function r2jadxListConfig(): void {
	for (const key of Object.keys(r2jadxConfigHandlers)) {
		console.log("r2jadx -e " + key + "=" + r2jadxConfigHandlers[key].get());
	}
}

export function r2jadxEvalConfig(arg: string): void {
	const eqIndex = arg.indexOf("=");
	const key = eqIndex === -1 ? arg : arg.slice(0, eqIndex);
	const value = eqIndex === -1 ? undefined : arg.slice(eqIndex + 1);
	const handler = r2jadxConfigHandlers[key];
	if (!handler) {
		console.error("Unknown config key: " + key);
		return;
	}
	if (value === "?") {
		console.log("true\nfalse");
		return;
	}
	if (value === undefined) {
		console.log(handler.get());
		return;
	}
	handler.set(value);
}

export function r2jadxWithAddr(addr: boolean, cb: () => string | undefined): string | undefined {
	const savedAddr = r2jadxConfig.addr;
	r2jadxConfig.addr = addr;
	try {
		return cb();
	} finally {
		r2jadxConfig.addr = savedAddr;
	}
}
