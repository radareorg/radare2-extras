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

export function b64encode(data: string): string {
	return b64(data);
}

export function r2cmd(cmd: string): string {
	return r2.cmd(cmd);
}

export function r2cmdj<T = unknown>(cmd: string): T {
	return r2.cmdj<T>(cmd);
}

export function r2plugin(type: string, factory: () => R2CorePlugin): void {
	r2.plugin(type, factory);
}

export function r2unload(type: string, name: string): void {
	r2.unload(type, name);
}
