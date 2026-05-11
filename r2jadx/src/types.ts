export type Offset = string | number | undefined;

export interface JadxLine {
	offset?: Offset;
	code: string;
}

export interface JadxMethod {
	offset: Offset;
	name: string;
	declaration?: string;
	lines?: JadxLine[];
}

export interface JadxField {
	name: string;
	declaration?: string;
}

export interface JadxClass {
	name?: string;
	package?: string;
	declaration?: string;
	fields?: JadxField[];
	source?: string;
	methods?: JadxMethod[];
	"inner-classes"?: JadxClass[];
}

export interface R2Info {
	core: {
		file: string;
	};
}

export interface R2FunctionInfo {
	offset: number;
	name?: string;
	file?: string;
}

export interface R2JadxContext {
	offset: number;
	functionName: string;
	fileName: string;
}
