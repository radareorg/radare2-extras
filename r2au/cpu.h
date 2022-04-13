
enum aucpu_opcodes {
	AUCPU_OP_NOP,
	AUCPU_OP_MOV,
	AUCPU_OP_WAVE,
	AUCPU_OP_MOVREG,
	AUCPU_OP_PLAY,
	AUCPU_OP_PLAYREG,
	AUCPU_OP_WAIT,
	AUCPU_OP_JMP,
	AUCPU_OP_TRAP,
};

typedef struct {
	int regs[32];
} AuCpuState;

