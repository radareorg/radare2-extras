public class Bincrowd.Node {
	public uint64 start;
	public uint64 end;
	public uint64 size;
	public int calls;
	public uint64 prime;
	public int order;
	public int indegree;
	public int outdegree;

	/* edges */
	public uint64 jump;
	public uint64 fail;

	// TODO: prime calculated here.. not outside.pass opstr
	public Node(uint64 addr, uint64 size, int calls, uint64 prime) {
		start = addr;
		end = addr+size;
		this.calls = calls;
		this.prime = prime;
		this.size = size;
	}
}
