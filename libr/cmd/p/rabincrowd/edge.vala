using Bincrowd;

namespace Bincrowd {

public class Edge {
	/* find better names... */
	public int indegree_source;
	public int outdegree_source;
	public int indegree_target;
	public int outdegree_target;
	public int topological_order_source;
	public int topological_order_target;
	public uint64 source_prime;
	public int source_call_num;
	public uint64 target_prime;
	public int target_call_num;

	public Bincrowd.Node source;
	public Bincrowd.Node target;

	/* TODO: move this stuff into function.add_edge() */
	public Edge(Bincrowd.Node a, Bincrowd.Node b) {
		this.source = a;
		this.target = b;

		/*
		topological_order_source = a.order; 
		topological_order_target = b.order;

		source_prime = a.prime;
		target_prime = b.prime;
		source_call_num = a.calls;
		target_call_num = b.calls;
		*/
	}
}
}
