
public class Bincrowd.Layer {
	public List<Bincrowd.Node> nodes;
	public Layer() { 
		nodes = new List<Bincrowd.Node>();
	}
}

public class Bincrowd.Function {
	public string name;
	public string description;
	public List<Node> nodes;
	public List<Edge> edges;
	public List<Layer> layers;
	public List<Argument> args;
	public List<Variable> vars;
	public uint64 prime;
	public int indegree;
	public int outdegree;
	public uint64 base_address;
	public uint64 rva;

	public Function() {
		name = "";
		description = "";
		nodes = new List<Bincrowd.Node>();
		layers = new List<Bincrowd.Layer>();
		edges = new List<Bincrowd.Edge>();
		indegree = outdegree = 0;
	}

	private Bincrowd.Node? get_node(List<Bincrowd.Node> list, uint64 addr) {
		foreach (var n in list) {
			if (n.start == addr)
				return n;
		}
		return null;
	}

	public void update_edges() {
		// calculate inoutdegrees
		foreach (var n in nodes) {
			foreach (var m in nodes) {
				if (m.jump == n.start || m.fail == n.start)
					n.indegree++;
				if (n.jump == m.start || n.fail == m.start)
					n.outdegree++;
			}
			n.outdegree = 0;
			if (n.jump != uint64.MAX) n.outdegree++;
			if (n.fail != uint64.MAX) n.outdegree++;
		}

		edges = new List<Bincrowd.Edge>();
		indegree = outdegree = 0;
		foreach (var a in nodes) {
			if (a.jump != uint64.MAX) {
				var node = get_node (nodes, a.jump);
				if (node != null)
					edges.append (new Edge (a, node));
			}
			if (a.fail != uint64.MAX) {
				var node = get_node (nodes, a.fail);
				if (node != null)
					edges.append (new Edge (a, node));
			}
		}
	}

	public void update() {
		prime = BinCrowd.prime_product (this);
		layers = new List<Bincrowd.Layer>();
		var nds = nodes.copy ();

		/* root node */
		Node ? n = null;
		var lastlayer = new Layer ();
		foreach (var b in nds) {
			if (n == null)
				n = b;
			else if (b.start < n.start)
				n = b;
		}
		if (n != null) {
			n.order = 0;
			lastlayer.nodes.append (n);
			nds.remove (n);
		}
		layers.append (lastlayer);

		int nlayer = 0;
		/* walk children layers */
		while (nds.length () > 0) {
			int count = 0;
			var newlayer = new Layer ();
			foreach (var n in lastlayer.nodes) {
				foreach (var m in nds) {
					if (n.jump == m.start || n.fail == m.start) {
						m.order = nlayer;
						newlayer.nodes.append (m);
						nds.remove (m);
						count++;
					}
				}
			}
			if (count == 0 && nds.length ()>0) {
				warning ("invalid graph");
				break;
			} else {
				layers.append (newlayer);
				lastlayer = newlayer;
				nlayer++;
			}
		}

		print ("Function layer depth: %u\n", layers.length ());
		update_edges ();
	}
}
