#!/usr/bin/python3.8
from __future__ import print_function
import r2lang
import r2pipe
from graph import Graph # pip3 install graph-theory
from tempfile import NamedTemporaryFile
from random import choice
from string import ascii_uppercase
from json import dumps
from sys import argv
from os import system
import traceback

__author__ = "s0i37"
__version__ = 0.10

r2 = r2pipe.open()
MAX_DEEP = int( argv[1] ) if len(argv) > 1 else 100


def aG():
    '''Recursive graphs:
aGx[format]     references to current function (Xrefs to graph)
aGc[format]     calls of current function (Xrefs from graph)
aGC[format]     calls of all functions (Global calls graph)

Output formats:
<blank>     simple text
v           interactive ascii art
d           graphviz dot
w           webGL 3D graph
    '''
    print(aG.__doc__)

def just_print(graph):
    from colorama import Fore

    def get_node_color(sub):
        if sub.find('imp.') != -1:
            return Fore.LIGHTYELLOW_EX
        elif sub.find('sym.') != -1:
            return Fore.LIGHTGREEN_EX
        elif sub.find('sub.') != -1:
            return Fore.LIGHTMAGENTA_EX
        else:
            return Fore.LIGHTWHITE_EX

    def walk(node, deep):
        print("%s%s" % (" "*deep, get_node_color(node) + node + Fore.RESET))
        for sub_node in nodes[node]:
            walk(sub_node, deep+1)

    nodes = graph.to_dict()
    for node in graph.roots:
        walk(node, 0)

def v(graph):
    '''Interactive ascii art'''
    def walk(node):
        for sub_node in nodes[node]:
            r2.cmd("agn {sub}".format(sub=sub_node))
            r2.cmd("age {sub1} {sub2}".format(sub1=node, sub2=sub_node))
            walk(sub_node)
    r2.cmd("ag-")
    nodes = graph.to_dict()
    for node in graph.roots:
        r2.cmd("agn {sub}".format(sub=node))
        walk(node)
    r2.cmd("aggv")

def d(graph):
    '''Graphviz dot'''
    import pydot

    def get_node_color(sub):
        if sub.find('imp.') != -1:
            return 'yellow','black'
        elif sub.find('sym.') != -1:
            return 'green','black'
        elif sub.find('sub.') != -1:
            return 'purple','white'
        else:
            return 'black','white'

    known_nodes = set()
    known_edges = set()
    def walk(node):
        for sub_node in nodes[node]:
            if not graph.node(sub_node) in known_nodes:
                dot.add_node(pydot.Node(sub_node, style="filled", fillcolor=get_node_color(sub_node)[0], fontcolor=get_node_color(sub_node)[1]))
                known_nodes.add(graph.node(sub_node))
            if not (node, sub_node) in known_edges:
                dot.add_edge(pydot.Edge(node, sub_node))
                known_edges.add((node, sub_node))
            walk(sub_node)

    nodes = graph.to_dict()
    dot = pydot.Dot(graph_type='digraph')
    for node in graph.roots:
        if not graph.node(node) in known_nodes:
            dot.add_node(pydot.Node(node, style="filled", fillcolor=get_node_color(node)[0], fontcolor=get_node_color(node)[1]))
            known_nodes.add(graph.node(node))
        walk(node)

    tmpfile = NamedTemporaryFile(suffix='.dot', delete=False)
    dot.write_dot(tmpfile.name)
    system('xdot %s &' % tmpfile.name)

def w(graph):
    '''WebGL 3D graph (regards https://github.com/vasturiano/3d-force-graph)'''
    WWW='''
<head>
  <style> body { margin: 0; } </style>
  <script src="https://unpkg.com/three"></script>
  <script src="https://unpkg.com/three-spritetext"></script>
  <script src="https://unpkg.com/3d-force-graph"></script>
</head>
<body>
  <div id="3d-graph"></div>
  <script>
    var xrefs = __xrefs__
    const elem = document.getElementById('3d-graph');
    const nodes = {}
    xrefs.nodes.forEach(node => {
      nodes[node.id] = node
    })
    xrefs.links.forEach(link => {
      const a = nodes[link.source];
      const b = nodes[link.target];
      !a.neighbors && (a.neighbors = []);
      !b.neighbors && (b.neighbors = []);
      a.neighbors.push(b);
      b.neighbors.push(a);

      !a.links && (a.links = []);
      !b.links && (b.links = []);
      a.links.push(link);
      b.links.push(link);
    });

    const highlightNodes = new Set();
    const highlightLinks = new Set();
    let hoverNode = null;

    const Graph = ForceGraph3D()(elem)
      .graphData(xrefs)
      .nodeAutoColorBy('color')
      .nodeLabel(node => `${node.name}`)
      .onNodeHover(node => elem.style.cursor = node ? 'pointer' : null)
      .onNodeClick(node => alert(`function ${node.id}`))
      .nodeThreeObject(node => {
          const obj = new THREE.Mesh(
          new THREE.SphereGeometry(10),
          new THREE.MeshBasicMaterial({ depthWrite: false, transparent: true, opacity: 0 })
        );
        const sprite = new SpriteText(node.name);
        sprite.color = node.color;
        sprite.textHeight = 8;
        obj.add(sprite);
        return obj;
      })
      .onNodeDragEnd(node => {
        node.fx = node.x;
        node.fy = node.y;
        node.fz = node.z;
      })
      .nodeColor(node => highlightNodes.has(node) ? node === hoverNode ? 'rgb(255,0,0,1)' : 'rgba(255,160,0,0.8)' : 'rgba(0,255,255,0.6)')
      .linkWidth(link => highlightLinks.has(link) ? 4 : 1)
      .linkDirectionalParticles(link => highlightLinks.has(link) ? 4 : 0)
      .linkDirectionalParticleWidth(4)
      .onNodeHover(node => {
        if ((!node && !highlightNodes.size) || (node && hoverNode === node)) return;
        highlightNodes.clear();
        highlightLinks.clear();
        if (node) {
        highlightNodes.add(node);
        node.neighbors.forEach(neighbor => highlightNodes.add(neighbor));
        node.links.forEach(link => highlightLinks.add(link));
        }
        hoverNode = node || null;
        updateHighlight();
        })
      .onLinkHover(link => {
        highlightNodes.clear();
        highlightLinks.clear();
        if (link) {
          highlightLinks.add(link);
          highlightNodes.add(link.source);
          highlightNodes.add(link.target);
        }
        updateHighlight();
      });
    Graph.d3Force('charge').strength(-120);

    function updateHighlight() {
      Graph
        .nodeColor(Graph.nodeColor())
        .linkWidth(Graph.linkWidth())
        .linkDirectionalParticles(Graph.linkDirectionalParticles());
    };
  </script>
</body>
'''
    def get_color(name):
        if name == graph.origin:
            return 'red'
        elif name.find('imp.') != -1:
            return 'yellow'
        elif name.find('sym.') != -1:
            return 'green'
        elif name.find('sub.') != -1:
            return 'purple'
        else:
            return 'white'

    xrefs = {'nodes': [], 'links': []}

    known_nodes = set()
    known_edges = set()
    def walk(node):
        for sub_node in nodes[node]:
            if not graph.node(sub_node) in known_nodes:
                xrefs['nodes'].append(
                    {
                      "id": graph.node(sub_node),
                      "name": sub_node,
                      "description": sub_node,
                      "color": get_color(sub_node)
                    }
                )
                known_nodes.add(graph.node(sub_node))
            if not (graph.node(node), graph.node(sub_node)) in known_edges:
                xrefs['links'].append(
                    {
                      "source": graph.node(node),
                      "target": graph.node(sub_node),
                      "color": get_color(sub_node)
                    }
                )
                known_edges.add((graph.node(node), graph.node(sub_node)))
            walk(sub_node)

    nodes = graph.to_dict()
    for node in graph.roots:
        if not graph.node(node) in known_nodes:
            xrefs['nodes'].append(
                {
                  "id": graph.node(node),
                  "name": node,
                  "description": node,
                  "color": get_color(node)
                }
            )
            known_nodes.add(graph.node(node))
        walk(node)

    tmpfile = NamedTemporaryFile(suffix='.html', delete=False)
    with open(tmpfile.name, 'w') as o:
        o.write( WWW.replace('__xrefs__', dumps(xrefs)) )
    system('xdg-open %s &' % tmpfile.name)


def aGx(command):
    '''xrefs to'''
    graph = Graph()
    graph.roots = set()
    known_subs = set()
    def fcns_walk(fcn, calls):
        xref = None
        for xref in r2.cmdj( 'axtj {fcn}'.format(fcn=fcn) ):
            if xref["type"].lower() == "call":
                sub_fcn = xref.get("fcn_name")
                sub_fcn_addr = xref.get("fcn_addr")
                if not sub_fcn:
                    sub_fcn = r2.cmdj("fdj @ {addr}".format(addr=xref.get("from")))["name"] or hex(addr)

                if sub_fcn in calls: # anti loop
                    continue

                if not sub_fcn in graph:
                    graph.add_node(sub_fcn, sub_fcn_addr)
                
                graph.add_edge(sub_fcn, fcn)

                if sub_fcn in known_subs or len(calls) >= MAX_DEEP:
                    graph.roots.add(sub_fcn)
                    continue
                
                known_subs.add(sub_fcn)
                fcns_walk(sub_fcn, calls+[sub_fcn])

        if not xref:
            graph.roots.add(fcn)

    current_fcn = r2.cmd("afn").split('\n')[0] or r2.cmdj("fdj")["name"] or r2.cmd("s")
    current_addr = int(r2.cmd("s").split('\n')[0], 16)
    graph.origin = current_fcn
    known_subs.add(current_fcn)
    graph.add_node(current_fcn, current_addr)
    try:
        fcns_walk(current_fcn, [current_fcn])
    except Exception as e:
        print(str(e))


    if command == "aGx":
        just_print(graph)
    elif command == "aGxv":
        v(graph)
    elif command == "aGxd":
        d(graph)
    elif command == "aGxw":
        w(graph)

def aGc(command):
    '''xrefs from'''
    graph = Graph()
    graph.roots = set()
    known_subs = set()
    def fcns_walk(fcn, deep, calls):
        subs = set()
        for xref in r2.cmdj("afxj @ {fcn}".format(fcn=fcn)):
            if xref["type"] == "call":
                sub_fcn_addr = xref["to"]
                sub_fcn = r2.cmd("afn @ {addr}".format(addr=sub_fcn_addr)).split('\n')[0] or r2.cmdj("fdj @ {addr}".format(addr=sub_fcn_addr))["name"] or hex(sub_fcn_addr)
                
                if sub_fcn in calls: # anti loop
                    continue
                
                if not sub_fcn in subs:
                    subs.add(sub_fcn)
                    graph.add_node(sub_fcn, sub_fcn_addr)
                    graph.add_edge(fcn, sub_fcn)
                    if sub_fcn in known_subs or deep >= MAX_DEEP:
                        continue
                    known_subs.add(sub_fcn)
                    fcns_walk(sub_fcn, deep+1, calls+[sub_fcn])
        
    current_fcn = r2.cmd("afn").split('\n')[0] or r2.cmdj("fdj")["name"] or r2.cmd("s")
    current_addr = int(r2.cmd("s").split('\n')[0], 16)
    graph.origin = current_fcn
    graph.add_node(current_fcn, current_addr)
    graph.roots.add(current_fcn)
    try:
        fcns_walk(current_fcn, 1, [current_fcn])
    except Exception as e:
        print(str(e))


    if command == "aGc":
        just_print(graph)
    elif command == "aGcv":
        v(graph)
    elif command == "aGcd":
        d(graph)
    elif command == "aGcw":
        w(graph)

def aGC(command):
    '''global calls graph'''
    graph = Graph()
    graph.roots = set()
    def unknown():
        return "unknown_" + "".join(map(lambda i:choice(ascii_uppercase), range(5)))

    current_fcn = r2.cmd("afn").split('\n')[0] or r2.cmdj("fdj")["name"] or r2.cmd("s")
    graph.origin = current_fcn

    nodes_from = set()
    nodes_to = set()
    for xref in r2.cmdj('axj'):
        if xref['type'] == 'CALL' and xref['addr'] != 0:
            fcn_addr_from = r2.cmd('afo @%d' % xref['from'])
            fcn_from = r2.cmd('afn @%d' % xref['from']).split('\n')[0] or unknown()
            fcn_addr_to = r2.cmd('afo @%d' % xref['addr'])
            fcn_to = r2.cmd('afn @%d' % xref['addr']).split('\n')[0] or unknown()
            if fcn_addr_from and fcn_addr_to:
                if not fcn_from in graph:
                    graph.add_node(fcn_from, fcn_addr_from)
                
                if not fcn_to in graph:
                    graph.add_node(fcn_to, fcn_addr_to)
                
                graph.add_edge(fcn_from, fcn_to)
                nodes_from.add(fcn_from)
                nodes_to.add(fcn_to)

    graph.roots = nodes_from - nodes_to
    
    graph_without_loops = Graph()
    graph_without_loops.roots = graph.roots
    graph_without_loops.origin = graph.origin
    known_nodes = set()
    def check_loops(node, calls):
        graph_without_loops.add_node(node, graph.node(node))
        for sub_node in nodes[node]:
            
            if sub_node in calls: # anti loop
                continue

            graph_without_loops.add_node(sub_node, graph.node(sub_node))
            graph_without_loops.add_edge(node, sub_node)

            if sub_node in known_nodes or len(calls) >= MAX_DEEP:
                continue
            known_nodes.add(sub_node)
            check_loops(sub_node, calls+[sub_node])

    nodes = graph.to_dict()
    for node in graph.roots:
        check_loops(node, [node])

    if command == "aGC":
        just_print(graph_without_loops)
    elif command == "aGCv":
        v(graph_without_loops)
    elif command == "aGCd":
        d(graph_without_loops)
    elif command == "aGCw":
        w(graph_without_loops)

def r2xrefs(_):
    """Build the plugin"""

    def process(command):
        try:
            if not command in ("aG",
                "aGx", "aGxv", "aGxd", "aGxw",
                "aGc", "aGcv", "aGcd", "aGcw",
                "aGC", "aGCv", "aGCd", "aGCw"):
                return 0

            # Parse arguments
            if command == "aG":
                aG()
            elif command.startswith("aGx"):
                aGx(command)
            elif command.startswith("aGc"):
                aGc(command)
            elif command.startswith("aGC"):
                aGC(command)
        except Exception as e:
            print(traceback.format_exc())

        return 1

    return {"name": "r2xrefs",
            "author": "s0i37",
            "version": 0.10,
            "licence": "GPLv3",
            "desc": "radare2 cross reference visualization",
            "call": process}


# Register the plugin
if not r2lang.plugin("core", r2xrefs):
    print("An error occurred while registering r2xrefs plugin !")
