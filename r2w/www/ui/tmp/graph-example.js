var g = new Graph();
 
g.addEdge($('fred'), $('wilma'));
g.addEdge($('wilma'), $('dino'));
g.addEdge($('fred'), $('barney'));
g.addEdge($('wilma'), $('barney'));
g.addEdge($('aslak'), $('fred'));
g.addEdge($('aslak'), $('dave'));
g.addEdge($('patty'), $('aslak'));
g.addEdge($('barney'), $('patty'));
 
var layouter = new Graph.Layout.Spring(g);
layouter.layout();
 
var renderer = new Graph.Renderer.Basic($('people'), g);
//renderer.draw();
