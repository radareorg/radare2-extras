load('nashorn:mozilla_compat.js')
importPackage(org.radare.r2pipe.R2Pipe);


function fun() {
var d = new Drone();
for ( var i =0;i < 4; i++) { d.cottage().right(8); }
}
/*
if (r2p) {
	r2p.quit ();
}
*/
events.on('block.BlockBreakEvent', function( evt ) { 
echo ("BROKEN BLOCK");
    var breaker = evt.player;
    //breaker.sendMessage('You broke a block');
    this.unregister();
} );
	
var r2p = new org.radare.r2pipe.R2Pipe("/bin/ls");

function r2cmd(c) {
	return r2p.cmd(c);
}
function r2(c) {
	try {
	//	var r2p = new org.radare.r2pipe.R2Pipe("/bin/ls");
		var res = r2p.cmd (c);
		var lines = res.split("\n");
		for (var line in lines) {
			echo ("; "+lines[line]);
			command ("/me "+lines[line]);
		}
//		r2p.quit ();
	} catch (e) {
		echo ("Error: "+e);
	}
}

try {
	var r2p = new org.radare.r2pipe.R2Pipe("/bin/ls");
	echo (r2p.cmd ("pd 10"));
	r2p.quit ();
} catch (e) {
	echo ("Error: "+e);
}

function d(x,y) {
        for (var a in x) {
                if (y && a.indexOf(y)==-1)
                        continue;
                print (a);
        }
}

//var b = drone.box(blocks.oak);
var users = server.getNumPlayersOnline()
if (users>0) {
	var p = server.getPlayerList()[0];
	//var p = server.getPlayer ("trufae");
	// same as "/op trufae"
	command ("/op "+p.name);
	p.op = true;
	classroom.allowScripting (true, p);
	echo("HELLO "+p.name);

} else {
	echo ("No users connected");
}
