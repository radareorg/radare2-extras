#!/usr/bin/env node

/*
 * ----------------
 * Blessr2 frontend
 * ----------------
 * author: pancake@nopcode.org 
 * date: 2015-12-25
 */
'use strict';

const r2pipe = require('r2pipe');
const process = require('process');
const blessed = require('blessed');
const contrib = require('blessed-contrib');
const program = blessed.program();

/* global vars (must die at some point) */
var regs = undefined;
var offsetStack = [];

//const target = 'http://cloud.radare.org/cmd/';

function parseOptions() {
    var config = {};
    const argv = require('optimist').argv;
    if (argv.h) {
        console.log(`Usage:

  blessr2 [-HtnwdD] [file|url]

Examples:

  $ blessr2 http://cloud.radare.org/cmd/
  $ blessr2 -H /bin/ls ; blessr2 http://localhost:9090/cmd/
  $ blessr2 -d /bin/ls
  $ blessr2 -nw /etc/crontab
`);
        process.exit(0);
    }
    config.brand = 'blessr2';
    config.debug = argv.d;
    config.https = argv.H;
    config.write = argv.w;
    config.nobin = argv.n;
    config.trans = argv.t;
    config.demos = argv.D;
    config.theme = argv.r;
    config.border = 'line';
    config.target = (argv._.length > 0) ?
        argv._[0] : '/bin/ls';
    return config;
}

function initScreen() {
    var options = {
        smartCSR: true,
    };
    const isWin = /^win/.test(process.platform);
    if (isWin) {
        options.terminal = 'vt110';
        options.fullUnicode = false;
    } else {
        options.terminal = 'xterm-256color';
        options.fullUnicode = true;
    }
    var screen = blessed.screen(options);
    return screen;
}

var config = parseOptions();
var notes = undefined;
var screen = initScreen();

screen.title = '[blessr2 ' + config.target + ']';

const title = blessed.box({
    style: {
        fg: 'white',
        bg: '#000070',
    },
    top: 0,
    left: 0,
    width: '100%',
    height: 1,
});

var bgbox = blessed.box({
    style: {
        fg: 'white',
        bg: 'lightblue',
    },
    top: 1,
    width: '100%',
    height: '100%',
});
bgbox.cmd = 'izq';

function uiQuestion(title, text, cb) {
    var question = blessed.prompt({
        parent: screen,
        border: config.border,
        height: 'shrink',
        width: 'half',
        top: 'center',
        left: 'center',
        label: title,
        tags: true,
        keys: true,
        vi: true
    });
    question.input('\n  ' + text, (err, val) => {
        question.destroy();
        screen.render();
        if (!err && val) {
            cb(val);
            screen.render();
        }
    });
    return question;
}

function uiMessage(text, cb) {
    if (!text) text = '';
    var msg = blessed.message({
        parent: screen,
        border: config.border,
        height: 'shrink',
        width: 'half',
        top: 'center',
        left: 'center',
        label: ' {blue-fg}Message{/blue-fg} ',
        tags: true,
        keys: true,
        hidden: true,
        vi: true
    });
    msg.display(text, -1, cb);
}

function newBox(name, obj) {
    if (!obj) obj = {};
    if (obj.shadow === undefined) {
        obj.shadow = true;
    }
    if (obj.style === undefined) {
        obj.style = {
            fg: 'white',
            bg: 'black',
            selectedFg: 'green',
            selectedBg: 'red'
        };
        if (config.trans) {
            obj.style.transparent = true;
        }
    }
    if (obj.style.fg === undefined) obj.style.fg = 'white';
    if (obj.style.bg === undefined) obj.style.bg = 'green';
    if (obj.style.selectedFg === undefined) obj.style.selectedFg = 'green';
    if (obj.style.selectedBg === undefined) obj.style.selectedBg = 'white';
    if (obj.draggable === undefined) obj.draggable = true;
    if (obj.left === undefined) obj.left = '5%';
    if (obj.top === undefined) obj.top = 1;
    if (obj.width === undefined) obj.width = 'shrink';
    if (obj.height === undefined) obj.height = '80%';
    if (obj.border === undefined) obj.border = config.border;
    //	if (obj.scrollable === undefined)
    obj.scrollable = true;
    //	if (obj.scrollbar === undefined)
    obj.scrollbar = {
        bg: 'red',
        fg: 'white'
    };

    function isaBox(x) {
        if (x.indexOf('ag') != -1)
            return true;
        return false;
    }

    function isaText(x) {
        return (x[0] == ':');
    }
    let res = undefined;
    if (isaText(name)) {
        res = blessed.textarea(obj);
        res.select = function() { /* do nothing */ };
    } else if (isaBox(name)) {
        res = blessed.box(obj);
        res.select = function() { /* do nothing */ };
    } else {
        obj.selectedFg = 'white';
        obj.selectedBg = '#000070';
        res = blessed.list(obj);
        res.setContent = function(x) {
            if (typeof x === 'string') {
                res.setItems(x.split('\n'));
            }
        }
    }
    res.cmd = name;
    return res;
}

const box = newBox('pd 200', {
    width: 90,
    height: 20
});
const gbox = newBox('af;agf', {
    width: 80,
    height: 20
});
const xbox = newBox('px 2048', {
    width: 80,
    height: 20
});

title.setText(config.brand + ' ' + config.target + ' @ entry0');

function walkInto(r2, foo) {
    gotoOffset(r2, foo, screen.focused);
    r2.cmd("e asm.cmtcol=55");
    r2.cmd('e asm.bytes=false');
    r2.cmd('e scr.html=false');
    r2.cmd('e scr.color=true');
    r2.cmd('e anal.hasnext=true');
    if (!config.debug && !config.nobin) {
        r2.cmd('om-*');
        r2.cmd('e io.sectonly=true');
    }
    //r2.cmd("e asm.emu=true");
    box.setText('Loading...\n');
    screen.render();
    [bgbox, box, xbox, gbox].forEach((b) => {
        r2.cmd(b.cmd, (err, txt) => {
            b.setContent(txt);
            screen.render();
        });
    });
}

function demoStuff() {
    var donut = contrib.donut({
        label: 'Test',
        radius: 8,
        arcWidth: 3,
        spacing: 2,
        yPadding: 2,
        width: '70%',
        height: '50%',
        left: 0,
        top: 0,
        draggable: true,
        border: config.border,
        data: [{
            percent: 60,
            label: '.text',
            color: 'green',
        }, {
            percent: 30,
            label: '.data',
            color: 'red',
        }, {
            percent: 10,
            label: '.header',
            color: 'yellow',
        }]
    });
    screen.append(donut);
    var map = contrib.map({
        label: 'World Map',
        border: config.border,
        width: '80%',
        height: '60%',
        draggable: true
    });
    //map.addMarker({"lon" : "-79.0000", "lat" : "37.5000", color: "red", char: "X" })
    screen.append(map);
    var tree = contrib.tree({
        fg: 'orange',
        label: 'Fruit Tree',
        border: config.border,
        width: '50%',
        height: '30%',
        draggable: true
    });

    //allow control the table with the keyboard
    tree.focus();

    tree.on('select', function(node) {
        if (node.myCustomProperty) {
            console.log(node.myCustomProperty);
        }
        console.log(node.name);
    });
    screen.append(tree);

    // you can specify a name property at root level to display root
    tree.setData({
        extended: true,
        children: {
            'Fruit': {
                children: {
                    'Banana': {},
                    'Apple': {},
                    'Cherry': {},
                    'Exotics': {
                        children: {
                            'Mango': {},
                            'Papaya': {},
                            'Kiwi': {
                                name: 'Kiwi (not the bird!)',
                                myCustomProperty: 'hairy fruit'
                            }
                        }
                    },
                    'Pear': {}
                }
            },
            'Vegetables': {
                children: {
                    'Peas': {},
                    'Lettuce': {},
                    'Pepper': {}
                }
            }
        }
    });
}


box.focus();

function layout(style) {
    const box = screen.focused;
    if (!box) return;

    for (var x in style) {
        box[x] = style[x];
    }
    screen.render();
}

function uiNewFrame(r2, cmd, opts) {
    const box = newBox(cmd, opts || {
        width: 80,
        height: '60%'
    });
    box.setContent('Loading...');
    if (cmd && box.cmd) {
        refreshBox (r2, box);
    }
    box.focus();
    screen.append(box);
    screen.render();
    return box;
}

function refreshBox(r2, box) {
    if (!box || !box.cmd) {
        return;
    }
    r2.cmd(box.cmd, (err, txt) => {
        box.setContent(txt);
        screen.render();
    });
}

function refreshCurrentBox(r2) {
    return refreshBox(r2, screen.focused);
}

function refreshAllBoxes(r2, box) {
    for (let box of screen.children) {
        refreshBox(r2, box);
    }
}

function keysHelp() {
    return `blessr2 keybindings
===================
/  - search
=  - start webserver
:  - run command in background console
;  - enter comment
!  - run command in new frame
?  - show this help
w  - close current window
a  - show basic block graph
A  - analyze function
d  - open disasm view
D  - open pds string disasm view
e  - eval configuration var
g  - goto offset/flag
G  - goto offset/flag in new frame
i  - show file info
I  - show functions and symbols list
jk - scroll few lines down/up
JK - scroll page down/up
hl - move left/right
HL - move up/down
Q  - quit blessr2
r  - show registers
R  - refresh frame
s  - step into
t  - text notes window. press 'e' to edit and then 'esc'
x  - open hexdump view
X  - open pxa hexdump
w  - close window (same as 'q')
z  - show strings in frame
[] - horizontal resize of frame
vV - vertical resize of frame
0-9  tile for different layouts
enter - follow jump/call/ref
space - goto address in selected line
o - open file dialog (WIP)`;
}

function findLastOffset(b) {
    if (!b || b.selected < 0) {
        return -1;
    }
    let idx = b.selected;
    while (idx >= 0) {
        const item = b.items[idx];
        if (!item) break;
        const line = '' + item.content;
        const addr = line.indexOf('0x');
        if (addr != -1) {
            return parseInt(line.substring(addr), 16);
        }
        idx--;
    }
    return -1;
}

function scrollBox(r2, b, delta, hardscroll) {
    if (!b || !b.scroll) return;
    b.scroll(delta);
    b.select(b.selected + delta);
    if (b.cmd && hardscroll) {
        if (delta < 0) {
            if (b.getScroll() < 1) {
                gotoOffset(r2, '$$-64', b);
            }
        } else {
            if (b.items && 2 + b.getScroll() >= b.items.length) {
                const at = findLastOffset(b);
                if (at != -1) gotoOffset(r2, at, b);
            }
        }
    }
    screen.render();
}

function popOffset(r2, box) {
    if (offsetStack.length > 0) {
        let off = offsetStack[offsetStack.length - 1];
        gotoOffset(r2, off, box);
        offsetStack = offsetStack.slice(0, offsetStack.length - 2);
        if (!offsetStack)
            offsetStack = [];
    }
}

function seekLine(r2, box) {
    if (!r2 || !box) return;
    const item = box.items[box.selected]
    if (!item) return;
    const line = '' + item.content;
    const addr = line.indexOf('0x');
    if (addr != -1) {
        const at = parseInt(line.substring(addr), 16);
        gotoOffset(r2, at, box);
    }
}

function nextWindow() {
    const curbox = screen.focused;
    for (let box of screen.children) {
        if (box && box !== bgbox && box !== title && box !== curbox) {
            box.setFront();
            box.focus();
            screen.render();
            break;
        }
    }
}

function prevWindow() {
    const curbox = screen.focused;
    let rch = screen.children;
    let nextIsGood = false;
    for (let box of rch) {
        if (nextIsGood) {
            box.setFront();
            box.focus();
            nextIsGood = false;
            break;
        }
        if (box && box !== bgbox && box !== title && box !== curbox) {
            nextIsGood = true;
        }
    }
    if (nextIsGood) {
        for (let box of rch) {
            if (box && box !== bgbox && box !== title && box !== curbox) {
                continue;
            }
            box.setFront();
            box.focus();
            break;
        }
    }
    screen.render();
}

function seekToLine(r2, box) {
    return activateLine(r2, box);
}

function activateLine(r2, box) {
    if (box) {
        const item = box.items ? box.items[box.selected] : undefined;
        if (!item) return;
        const line = '' + item.content;
        const addr = line.indexOf('0x');
        if (addr != -1) {
            const at = parseInt(line.substring(addr), 16);
            const isCode = true; //item.cmd && item.cmd.indexOf && item.cmd.indexOf('pd') != -1;
            if (isCode) {
                r2.cmd('e scr.color=0;ao@' + at + ';e scr.color=1', (err, txt) => {
                    let obj = {}
                    txt.split('\n').forEach((x) => {
                        const ab = x.split(': ');
                        if (ab.length > 1) {
                            obj[ab[0]] = ab[1];
                        }
                    });
                    if (obj.jump && obj.jump != -1) {
                        gotoOffset(r2, obj.jump, box);
                    } else if (obj.ptr && obj.ptr != -1) {
                        gotoOffset(r2, obj.ptr, box);
                    }
                });
            } else {
                gotoOffset(r2, at, box);
            }
        }
    }
}

function stepInto(r2, box) {
    r2.cmd(config.debug ? 'ds;dr*' : 'aes;.aer*', (err, cmds) => {
        r2.cmd(cmds.split('\n').join(';'));
        if (!box) box = bgbox;
        r2.cmd(box.cmd, (err, txt) => {
            box.setContent(txt);
            screen.render();
            r2.cmd(bgbox.cmd, (err, txt) => {
                bgbox.setContent(txt);
                screen.render();
refreshAllBoxes(r2);
            });
/*
            if (regs !== undefined) {
                r2.cmd(regs.cmd, (txt) => {
                    regs.setContent(txt);
                    screen.render();
                });
            }
*/
        });
    });
    screen.render();
}

function addComment(r2, box) {
    if (box) {
        uiQuestion('Comment', 'Enter your notes', (txt) => {
            const item = box.items[box.selected]
            if (!item) return;
            const line = '' + item.content;
            const addr = line.indexOf('0x');
            if (addr != -1) {
                const at = parseInt(line.substring(addr), 16);
                const cc = (txt === '-') ? 'CC' : 'CC ';
                r2.cmd(cc + txt + '@' + at, () => {
                    refreshCurrentBox(r2);
                });
            } else {
                uiMessage('Cannot determine offset');
            }
        });
    }
}

function gotoOffset(r2, val, box, nostack) {
    val = '' + val;
    if (val === '') {
        return;
    }
    if (offsetStack) {
        offsetStack.push(val);
    }
    r2.cmd('s ' + val + ';' + box.cmd, (err, txt) => {
        box.setContent(txt);
        box.setScroll(0);
        box.selected = 0;
        screen.render();
    });
}

function handleKeys(r2) {
    [
        ['S-q', (ch, key) => {
            program.clear();
            program.disableMouse();
            program.showCursor();
            program.normalBuffer();
            screen.destroy();
            return process.exit(0);
        }],
        ['z', () => {
            uiNewFrame(r2, 'izq');
        }],
        ['i', () => {
            uiNewFrame(r2, 'afi;?e;i');
        }],
        ['S-i', () => {
            uiNewFrame(r2, 'afl;isq');
        }],
        ['r', () => {
            regs = uiNewFrame(r2, 'aer=');
        }],
        ['x', () => {
            uiNewFrame(r2, 'px 2048');
        }],
        ['S-x', () => {
            uiNewFrame(r2, 'pxa 2048');
        }],
        ['d', () => {
            uiNewFrame(r2, 'pdf');
        }],
        ['S-d', () => {
            uiNewFrame(r2, 'af;pdsf');
        }],
        ['a', () => {
            uiNewFrame(r2, 'af;agf');
        }],
        ['n', () => {
            nextWindow();
        }],
        ['tab', () => {
            nextWindow();
        }],
        ['S-n', () => {
            prevWindow();
        }],
        ['s', () => {
            stepInto(r2, screen.focused);
        }],
        [';', () => {
            addComment(r2, screen.focused);
        }],
        ['/', () => {
            uiQuestion('String', 'String to search', (val) => {
                let box = uiNewFrame(r2, val);
                box.setContent('Loading...');
                r2.cmd('/ ' + val, (err, txt) => {
                    box.setContent(txt);
                    screen.render();
                    r2.cmd('fs searches;f', (err, txt) => {
                        box.setContent('Search for: "' + val + '":\n\n' + txt);
                        screen.render();
                    });
                });
            });

        }],
        [
            ['q', 'w'], () => {
                const box = screen.focused;
                if (!box || !box.hide) return;
                if (box === bgbox || box === title) return;
                box.hide();
                box.destroy();
                screen.render();
            }
        ],
        ['S-a', () => {
            r2.cmd('af', () => {
                let box = screen.focused;
                r2.cmd(box.cmd, (err, txt) => {
                    box.setContent(txt);
                    screen.render();
                });
            });
        }],
        [':', () => {
            uiQuestion('Input', 'Command to run', (val) => {
                r2.cmd(bgbox.cmd = val, (err, txt) => {
                    bgbox.setContent(txt);
                    screen.render();
                });
            });
        }],
        ['!', () => {
            uiQuestion('Input', 'Command to run', (val) => {
                r2.cmd(val, (err, txt) => {
                    uiNewFrame(r2, val);
                    const box = screen.focused;
                    if (box) {
                        r2.cmd(box.cmd, (err, x) => {
                            box.setContent(x);
                        });
                    }
                });
            });

        }],
        ['=', () => {
            function httpsPopup() {
                const already = config.https ? ' is Already ' : ' ';
                uiMessage('\n Background r2 Webserver' + already + 'Running\n\n' +
                    '  $ blessr2 http://localhost:9090/cmd/\n');
            }
            if (config.https) {
                httpsPopup();
            } else {
                r2.cmd('=h&', () => {
                    httpsPopup();
                    config.https = true;
                });
            }
        }],
        ['?', () => {
            const box = uiNewFrame(r2, '');
            box.setContent(keysHelp());
            screen.render();
        }],
        ['S-r', () => {
            refreshAllBoxes(r2);
        }],
        ['S-e', () => {
            let ef = uiNewFrame(r2, 'e??', {
                width: '100%',
                height: '100%',
                left: 0,
                top: 0
            });
        }],
        ['e', () => {
            const box = screen.focused;
            if (notes !== undefined && box == notes) {
                notes.readEditor(function() {});
                screen.render();
            } else {
                uiQuestion('Eval Config', 'key=value', (val) => {
                    r2.cmd('e ' + val, (err, txt) => {
                        screen.render();
                    });
                });
            }
        }],
        ['u', () => {
            const b = screen.focused;
            if (b) popOffset(r2, b);
        }],
        ['g', () => {
            uiQuestion('Offset', 'Where to go?', (val) => {
                gotoOffset(r2, val, screen.focused);
            });
        }],
        ['S-g', () => {
            const obox = screen.focused;
            if (!obox) return;
            const box = newBox(obox.cmd, {
                width: 'shrink',
                height: 'shrink'
            });
            screen.append(box);
            uiQuestion('Offset', 'Where to go?', (val) => {
                r2.cmd('s ' + val + ';' + box.cmd, (err, txt) => {
                    box.setContent(txt);
                    screen.render();
                });
            });
        }],
        ['o', () => {
            const fm = blessed.FileManager({
                parent: screen,
                border: config.border,
                style: {
                    bg: 'blue',
                    fg: 'white'
                },
                left: 'center',
                top: 'center',
                height: '40%',
                width: '40%'
            });
            fm.refresh();
            fm.focus();
            screen.append(fm);
            screen.render();
        }],
        ['S-r', () => {
            refreshCurrentBox(r2);
        }],
        [
            ['j', 'down'], () => {
                scrollBox(r2, screen.focused, 1, false);
            }
        ],
        [
            ['k', 'up'], () => {
                scrollBox(r2, screen.focused, -1, false);
            }
        ],
        [
            ['S-j', 'pagedown'], () => {
                const box = screen.focused;
                if (box) scrollBox(r2, box, box.height / 2, true);
            }
        ],
        [
            ['S-k', 'pageup'], () => {
                const box = screen.focused;
                if (box) scrollBox(r2, box, -box.height / 2, true);
            }
        ],
        ['t', () => {
            if (notes === undefined) {
                notes = newBox(':', {
                    width: '70%',
                    height: '40%'
                });
                screen.append(notes);
                notes.focus();
                screen.render();
            }

        }],
        [
            'space', () => {
                seekToLine(r2, screen.focused);
            }
        ],
        [
            'enter', () => {
                activateLine(r2, screen.focused);
            }
        ]
    ].forEach((k) => {
        screen.key(k[0], k[1]);
    });

    /* layouts */
    screen.key('0', () => {
        layout({
            left: 0,
            top: 1,
            width: '100%',
            height: '99%'
        });
    });
    screen.key('1', () => {
        layout({
            left: 0,
            top: 1,
            width: '70%',
            height: '99%'
        });
    });
    screen.key('2', () => {
        layout({
            left: '70%',
            top: 1,
            width: '30%',
            height: '99%'
        });
    });
    screen.key('3', () => {
        layout({
            left: '0',
            top: 1,
            width: '100%',
            height: '70%'
        });
    });
    screen.key('4', () => {
        layout({
            left: '0',
            top: '72%',
            width: '100%',
            height: '30%'
        });
    });
    screen.key('5', () => {
        layout({
            left: 'center',
            top: 'center',
            width: '80%',
            height: '70%'
        });
    });
    screen.key('6', () => {
        layout({
            left: 'center',
            top: 'center',
            width: '60%',
            height: '40%'
        });
    });
    screen.key('7', () => {
        layout({
            left: 'center',
            top: 'center',
            width: '40%',
            height: '50%'
        });
    });

    screen.key('8', () => {
        layout({
            left: 'center',
            top: 'center',
            width: 80,
            height: '20%'
        });
    });
    screen.key('9', () => {
        layout({
            left: 'center',
            top: 'center',
            width: '70%',
            height: '50%'
        });
    });

    /* window position and size */
    screen.key('[', function() {
        const box = screen.focused;
        if (box) {
            const pc = ('' + box.width).indexOf('%');
            if (pc != -1) {
                const n = box.width.substring(0, pc);
                box.width = (n - 10) + '%';
            } else {
                box.width -= 2;
                if (box.width < 2)
                    box.width = 2;
            }
            screen.render();
        }
    });
    screen.key(']', function() {
        const box = screen.focused;
        if (box) {
            const pc = ('' + box.width).indexOf('%');
            if (pc != -1) {
                const n = box.width.substring(0, pc);
                box.width = (n + 10) + '%';
            } else {
                box.width += 2;
            }
            screen.render();
        }
    });
    screen.key('h', function() {
        const box = screen.focused;
        if (box) {
            const pc = ('' + box.left).indexOf('%');
            if (pc != -1) {
                const n = box.left.substring(0, pc);
                box.left = (n - 10) + '%';
            } else {
                box.left -= 1;
            }
            screen.render();
        }
    });
    screen.key('l', function() {
        const box = screen.focused;
        if (box) {
            const pc = ('' + box.left).indexOf('%');
            if (pc != -1) {
                const n = box.left.substring(0, pc);
                box.left = (n + 10) + '%';
            } else {
                box.left += 1;
            }
            screen.render();
        }
    });
    screen.key('S-h', function() {
        const box = screen.focused;
        if (box) {
            const pc = ('' + box.top).indexOf('%');
            if (pc != -1) {
                const n = box.top.substring(0, pc);
                box.top = (n - 10) + '%';
            } else {
                box.top -= 1;
            }
            screen.render();
        }
    });
    screen.key('S-l', function() {
        const box = screen.focused;
        if (box) {
            const pc = ('' + box.top).indexOf('%');
            if (pc != -1) {
                const n = box.top.substring(0, pc);
                box.top = (n + 10) + '%';
            } else {
                box.top += 1;
            }
            screen.render();
        }
    });
    screen.key('v', function() {
        const box = screen.focused;
        if (box) {
            const pc = ('' + box.height).indexOf('%');
            if (pc != -1) {
                const n = box.height.substring(0, pc);
                box.height = (n + 10) + '%';
            } else {
                box.height += 1;
            }
            screen.render();
        }
    });
    screen.key('S-v', function() {
        const box = screen.focused;
        if (box) {
            const pc = ('' + box.height).indexOf('%');
            if (pc != -1) {
                const n = box.height.substring(0, pc);
                box.height = (n + 10) + '%';
            } else {
                box.height -= 1;
                if (box.height < 2)
                    box.height = 1;
            }
            screen.render();
        }
    });
}

function handleMouse(r2) {
    /* handle mouse */
    program.on('mouse', function(data) {
        const b = screen.focused;
        if (!b || !b.scroll) return;
        switch (data.action) {
            case 'wheelup':
                scrollBox(r2, b, -4, true);
                break;
            case 'wheeldown':
                scrollBox(r2, b, 4, true);
                break;
        }
    });
}

function main(err, r2) {
  if (err) {
    throw err;
  }
  config.theme && r2.cmd("ecr");
  handleKeys(r2);
  handleMouse(r2);
  walkInto(r2, 'entry0');
}

/* main */

program.enableMouse();
program.hideCursor();

screen.append(bgbox);
screen.append(title);
screen.append(xbox);
screen.append(box);
screen.render();

if (config.demos) {
    demoStuff();
}
if (+process.env.R2PIPE_IN) {
    r2pipe.lpipe(main);
} else {
    if (config.target.indexOf('http') == 0) {
        r2pipe.connect(config.target, main);
    } else {
        if (config.nobin) r2pipe.options.push('-n');
        if (config.debug) r2pipe.options.push('-d');
        if (config.write) r2pipe.options.push('-w');
        r2pipe.open(config.target, main);
    }
}
