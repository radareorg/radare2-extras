'use strict';

const colors = require('colors');
const sprintf = require('sprintf');

const rl = require('readline').createInterface({
  input: process.stdin,
  output: process.stdout
});

var r2pipe = require("r2pipe");

var dict = {
  '🏄':'s',
  '💣':'q',
  '💥':'q!',
  '🐛':'d',
  '🐚':'!',
  '🐧':'u',
  '🕵':'pxe',
  '💭':'?E ',
  '📦':'P',
  '📝':'w',
  '🖨':'pd',
  '♿':'?',
  '👁':'V',
  '🐪': '#!perl',
  '🐍':'#!python',
  '#️⃣': '#',
  '🏃': 'dc'
};

var filter = {
  'Warning': '⚠️',
  "eax": "👾",
  "ebx": "🐵",
  "ecx": "🎩",
  "edx": "💅",
  "rip": "🍭",
  "rax": "🍤",
  "rbx": "🎄",
  "rcx": "🍴",
  "rdx": "🏂",
  "rbp": "🐷",
  "rsi": "🍝",
  "rdi": "👽",
  "esi": "🍝",
  "edi": "🏁",
  "esp": "🐷",
  "rsp": "🍆",
  "r9": "🐭",
  "r10": "💄",
  "r11": "🍰",
  "r12": "🎳",
  "r13": "🌷",
  "r14": "🌸",
  "r15": "👉",
};

if (process.argv.length< 3) {
  console.error("Usage: ramoji2 [file]");
  process.exit ();
}

r2pipe.open(process.argv[2], (r2) => {
  r2.cmd('e scr.color = true');
  r2.cmd('e asm.bytes = false');
  var promptLine = colors.yellow ('[0x00000000]> ');
  function getSeek(cb) {
      r2.cmd('s', function (off) {
         promptLine = sprintf(colors.yellow('[%08x]> '), +off);
         cb (off);
      });
   }
   function input() {
     rl.question(promptLine, (answer) => {
       function repeat(msg) {
          if (msg) {
              for (var a of Object.keys(filter)) {
                 msg = msg.replace (new RegExp(a,'g'), filter[a]);
              }
              console.log(msg);
          }
          getSeek (function (curoff) {
             input();
          });
       }
       if (answer === '♿') {
        console.log(JSON.stringify(dict).replace('{','')
          .replace('}','').replace(/,/g,'\n')
          .replace(/"/g,'').replace(/:/g,'  '));
        repeat();
      } else if (answer === 'q') {
        console.log('This is not the emoji way to quit!');
        rl.close();
        r2.quit();
      } else {
        let word = answer.split(' ')[0];
        if (dict[word]) {
          answer = answer.replace(word, dict[word]);
        } else {
          console.error("Unknown command. Use ♿ for help.");
          return repeat();
        }
        r2.cmd (answer, repeat);
      }
    });
  }
  getSeek(input);
});
