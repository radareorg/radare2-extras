"use strict";
(() => {
  // src/r2jadx.ts
  function nospace(d) {
    if (d.indexOf(" ") !== -1) {
      throw new Error("Path cant contain spaces");
    }
    return d;
  }
  function directoryExists(d) {
    const directory = r2.cmd("'!!test -d " + nospace(d) + " && echo exists").trim();
    return directory === "exists";
  }
  function runCmd(c) {
    const cmdline = c.join(" ");
    console.log(cmdline);
    r2.cmd("'!" + cmdline);
  }
  function parseOffset(value) {
    return parseInt(String(value));
  }
  function toPaddedHexString(num, len) {
    const str = parseOffset(num).toString(16);
    return "0x" + ("0".repeat(len - str.length) + str);
  }
  function pathJoin(...args) {
    return args.join("/");
  }
  function readFile(f) {
    return r2.cmd("cat " + f);
  }
  function dex2path(target) {
    return target + ".d";
  }
  function walkSync(dir) {
    const files = r2.cmd("!!find " + dir + " -type f").trim();
    return files.length > 0 ? files.split(/\n/g) : [];
  }
  var R2JADX_HELP = `Usage: r2jadx [-mode]
Setup: e cmd.pdc=r2jadx
 -r   = import low level decompilation as comments
 -r2  = import high level decompilation as comments
----------------------------------
 -cn  = show current classname
 -a   = show decompilation of all the classes
 -c   = decompile current class
 -f   = decompile current function
 -ahl = all high level decompilation
 -all = all low level decompilation
 -hl  = high level decompilation
 -ll  = low level decompilation`;
  function r2jadxIsHelpArg(arg) {
    switch (arg) {
      case "":
      case "?":
      case "h":
      case "help":
      case "-h":
      case "-help":
      case "--help":
        return true;
    }
    return false;
  }
  function processClass(data, mode, offset) {
    const classOffset = parseOffset(offset);
    let res = "";
    if (data.methods) {
      for (const method of data.methods) {
        switch (mode) {
          case "a":
          case "c":
          case "f":
          case "cat":
          case "r":
          case "r2":
          case "all":
          case "ahl":
          case "ll":
          case "hl":
            res += processMethod(data, mode, classOffset, method);
            break;
          default:
            res += "Invalid mode " + mode + "\n";
            break;
        }
      }
    }
    return res;
  }
  function processMethod(data, mode, offset, method) {
    function comment(addr, line) {
      if (mode === "c" || mode === "cat") {
        if (!data.source) {
          return "";
        }
        const lastOffset2 = parseOffset(method.offset);
        if (mode === "cat" || mode === "c" && addr === lastOffset2) {
          const source = data.source.replace(".json", ".java");
          const fileData = readFile(source);
          return fileData.toString();
        }
        return "";
      }
      if (line === "") {
        return "";
      }
      if (mode === "f") {
        const lastOffset2 = parseOffset(method.offset);
        if (addr === lastOffset2) {
          return toPaddedHexString(addr, 8) + "  " + line + "\n";
        }
        return "";
      }
      line = line.replaceAll("	", "  ");
      line = line.replaceAll("\r", "");
      line = line.replaceAll("\n", "");
      line = line.replaceAll(/[^ -~]+/g, "");
      line = line.replaceAll(/^SourceFile:\d+ /g, "");
      const b64line = b64(line);
      if (b64line.length > 2048) {
        return "CCu toolong @ " + addr + "\n";
      }
      return "CCu base64:" + b64line + " @ " + addr + "\n";
    }
    let lastOffset = parseOffset(method.offset);
    const lines = method.lines || [];
    if (mode === "all" || mode === "ahl") {
      let res2 = "\n" + toPaddedHexString(method.offset, 8) + "  " + method.name + ":\n";
      for (const line of lines) {
        res2 += toPaddedHexString(line.offset || lastOffset, 8) + "  " + line.code + "\n";
        if (line.offset) {
          lastOffset = parseOffset(line.offset);
        }
      }
      return res2;
    }
    if (mode === "r") {
      offset = 0;
      mode = "r2";
    }
    if (mode === "ll" || mode === "hl") {
      let res2 = "";
      if (offset === lastOffset) {
        return processMethod(data, "r2", offset, method);
      }
      for (const line of lines) {
        if (parseOffset(line.offset) === offset - 16) {
          res2 += processMethod(data, "r2", offset, method);
        }
      }
      return res2;
    }
    let res = comment(parseOffset(method.offset) + 16, method.name);
    for (const line of lines) {
      const addr = parseOffset(line.offset || lastOffset);
      res += comment(addr, line.code.trim());
      if (line.offset) {
        lastOffset = parseOffset(line.offset);
      }
    }
    return res;
  }
  function r2jadxCrawlFiles(target, mode, arg) {
    const ext = "json";
    const files = walkSync(target).filter((_) => _.endsWith && _.endsWith(ext));
    let res = "";
    for (const fileName of files) {
      try {
        if (mode === "cat") {
          const fileData = readFile(fileName.replace(".json", ".java"));
          res += fileData;
        } else {
          const fileData = readFile(fileName);
          const data = JSON.parse(fileData);
          res += processClass(data, mode, arg);
          if (data["inner-classes"]) {
            for (const klass of data["inner-classes"]) {
              klass.source = fileName;
              res += processClass(klass, mode, arg);
            }
          }
        }
      } catch (e) {
        console.error("" + fileName + ": " + e);
      }
    }
    return res;
  }
  function r2jadxCrawl(target, mode, arg) {
    switch (mode) {
      case "cn":
      case "f":
        return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, arg);
      case "c":
        return r2jadxCrawlFiles(pathJoin(target, "hl"), "c", arg);
      case "a":
        return r2jadxCrawlFiles(pathJoin(target, "hl"), "cat", arg);
      case "r":
        return r2jadxCrawlFiles(pathJoin(target, "ll"), mode, arg);
      case "r2":
        return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, arg);
      case "ll":
        return r2jadxCrawlFiles(pathJoin(target, "ll"), mode, arg);
      case "hl":
        return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, arg);
      case "ahl":
        return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, arg);
      case "all":
        return r2jadxCrawlFiles(pathJoin(target, "ll"), mode, arg);
      case "cat":
        return r2jadxCrawlFiles(pathJoin(target, "cat"), mode, arg);
      case "?":
      case "h":
      case "help":
      default:
        return R2JADX_HELP;
    }
  }
  function r2jadxDecompile(target, mode, arg) {
    const outdir = dex2path(target);
    if (!directoryExists(outdir)) {
      console.error("jadx: Performing the low level decompilation...");
      runCmd(["r2pm", "-r", "jadx", "--output-format", "json", "-m", "simple", "-d", pathJoin(outdir, "ll"), target]);
      runCmd(["r2pm", "-r", "jadx", "--output-format", "java", "-m", "simple", "-d", pathJoin(outdir, "ll"), target]);
      console.error("jadx: Performing the high level decompilation...");
      runCmd(["r2pm", "-r", "jadx", "--show-bad-code", "--output-format", "java", "-d", pathJoin(outdir, "hl"), target]);
      console.error("jadx: Constructing the high level jsons...");
      runCmd(["r2pm", "-r", "jadx", "--show-bad-code", "--output-format", "json", "-d", pathJoin(outdir, "hl"), target]);
    }
    return r2jadxCrawl(outdir, mode, arg);
  }
  function r2jadxMain(argv) {
    const firstArg = argv[0] || "";
    if (r2jadxIsHelpArg(firstArg)) {
      console.error(R2JADX_HELP);
      return void 0;
    }
    try {
      r2.cmd("af");
      const info = r2.cmdj("ij");
      const fileName = info.core.file;
      const fcn = r2.cmdj("afij");
      if (!fileName.endsWith(".dex")) {
        throw new Error("Sorry, this is not a DEX file");
      }
      if (!fileName) {
        throw new Error("Cannot find function");
      }
      const fcnOffset = fcn && fcn.length > 0 ? fcn[0].offset : 0;
      let mode = "all";
      if (firstArg[0] === "-") {
        mode = firstArg.substring(1);
      }
      const res = r2jadxDecompile(fileName, mode, fcnOffset);
      if (mode.startsWith("r")) {
        for (const line of res.split("\n")) {
          if (line.trim().length > 0) {
            r2.cmd(line);
          }
        }
      } else {
        console.log(res);
      }
      return res;
    } catch (e) {
      const error = e;
      console.error("Oops", e, error.output ? error.output.toString() : "");
      throw e;
    }
  }
  function r2jadxBegin() {
    r2.unload("core", "r2jadx");
    r2.plugin("core", function() {
      function coreCall(cmd) {
        if (cmd.startsWith("r2jadx")) {
          const argv = cmd.substring(6).trim().split(" ");
          r2jadxMain(argv);
          return true;
        }
        return false;
      }
      return {
        name: "r2jadx",
        license: "MIT",
        desc: "jadx decompiler for radare2",
        call: coreCall
      };
    });
  }
  r2jadxBegin();
})();
