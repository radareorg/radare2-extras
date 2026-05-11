"use strict";
(() => {
  // src/r2jadx.ts
  var r2jadxConfig = {
    addr: false,
    color: true,
    indent: true
  };
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
Setup: e cmd.pdc=pd:j
Alias: pd:j, pd:jo
 -r   = import low level decompilation as comments
 -r2  = import high level decompilation as comments
 -e   = display or change plugin config
 -C   = clear jadx cache directory for the current DEX
----------------------------------
 -cn  = show current classname
 -a   = show decompilation of all the classes
 -c   = decompile current class
 -f   = decompile current function
 -s   = search decompiled code for text
 -ahl = all high level decompilation
 -all = all low level decompilation
 -hl  = high level decompilation
 -ll  = low level decompilation`;
  function parseBoolean(value) {
    switch (value.toLowerCase()) {
      case "1":
      case "true":
      case "yes":
      case "on":
        return true;
      case "0":
      case "false":
      case "no":
      case "off":
        return false;
    }
    return void 0;
  }
  function boolConfigHandler(key) {
    return {
      get: () => String(r2jadxConfig[key]),
      set: (value) => {
        const parsed = parseBoolean(value);
        if (parsed === void 0) {
          console.error("Invalid boolean value: " + value);
          return false;
        }
        r2jadxConfig[key] = parsed;
        return true;
      }
    };
  }
  var r2jadxConfigHandlers = {
    "addr": boolConfigHandler("addr"),
    "color": boolConfigHandler("color"),
    "indent": boolConfigHandler("indent")
  };
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
  function r2jadxListConfig() {
    for (const key of Object.keys(r2jadxConfigHandlers)) {
      console.log("r2jadx -e " + key + "=" + r2jadxConfigHandlers[key].get());
    }
  }
  function r2jadxEvalConfig(arg) {
    const eqIndex = arg.indexOf("=");
    const key = eqIndex === -1 ? arg : arg.slice(0, eqIndex);
    const value = eqIndex === -1 ? void 0 : arg.slice(eqIndex + 1);
    const handler = r2jadxConfigHandlers[key];
    if (!handler) {
      console.error("Unknown config key: " + key);
      return;
    }
    if (value === "?") {
      console.log("true\nfalse");
      return;
    }
    if (value === void 0) {
      console.log(handler.get());
      return;
    }
    handler.set(value);
  }
  function r2jadxDisplayLine(line) {
    line = line.replaceAll("	", "  ");
    line = line.replaceAll("\r", "");
    line = line.replaceAll("\n", "");
    return r2jadxConfig.indent ? line : line.trim();
  }
  function r2jadxDisplayPrefix(addr) {
    return r2jadxConfig.addr ? toPaddedHexString(addr, 8) + "  " : "";
  }
  function r2jadxDisplayUnknownPrefix() {
    return r2jadxConfig.addr ? " ".repeat(12) : "";
  }
  function r2jadxDisplayAddressLine(addr, line) {
    const prefix = addr === void 0 ? r2jadxDisplayUnknownPrefix() : r2jadxDisplayPrefix(addr);
    return prefix + line;
  }
  function r2jadxIndentLine(line, level) {
    const code = r2jadxDisplayLine(line);
    if (code.length === 0) {
      return "";
    }
    return " ".repeat(level * 4) + code;
  }
  function r2jadxEscapeQuotedArg(value) {
    return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  }
  function r2jadxColorCode(line) {
    const leadingMatch = line.match(/^\s*/);
    const leading = leadingMatch ? leadingMatch[0] : "";
    const code = line.substring(leading.length);
    if (code.length === 0) {
      return line;
    }
    const colored = r2.cmd('?e "' + r2jadxEscapeQuotedArg(code) + '"~:))');
    return leading + colored.replace(/\n$/, "");
  }
  function r2jadxColorLine(line) {
    const addressMatch = line.match(/^(0x[0-9a-fA-F]+\s+)(.*)$/);
    if (addressMatch) {
      return addressMatch[1] + r2jadxColorCode(addressMatch[2]);
    }
    return r2jadxColorCode(line);
  }
  function r2jadxShouldColor(mode) {
    switch (mode) {
      case "a":
      case "c":
      case "cat":
      case "f":
      case "all":
      case "ahl":
      case "s":
        return r2jadxConfig.color;
    }
    return false;
  }
  function r2jadxFormatOutput(output, mode) {
    if (!r2jadxShouldColor(mode)) {
      return output;
    }
    return output.split("\n").map(r2jadxColorLine).join("\n");
  }
  function processClass(data, mode, context) {
    const methods = data.methods || [];
    if (mode === "c") {
      return r2jadxClassMatches(data, context) ? r2jadxReadClassSource(data) : "";
    }
    let res = "";
    for (const method of methods) {
      switch (mode) {
        case "a":
        case "f":
        case "cat":
        case "r":
        case "r2":
        case "all":
        case "ahl":
        case "ll":
        case "hl":
          res += processMethod(data, mode, context, method);
          break;
        default:
          res += "Invalid mode " + mode + "\n";
          break;
      }
    }
    return res;
  }
  function r2jadxReadClassSource(data) {
    if (!data.source) {
      return "";
    }
    const source = readFile(data.source.replace(".json", ".java")).toString();
    return r2jadxConfig.addr ? r2jadxAddressClassSource(data, source) : source;
  }
  function r2jadxSanitizeName(name) {
    return name.replace(/[^A-Za-z0-9_]+/g, "_").replace(/^_+|_+$/g, "");
  }
  function r2jadxMethodLineOffsets(method) {
    const offsets = [parseOffset(method.offset)];
    for (const line of method.lines || []) {
      if (line.offset) {
        offsets.push(parseOffset(line.offset));
      }
    }
    return offsets.filter((offset) => !isNaN(offset));
  }
  function r2jadxMethodContainsOffset(method, offset) {
    const offsets = r2jadxMethodLineOffsets(method);
    if (offsets.length === 0) {
      return false;
    }
    const min = Math.min(...offsets);
    const max = Math.max(...offsets);
    return offset >= min && offset <= max + 16;
  }
  function r2jadxClassMatches(data, context) {
    for (const method of data.methods || []) {
      if (r2jadxMethodMatches(data, method, context)) {
        return true;
      }
    }
    return false;
  }
  function r2jadxNormalizeSourceLine(line, className) {
    let normalized = line.trim();
    if (className.length > 0) {
      normalized = normalized.replaceAll(className + ".", "");
    }
    normalized = normalized.replace(/\b[A-Za-z_$][A-Za-z0-9_$]*\.(?=[A-Z_])/g, "");
    return normalized.replace(/\s+/g, " ");
  }
  function r2jadxFindSourceLine(lines, needle, start, className, used) {
    const trimmedNeedle = needle.trim();
    if (trimmedNeedle.length === 0) {
      return -1;
    }
    const normalizedNeedle = r2jadxNormalizeSourceLine(trimmedNeedle, className);
    for (let i = start; i < lines.length; i++) {
      if (used && used.has(i)) {
        continue;
      }
      const trimmedLine = lines[i].trim();
      const normalizedLine = r2jadxNormalizeSourceLine(trimmedLine, className);
      if (trimmedLine === trimmedNeedle || normalizedLine === normalizedNeedle) {
        return i;
      }
      if (normalizedLine.length > 0 && normalizedNeedle.length > 0 && (normalizedLine.indexOf(normalizedNeedle) !== -1 || normalizedNeedle.indexOf(normalizedLine) !== -1)) {
        return i;
      }
      if (trimmedLine === trimmedNeedle + " {" || normalizedLine === normalizedNeedle + " {") {
        return i;
      }
    }
    return -1;
  }
  function r2jadxFindClosingBrace(lines, start) {
    for (let i = start; i < lines.length; i++) {
      if (lines[i].trim() === "}") {
        return i;
      }
    }
    return -1;
  }
  function r2jadxAddressClassSource(data, source) {
    const lines = source.replace(/\r/g, "").split("\n");
    const addresses = new Array(lines.length);
    let cursor = 0;
    const className = data.name || "";
    const used = /* @__PURE__ */ new Set();
    for (const method of data.methods || []) {
      const methodOffset = parseOffset(method.offset);
      let methodStart = cursor;
      for (const declarationLine of (method.declaration || "").split("\n")) {
        const lineIndex = r2jadxFindSourceLine(lines, declarationLine, cursor, className, used);
        if (lineIndex !== -1) {
          addresses[lineIndex] = methodOffset;
          used.add(lineIndex);
          cursor = lineIndex + 1;
          methodStart = Math.min(methodStart, lineIndex);
        }
      }
      let lastOffset = methodOffset;
      let lastLineIndex = cursor;
      for (const line of method.lines || []) {
        if (line.offset) {
          lastOffset = parseOffset(line.offset);
        }
        const lineIndex = r2jadxFindSourceLine(lines, line.code, methodStart, className, used);
        if (lineIndex !== -1) {
          addresses[lineIndex] = lastOffset;
          used.add(lineIndex);
          lastLineIndex = Math.max(lastLineIndex, lineIndex);
        }
      }
      const closeIndex = r2jadxFindClosingBrace(lines, lastLineIndex + 1);
      if (closeIndex !== -1) {
        addresses[closeIndex] = lastOffset;
        used.add(closeIndex);
        cursor = closeIndex + 1;
      }
    }
    return lines.map((line, index) => r2jadxDisplayAddressLine(addresses[index], line)).join("\n");
  }
  function r2jadxMethodMatches(data, method, context) {
    if (r2jadxMethodContainsOffset(method, context.offset)) {
      return true;
    }
    const functionName = context.functionName;
    if (functionName.length === 0) {
      return false;
    }
    const className = data.name || "";
    const packageName = data.package || "";
    const qualifiedName = packageName.length > 0 ? packageName + "." + className : className;
    const classTokens = [
      r2jadxSanitizeName(className),
      r2jadxSanitizeName(qualifiedName)
    ].filter((token) => token.length > 0);
    if (!classTokens.some((token) => functionName.indexOf("L" + token) !== -1 || functionName.indexOf(token) !== -1)) {
      return false;
    }
    const methodToken = r2jadxSanitizeName(method.name);
    return methodToken.length > 0 && (functionName.indexOf(".method." + methodToken) !== -1 || functionName.indexOf("_" + methodToken + "_") !== -1);
  }
  function r2jadxFormatMethod(method) {
    let res = "";
    const offset = parseOffset(method.offset);
    const declaration = (method.declaration || method.name).trim().split("\n");
    for (let i = 0; i < declaration.length; i++) {
      const suffix = i === declaration.length - 1 ? " {" : "";
      res += r2jadxDisplayAddressLine(offset, declaration[i] + suffix) + "\n";
    }
    let lastOffset = offset;
    for (const line of method.lines || []) {
      if (!line.code || line.code.length === 0) {
        continue;
      }
      if (line.offset) {
        lastOffset = parseOffset(line.offset);
      }
      res += r2jadxDisplayAddressLine(lastOffset, r2jadxIndentLine(line.code, 1)) + "\n";
    }
    res += r2jadxDisplayAddressLine(lastOffset, "}") + "\n";
    return res;
  }
  function processMethod(data, mode, context, method) {
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
    if (mode === "f") {
      return r2jadxMethodMatches(data, method, context) ? r2jadxFormatMethod(method) : "";
    }
    if (mode === "all" || mode === "ahl") {
      let res2 = "\n" + r2jadxDisplayPrefix(parseOffset(method.offset)) + method.name + ":\n";
      for (const line of lines) {
        const lineOffset = parseOffset(line.offset || lastOffset);
        res2 += r2jadxDisplayPrefix(lineOffset) + r2jadxDisplayLine(line.code) + "\n";
        if (line.offset) {
          lastOffset = parseOffset(line.offset);
        }
      }
      return res2;
    }
    if (mode === "r") {
      mode = "r2";
    }
    if (mode === "ll" || mode === "hl") {
      let res2 = "";
      if (context.offset === lastOffset) {
        return processMethod(data, "r2", context, method);
      }
      for (const line of lines) {
        if (parseOffset(line.offset) === context.offset - 16) {
          res2 += processMethod(data, "r2", context, method);
        }
      }
      return res2;
    }
    let res = comment(parseOffset(method.offset) + 16, method.name);
    for (const line of lines) {
      const addr = parseOffset(line.offset || lastOffset);
      const code = mode === "f" ? line.code : line.code.trim();
      res += comment(addr, code);
      if (line.offset) {
        lastOffset = parseOffset(line.offset);
      }
    }
    return res;
  }
  function r2jadxCrawlFiles(target, mode, context) {
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
          data.source = fileName;
          res += processClass(data, mode, context);
          if (data["inner-classes"]) {
            for (const klass of data["inner-classes"]) {
              klass.source = fileName;
              res += processClass(klass, mode, context);
            }
          }
        }
      } catch (e) {
        console.error("" + fileName + ": " + e);
      }
    }
    return res;
  }
  function r2jadxCrawl(target, mode, context) {
    switch (mode) {
      case "cn":
      case "f":
        return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, context);
      case "c":
        return r2jadxCrawlFiles(pathJoin(target, "hl"), "c", context);
      case "a":
        return r2jadxCrawlFiles(pathJoin(target, "hl"), "cat", context);
      case "r":
        return r2jadxCrawlFiles(pathJoin(target, "ll"), mode, context);
      case "r2":
        return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, context);
      case "ll":
        return r2jadxCrawlFiles(pathJoin(target, "ll"), mode, context);
      case "hl":
        return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, context);
      case "ahl":
        return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, context);
      case "all":
        return r2jadxCrawlFiles(pathJoin(target, "ll"), mode, context);
      case "cat":
        return r2jadxCrawlFiles(pathJoin(target, "cat"), mode, context);
      case "?":
      case "h":
      case "help":
      default:
        return R2JADX_HELP;
    }
  }
  function r2jadxEnsureDecompiled(target) {
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
    return outdir;
  }
  function r2jadxDecompile(target, mode, context) {
    const outdir = r2jadxEnsureDecompiled(target);
    return r2jadxCrawl(outdir, mode, context);
  }
  function r2jadxClearCache(target) {
    runCmd(["rm", "-rf", nospace(dex2path(target))]);
  }
  function r2jadxQualifiedClassName(data) {
    const className = data.name || "";
    const packageName = data.package || "";
    if (packageName.length > 0 && className.indexOf(packageName + ".") === 0) {
      return className;
    }
    return packageName.length > 0 && className.length > 0 ? packageName + "." + className : className;
  }
  function r2jadxSearchLine(query, addr, scope, line) {
    if (line.indexOf(query) === -1) {
      return "";
    }
    const offset = parseOffset(addr);
    const prefix = isNaN(offset) ? "            " : toPaddedHexString(offset, 8) + "  ";
    return prefix + scope + ": " + r2jadxDisplayLine(line).trim() + "\n";
  }
  function r2jadxSearchClass(data, query) {
    let res = "";
    const className = r2jadxQualifiedClassName(data);
    if (className.length === 0) {
      return "";
    }
    if (data.declaration) {
      res += r2jadxSearchLine(query, void 0, className, data.declaration);
    }
    for (const field of data.fields || []) {
      res += r2jadxSearchLine(query, void 0, className + "." + field.name, field.declaration || field.name);
    }
    for (const method of data.methods || []) {
      const methodScope = className + "." + method.name;
      res += r2jadxSearchLine(query, method.offset, methodScope, method.declaration || method.name);
      let lastOffset = method.offset;
      for (const line of method.lines || []) {
        if (line.offset) {
          lastOffset = line.offset;
        }
        res += r2jadxSearchLine(query, lastOffset, methodScope, line.code || "");
      }
    }
    for (const klass of data["inner-classes"] || []) {
      res += r2jadxSearchClass(klass, query);
    }
    return res;
  }
  function r2jadxSearch(target, query) {
    const files = walkSync(target).filter((_) => _.endsWith && _.endsWith(".json"));
    let res = "";
    for (const fileName of files) {
      try {
        const fileData = readFile(fileName);
        const data = JSON.parse(fileData);
        res += r2jadxSearchClass(data, query);
      } catch (e) {
        console.error("" + fileName + ": " + e);
      }
    }
    return res;
  }
  function r2jadxMain(argv) {
    const firstArg = argv[0] || "";
    if (r2jadxIsHelpArg(firstArg)) {
      console.error(R2JADX_HELP);
      return void 0;
    }
    if (firstArg === "-e") {
      const configArg = argv.slice(1).join(" ").trim();
      if (configArg.length > 0) {
        r2jadxEvalConfig(configArg);
      } else {
        r2jadxListConfig();
      }
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
      const currentFunction = fcn && fcn.length > 0 ? fcn[0] : void 0;
      const context = {
        offset: currentFunction ? currentFunction.offset : 0,
        functionName: currentFunction && currentFunction.name ? currentFunction.name : "",
        fileName: currentFunction && currentFunction.file ? currentFunction.file : ""
      };
      let mode = "all";
      if (firstArg[0] === "-") {
        mode = firstArg.substring(1);
      }
      if (mode === "C") {
        r2jadxClearCache(fileName);
        return void 0;
      }
      const searchText = argv.slice(1).join(" ").trim();
      if (mode === "s") {
        if (searchText.length === 0) {
          console.error("Usage: r2jadx -s text");
          return void 0;
        }
        const res2 = r2jadxSearch(pathJoin(r2jadxEnsureDecompiled(fileName), "hl"), searchText);
        console.log(r2jadxFormatOutput(res2, mode));
        return res2;
      }
      const res = r2jadxDecompile(fileName, mode, context);
      if (mode.startsWith("r")) {
        for (const line of res.split("\n")) {
          if (line.trim().length > 0) {
            r2.cmd(line);
          }
        }
      } else {
        console.log(r2jadxFormatOutput(res, mode));
      }
      return res;
    } catch (e) {
      const error = e;
      console.error("Oops", e, error.output ? error.output.toString() : "");
      throw e;
    }
  }
  function r2jadxWithAddr(addr, cb) {
    const savedAddr = r2jadxConfig.addr;
    r2jadxConfig.addr = addr;
    try {
      return cb();
    } finally {
      r2jadxConfig.addr = savedAddr;
    }
  }
  function r2jadxPdCommand(cmd) {
    const flags = cmd.substring(4).trim();
    if (flags.indexOf("?") !== -1) {
      console.error(R2JADX_HELP);
      return;
    }
    if (flags.indexOf("*") !== -1) {
      r2jadxMain(["-r2"]);
      return;
    }
    if (flags.indexOf("=") !== -1 || flags.indexOf("a") !== -1) {
      r2jadxMain(["-a"]);
      return;
    }
    r2jadxWithAddr(flags.indexOf("o") !== -1, () => r2jadxMain(["-f"]));
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
        if (cmd.startsWith("pd:j")) {
          r2jadxPdCommand(cmd);
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
