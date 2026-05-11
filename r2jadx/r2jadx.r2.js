"use strict";
(() => {
  // src/r2api.ts
  function b64encode(data) {
    return b64(data);
  }
  function r2cmd(cmd) {
    return r2.cmd(cmd);
  }
  function r2log(msg) {
    r2.log(msg);
  }
  function r2cmdj(cmd) {
    return r2.cmdj(cmd);
  }
  function r2fdump(data, file) {
    return r2.fdump(data, file);
  }
  function r2fload(file) {
    return r2.fload(file);
  }
  function r2plugin(type, factory) {
    r2.plugin(type, factory);
  }
  function r2unload(type, name) {
    r2.unload(type, name);
  }

  // src/config.ts
  var r2jadxConfig = {
    alias: true,
    addr: false,
    color: true,
    indent: true
  };
  var R2JADX_HELP = `Usage: r2jadx [-mode]
Setup: e cmd.pdc=pd:j
Alias: pd:j, pd:jo
 -C   = clear jadx cache directory for the current DEX
 -a   = show decompilation of all the classes
 -ahl = all high level decompilation
 -all = all low level decompilation
 -ci  = list current class imports
 -cn  = show current classname
 -d   = decompile current function
 -d*  = import current function decompilation as comments
 -dc  = decompile current class
 -dc* = import current class decompilation as comments
 -dj  = decompile current function as json
 -e   = display or change plugin config
 -hl  = high level decompilation
 -i   = list all imports
 -ll  = low level decompilation
 -p   = show current package
 -pi  = list current package imports
 -pl  = list all packages
 -s   = search decompiled code for text
 -x   = show xrefs to current function or class`;
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
    "alias": boolConfigHandler("alias"),
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
      r2log("r2jadx -e " + key + "=" + r2jadxConfigHandlers[key].get());
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
      r2log("true\nfalse");
      return;
    }
    if (value === void 0) {
      r2log(handler.get());
      return;
    }
    handler.set(value);
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

  // src/util.ts
  function nospace(d) {
    if (d.indexOf(" ") !== -1) {
      throw new Error("Path cant contain spaces");
    }
    return d;
  }
  function fileExists(f) {
    const file = r2cmd("'!!test -f " + nospace(f) + " && echo exists").trim();
    return file === "exists";
  }
  function runCmd(c) {
    const cmdline = c.join(" ");
    console.log(cmdline);
    r2cmd("'!" + cmdline);
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
    return r2fload(nospace(f));
  }
  function writeFile(f, data) {
    if (!r2fdump(data, nospace(f))) {
      throw new Error("Cannot write file: " + f);
    }
  }
  function dex2path(target) {
    return target + ".d";
  }
  function walkSync(dir) {
    const files = r2cmd("!!find " + dir + " -type f").trim();
    return files.length > 0 ? files.split(/\n/g) : [];
  }

  // src/format.ts
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
    const colored = r2cmd('?e "' + r2jadxEscapeQuotedArg(code) + '"~:))');
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
      case "cat":
      case "d":
      case "dc":
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

  // src/jadx.ts
  var r2jadxImportCache = {};
  function processClass(data, mode, context) {
    if (mode === "p") {
      return r2jadxClassMatches(data, context) ? r2jadxPackageLine(data) : "";
    }
    if (mode === "ci") {
      return r2jadxClassMatches(data, context) ? r2jadxImportLines(data, true) : "";
    }
    const methods = data.methods || [];
    if (mode === "dc*") {
      if (!r2jadxClassMatches(data, context)) {
        return "";
      }
      return methods.map((method) => processMethod(data, "dc*", context, method)).join("");
    }
    if (mode === "dc") {
      return r2jadxClassMatches(data, context) ? r2jadxReadClassSource(data) : "";
    }
    let res = "";
    for (const method of methods) {
      switch (mode) {
        case "a":
        case "d":
        case "dj":
        case "d*":
        case "cat":
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
  function r2jadxClassOffset(data) {
    const offsets = (data.methods || []).map((method) => parseOffset(method.offset)).filter((offset) => !isNaN(offset));
    return offsets.length > 0 ? Math.min(...offsets) : 0;
  }
  function r2jadxQualifiedClassName(data) {
    const className = data.name || "";
    const packageName = data.package || "";
    if (packageName.length > 0 && className.indexOf(packageName + ".") === 0) {
      return className;
    }
    return packageName.length > 0 && className.length > 0 ? packageName + "." + className : className;
  }
  function r2jadxRecord(addr, fields) {
    let res = toPaddedHexString(addr, 8);
    for (const key of Object.keys(fields)) {
      res += "	" + key + "	" + String(fields[key]);
    }
    return res + "\n";
  }
  function r2jadxImportPackage(importName) {
    const trimmed = importName.replace(/\.\*$/, "");
    const lastDot = trimmed.lastIndexOf(".");
    return lastDot === -1 ? "" : trimmed.slice(0, lastDot);
  }
  function r2jadxClassImports(data) {
    if (data.imports) {
      return data.imports.slice().sort();
    }
    if (!data.source) {
      return [];
    }
    if (r2jadxImportCache[data.source]) {
      return r2jadxImportCache[data.source];
    }
    const source = readFile(data.source.replace(".json", ".java")).toString();
    const imports = /* @__PURE__ */ new Set();
    for (const line of source.split(/\r?\n/g)) {
      const match = line.trim().match(/^import\s+(?:static\s+)?([^;]+);$/);
      if (match) {
        imports.add(match[1]);
      }
    }
    r2jadxImportCache[data.source] = Array.from(imports).sort();
    return r2jadxImportCache[data.source];
  }
  function r2jadxPackageLine(data) {
    return toPaddedHexString(r2jadxClassOffset(data), 8) + "	" + (data.package || "") + "	" + r2jadxQualifiedClassName(data) + "\n";
  }
  function r2jadxImportLines(data, brief) {
    let res = "";
    for (const importName of r2jadxClassImports(data)) {
      if (brief) {
        res += toPaddedHexString(r2jadxClassOffset(data), 8) + "	" + importName + "\n";
        continue;
      }
      res += r2jadxRecord(r2jadxClassOffset(data), {
        "kind": "import",
        "package": data.package || "",
        "class": r2jadxQualifiedClassName(data),
        "import": importName,
        "import_package": r2jadxImportPackage(importName)
      });
    }
    return res;
  }
  function r2jadxCompactLine(line) {
    return line.trim().replace(/\s+/g, " ");
  }
  function r2jadxXrefScope(data, method) {
    return r2jadxQualifiedClassName(data) + "." + method.name;
  }
  function r2jadxShortClassName(data) {
    const name = data.name || "";
    return name.split(".").pop() || name;
  }
  function r2jadxMethodKey(data, method) {
    return r2jadxQualifiedClassName(data) + "." + method.name;
  }
  function r2jadxClassMaps(classes) {
    const byQualified = {};
    const byShort = {};
    for (const data of classes) {
      const qualifiedName = r2jadxQualifiedClassName(data);
      const shortName = r2jadxShortClassName(data);
      if (qualifiedName.length > 0) {
        byQualified[qualifiedName] = data;
      }
      if (shortName.length > 0) {
        byShort[shortName] = byShort[shortName] || [];
        byShort[shortName].push(data);
      }
    }
    return { byQualified, byShort };
  }
  function r2jadxResolveClassName(name, source, byQualified, byShort) {
    if (byQualified[name]) {
      return byQualified[name];
    }
    for (const importName of r2jadxClassImports(source)) {
      if (importName === name || importName.endsWith("." + name)) {
        return byQualified[importName];
      }
      if (importName.endsWith(".*") && byQualified[importName.slice(0, -1) + name]) {
        return byQualified[importName.slice(0, -1) + name];
      }
    }
    const packageName = source.package || "";
    if (packageName.length > 0 && byQualified[packageName + "." + name]) {
      return byQualified[packageName + "." + name];
    }
    const matches = byShort[name] || [];
    return matches.length === 1 ? matches[0] : void 0;
  }
  function r2jadxHasMethod(data, methodName) {
    return (data.methods || []).some((method) => method.name === methodName);
  }
  function r2jadxAddXref(records, seen, record) {
    const key = record.kind + "	" + record.target + "	" + record.addr + "	" + record.scope + "	" + record.line;
    if (!seen.has(key)) {
      seen.add(key);
      records.push(record);
    }
  }
  function r2jadxIndexClassRef(records, seen, source, target, addr, scope, line) {
    if (source === target) {
      return;
    }
    r2jadxAddXref(records, seen, {
      kind: "class",
      target: r2jadxQualifiedClassName(target),
      addr,
      scope,
      line
    });
  }
  function r2jadxIndexMethodRef(records, seen, target, methodName, addr, scope, line) {
    if (!r2jadxHasMethod(target, methodName)) {
      return;
    }
    r2jadxAddXref(records, seen, {
      kind: "method",
      target: r2jadxQualifiedClassName(target) + "." + methodName,
      addr,
      scope,
      line
    });
  }
  function r2jadxIndexXrefLine(records, seen, source, method, line, addr, byQualified, byShort) {
    const compactLine = r2jadxCompactLine(line);
    if (compactLine.length === 0) {
      return;
    }
    const scope = r2jadxXrefScope(source, method);
    const qualifiedClassRe = /\b(?:[a-z_$][A-Za-z0-9_$]*\.)+[A-Z_$][A-Za-z0-9_$]*\b/g;
    const shortClassRe = /\b[A-Z_$][A-Za-z0-9_$]*\b/g;
    const callRe = /\b((?:[A-Za-z_$][A-Za-z0-9_$]*\.)*[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g;
    const bareCallRe = /(^|[^A-Za-z0-9_$\.])([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g;
    let match;
    while (match = qualifiedClassRe.exec(compactLine)) {
      const target = r2jadxResolveClassName(match[0], source, byQualified, byShort);
      if (target) {
        r2jadxIndexClassRef(records, seen, source, target, addr, scope, compactLine);
      }
    }
    while (match = shortClassRe.exec(compactLine)) {
      const target = r2jadxResolveClassName(match[0], source, byQualified, byShort);
      if (target) {
        r2jadxIndexClassRef(records, seen, source, target, addr, scope, compactLine);
      }
    }
    while (match = callRe.exec(compactLine)) {
      const target = r2jadxResolveClassName(match[1], source, byQualified, byShort);
      if (target) {
        r2jadxIndexClassRef(records, seen, source, target, addr, scope, compactLine);
        r2jadxIndexMethodRef(records, seen, target, match[2], addr, scope, compactLine);
      }
    }
    while (match = bareCallRe.exec(compactLine)) {
      r2jadxIndexMethodRef(records, seen, source, match[2], addr, scope, compactLine);
    }
  }
  function r2jadxBuildXrefSymbols(classes) {
    const symbols = [];
    for (const data of classes) {
      const classOffsets = [];
      for (const method of data.methods || []) {
        const range = r2jadxMethodRange(method);
        if (!isNaN(range.min) && !isNaN(range.max)) {
          classOffsets.push(range.min, range.max);
        }
      }
      if (classOffsets.length > 0) {
        symbols.push({
          kind: "class",
          target: r2jadxQualifiedClassName(data),
          min: Math.min(...classOffsets),
          max: Math.max(...classOffsets)
        });
      }
      for (const method of data.methods || []) {
        const range = r2jadxMethodRange(method);
        if (!isNaN(range.min) && !isNaN(range.max)) {
          symbols.push({
            kind: "method",
            target: r2jadxMethodKey(data, method),
            min: range.min,
            max: range.max
          });
        }
      }
    }
    return symbols;
  }
  function r2jadxBuildXrefIndex(classes) {
    const records = [];
    const seen = /* @__PURE__ */ new Set();
    const maps = r2jadxClassMaps(classes);
    for (const source of classes) {
      const scope = r2jadxQualifiedClassName(source);
      for (const importName of r2jadxClassImports(source)) {
        const target = maps.byQualified[importName];
        if (target) {
          r2jadxIndexClassRef(records, seen, source, target, r2jadxClassOffset(source), scope, "import " + importName);
        }
      }
      for (const method of source.methods || []) {
        let lastOffset = parseOffset(method.offset);
        for (const line of method.lines || []) {
          if (line.offset) {
            lastOffset = parseOffset(line.offset);
          }
          r2jadxIndexXrefLine(records, seen, source, method, line.code || "", lastOffset, maps.byQualified, maps.byShort);
        }
      }
    }
    return {
      version: 1,
      symbols: r2jadxBuildXrefSymbols(classes),
      records: records.sort((a, b) => a.target === b.target ? a.addr - b.addr : a.target.localeCompare(b.target))
    };
  }
  function r2jadxXrefIndexPath(target) {
    return pathJoin(target, "r2jadx-xrefs.json");
  }
  function r2jadxReadXrefIndex(indexFile) {
    if (!fileExists(indexFile)) {
      return void 0;
    }
    const data = readFile(indexFile).trim();
    try {
      if (data.length === 0) {
        return void 0;
      }
      const parsed = JSON.parse(data);
      return parsed.version === 1 && Array.isArray(parsed.symbols) && Array.isArray(parsed.records) ? parsed : void 0;
    } catch (e) {
      return void 0;
    }
  }
  function r2jadxLoadXrefIndex(target, classes) {
    const indexFile = r2jadxXrefIndexPath(target);
    const cached = r2jadxReadXrefIndex(indexFile);
    if (cached) {
      return cached;
    }
    const records = r2jadxBuildXrefIndex(classes);
    writeFile(indexFile, JSON.stringify(records));
    return records;
  }
  function r2jadxXrefSymbol(index, context) {
    const methods = index.symbols.filter((symbol) => symbol.kind === "method" && context.offset >= symbol.min && context.offset <= symbol.max);
    if (methods.length > 0) {
      return methods[0];
    }
    return index.symbols.find((symbol) => symbol.kind === "class" && context.offset >= symbol.min && context.offset <= symbol.max);
  }
  function r2jadxXrefLinesFromIndex(index, context) {
    const target = r2jadxXrefSymbol(index, context);
    if (!target) {
      return "";
    }
    let res = "";
    for (const record of index.records) {
      if (record.kind === target.kind && record.target === target.target) {
        res += toPaddedHexString(record.addr, 8) + "	" + record.scope + "	" + record.line + "\n";
      }
    }
    return res;
  }
  function r2jadxXrefLines(target, classes, context) {
    return r2jadxXrefLinesFromIndex(r2jadxLoadXrefIndex(target, classes), context);
  }
  function r2jadxMappedClassFile(target, context) {
    const mapping = JSON.parse(readFile(pathJoin(target, "sources", "mapping.json")));
    let best;
    for (const klass of mapping.classes || []) {
      for (const method of klass.methods || []) {
        const offset = parseOffset(method.offset);
        if (!isNaN(offset) && klass.json && offset <= context.offset && (!best || offset > best.offset)) {
          best = { offset, file: pathJoin(target, "sources", klass.json) };
        }
      }
    }
    return best ? best.file : void 0;
  }
  function r2jadxMappingFile(outdir, level) {
    return pathJoin(outdir, level, "sources", "mapping.json");
  }
  function r2jadxDirectClassFiles(target, context) {
    try {
      const mapped = r2jadxMappedClassFile(target, context);
      if (mapped) {
        return [mapped];
      }
    } catch (e) {
    }
    const classes = [];
    const descriptor = context.functionName.match(/L([^;]+);/);
    if (descriptor) {
      classes.push(descriptor[1]);
    }
    const methodName = context.functionName.match(/([A-Za-z_$][A-Za-z0-9_$.]+)\.(?:method\.)?[A-Za-z_$<][A-Za-z0-9_$<>]*/);
    if (methodName) {
      classes.push(methodName[1].replace(/\./g, "/"));
    }
    const files = [];
    for (const className of classes) {
      const normalized = className.replace(/^L/, "").replace(/;$/, "").replace(/\./g, "/");
      files.push(pathJoin(target, "sources", normalized + ".json"));
      files.push(pathJoin(target, normalized + ".json"));
    }
    return Array.from(new Set(files)).filter(fileExists);
  }
  function r2jadxReadClasses(fileName) {
    const fileData = readFile(fileName);
    const data = JSON.parse(fileData);
    data.source = fileName;
    const classes = [data];
    if (data["inner-classes"]) {
      for (const klass of data["inner-classes"]) {
        klass.source = fileName;
        classes.push(klass);
      }
    }
    return classes;
  }
  function r2jadxProcessClassFile(fileName, mode, context) {
    let res = "";
    for (const klass of r2jadxReadClasses(fileName)) {
      res += processClass(klass, mode, context);
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
  function r2jadxMethodRange(method) {
    const offsets = r2jadxMethodLineOffsets(method);
    if (offsets.length === 0) {
      const offset = parseOffset(method.offset);
      return { min: offset, max: offset };
    }
    return { min: Math.min(...offsets), max: Math.max(...offsets) + 16 };
  }
  function r2jadxMethodContainsOffset(method, offset) {
    const range = r2jadxMethodRange(method);
    return offset >= range.min && offset <= range.max;
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
  function r2jadxMethodLines(method) {
    const lines = [];
    const offset = parseOffset(method.offset);
    const declaration = (method.declaration || method.name).trim().split("\n");
    for (let i = 0; i < declaration.length; i++) {
      const suffix = i === declaration.length - 1 ? " {" : "";
      lines.push({ str: declaration[i] + suffix, offset });
    }
    let lastOffset = offset;
    for (const line of method.lines || []) {
      if (!line.code || line.code.length === 0) {
        continue;
      }
      if (line.offset) {
        lastOffset = parseOffset(line.offset);
      }
      lines.push({ str: r2jadxIndentLine(line.code, 1), offset: lastOffset });
    }
    lines.push({ str: "}" });
    return lines;
  }
  function r2jadxFormatMethodJson(method) {
    return JSON.stringify({ lines: r2jadxMethodLines(method) });
  }
  function processMethod(data, mode, context, method) {
    function comment(addr, line) {
      if (mode === "dc" || mode === "cat") {
        if (!data.source) {
          return "";
        }
        const lastOffset2 = parseOffset(method.offset);
        if (mode === "cat" || mode === "dc" && addr === lastOffset2) {
          const source = data.source.replace(".json", ".java");
          const fileData = readFile(source);
          return fileData.toString();
        }
        return "";
      }
      if (line === "") {
        return "";
      }
      if (mode === "d") {
        return "";
      }
      line = line.replaceAll("	", "  ");
      line = line.replaceAll("\r", "");
      line = line.replaceAll("\n", "");
      line = line.replaceAll(/[^ -~]+/g, "");
      line = line.replaceAll(/^SourceFile:\d+ /g, "");
      const b64line = b64encode(line);
      if (b64line.length > 2048) {
        return "CCu toolong @ " + addr + "\n";
      }
      return "CCu base64:" + b64line + " @ " + addr + "\n";
    }
    let lastOffset = parseOffset(method.offset);
    const lines = method.lines || [];
    if (mode === "d") {
      return r2jadxMethodMatches(data, method, context) ? r2jadxFormatMethod(method) : "";
    }
    if (mode === "dj") {
      return r2jadxMethodMatches(data, method, context) ? r2jadxFormatMethodJson(method) : "";
    }
    if (mode === "d*" && !r2jadxMethodMatches(data, method, context)) {
      return "";
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
    if (mode === "ll" || mode === "hl") {
      let res2 = "";
      if (context.offset === lastOffset) {
        return processMethod(data, "d*", context, method);
      }
      for (const line of lines) {
        if (parseOffset(line.offset) === context.offset - 16) {
          res2 += processMethod(data, "d*", context, method);
        }
      }
      return res2;
    }
    let res = comment(parseOffset(method.offset) + 16, method.name);
    for (const line of lines) {
      const addr = parseOffset(line.offset || lastOffset);
      const code = mode === "d" ? line.code : line.code.trim();
      res += comment(addr, code);
      if (line.offset) {
        lastOffset = parseOffset(line.offset);
      }
    }
    return res;
  }
  function r2jadxCrawlFiles(target, mode, context) {
    const ext = "json";
    const xrefIndexFile = r2jadxXrefIndexPath(target);
    if (mode === "x") {
      const cached = r2jadxReadXrefIndex(xrefIndexFile);
      if (cached) {
        return r2jadxXrefLinesFromIndex(cached, context);
      }
    }
    if (mode === "dc" || mode === "dc*" || mode === "ci" || mode === "d" || mode === "dj" || mode === "d*" || mode === "p") {
      for (const fileName of r2jadxDirectClassFiles(target, context)) {
        try {
          const directRes = r2jadxProcessClassFile(fileName, mode, context);
          if (directRes.length > 0) {
            return directRes;
          }
        } catch (e) {
          console.error("" + fileName + ": " + e);
        }
      }
      return "";
    }
    const files = walkSync(target).filter((_) => _.endsWith && _.endsWith(ext) && _ !== xrefIndexFile && !_.endsWith("/mapping.json"));
    let res = "";
    const classes = [];
    for (const fileName of files) {
      try {
        if (mode === "cat") {
          const fileData = readFile(fileName.replace(".json", ".java"));
          res += fileData;
        } else {
          classes.push(...r2jadxReadClasses(fileName));
        }
      } catch (e) {
        console.error("" + fileName + ": " + e);
      }
    }
    if (mode === "pl") {
      const packages = {};
      for (const data of classes) {
        const packageName = data.package || "";
        const addr = r2jadxClassOffset(data);
        const entry = packages[packageName] || { addr, count: 0 };
        entry.addr = Math.min(entry.addr, addr);
        entry.count++;
        packages[packageName] = entry;
      }
      for (const packageName of Object.keys(packages).sort()) {
        res += r2jadxRecord(packages[packageName].addr, { "kind": "package", "package": packageName, "classes": packages[packageName].count });
      }
      return res;
    }
    if (mode === "pi") {
      const current = classes.find((data) => r2jadxClassMatches(data, context));
      context.packageName = current ? current.package || "" : context.packageName || "";
      const packageImports = {};
      for (const data of classes) {
        if ((data.package || "") !== (context.packageName || "")) {
          continue;
        }
        for (const importName of r2jadxClassImports(data)) {
          const entry = packageImports[importName] || { addr: r2jadxClassOffset(data), count: 0 };
          entry.addr = Math.min(entry.addr, r2jadxClassOffset(data));
          entry.count++;
          packageImports[importName] = entry;
        }
      }
      for (const importName of Object.keys(packageImports).sort()) {
        res += r2jadxRecord(packageImports[importName].addr, {
          "kind": "package_import",
          "package": context.packageName || "",
          "import": importName,
          "import_package": r2jadxImportPackage(importName),
          "classes": packageImports[importName].count
        });
      }
      return res;
    }
    if (mode === "x") {
      return r2jadxXrefLines(target, classes, context);
    }
    for (const data of classes) {
      if (mode === "i") {
        res += r2jadxImportLines(data, false);
      } else {
        res += processClass(data, mode, context);
      }
    }
    return res;
  }
  function r2jadxCrawl(target, mode, context) {
    switch (mode) {
      case "cn":
      case "p":
      case "ci":
      case "d":
      case "dj":
      case "d*":
      case "x":
        return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, context);
      case "i":
      case "pi":
      case "pl":
        return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, context);
      case "dc":
        return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, context);
      case "dc*":
        return r2jadxCrawlFiles(pathJoin(target, "hl"), mode, context);
      case "a":
        return r2jadxCrawlFiles(pathJoin(target, "hl"), "cat", context);
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
  function r2jadxNeedsHighJson(mode) {
    return mode !== "ll" && mode !== "all";
  }
  function r2jadxNeedsHighJava(mode) {
    return mode === "a" || mode === "dc" || mode === "cat";
  }
  function r2jadxNeedsLowJson(mode) {
    return mode === "ll" || mode === "all";
  }
  function r2jadxHasHighJava(outdir) {
    try {
      const mapping = JSON.parse(readFile(r2jadxMappingFile(outdir, "hl")));
      for (const klass of mapping.classes || []) {
        if (klass.json) {
          return fileExists(pathJoin(outdir, "hl", "sources", klass.json.replace(/\.json$/, ".java")));
        }
      }
    } catch (e) {
    }
    return false;
  }
  function r2jadxEnsureDecompiled(target, mode = "d") {
    const outdir = dex2path(target);
    if (r2jadxNeedsLowJson(mode) && !fileExists(r2jadxMappingFile(outdir, "ll"))) {
      console.error("jadx: Performing the low level json decompilation...");
      runCmd(["r2pm", "-r", "jadx", "--output-format", "json", "-m", "simple", "-d", pathJoin(outdir, "ll"), target]);
    }
    if (r2jadxNeedsHighJava(mode) && !r2jadxHasHighJava(outdir)) {
      console.error("jadx: Performing the high level decompilation...");
      runCmd(["r2pm", "-r", "jadx", "--show-bad-code", "--output-format", "java", "-d", pathJoin(outdir, "hl"), target]);
    }
    if (r2jadxNeedsHighJson(mode) && !fileExists(r2jadxMappingFile(outdir, "hl"))) {
      console.error("jadx: Constructing the high level jsons...");
      runCmd(["r2pm", "-r", "jadx", "--show-bad-code", "--output-format", "json", "-d", pathJoin(outdir, "hl"), target]);
    }
    return outdir;
  }
  function r2jadxDecompile(target, mode, context) {
    const outdir = r2jadxEnsureDecompiled(target, mode);
    return r2jadxCrawl(outdir, mode, context);
  }

  // src/search.ts
  function r2jadxQualifiedClassName2(data) {
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
    const className = r2jadxQualifiedClassName2(data);
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
    const files = walkSync(target).filter((_) => _.endsWith && _.endsWith(".json") && !_.endsWith("/mapping.json"));
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

  // src/main.ts
  function r2jadxClearCache(target) {
    runCmd(["rm", "-rf", nospace(dex2path(target))]);
  }
  function r2jadxMain(argv) {
    const firstArg = argv[0] || "";
    if (r2jadxIsHelpArg(firstArg)) {
      r2log(R2JADX_HELP);
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
      const info = r2cmdj("ij");
      const fileName = info.core.file;
      if (!fileName) {
        throw new Error("Cannot find function");
      }
      if (!fileName.endsWith(".dex")) {
        throw new Error("Sorry, this is not a DEX file");
      }
      const context = {
        offset: parseInt(r2cmd("s")),
        functionName: r2cmd("afn.").trim()
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
          r2log("Usage: r2jadx -s text");
          return void 0;
        }
        const res2 = r2jadxSearch(pathJoin(r2jadxEnsureDecompiled(fileName, "s"), "hl"), searchText);
        r2log(r2jadxFormatOutput(res2, mode));
        return res2;
      }
      const res = r2jadxDecompile(fileName, mode, context);
      if (mode.endsWith("*")) {
        for (const line of res.split("\n")) {
          if (line.trim().length > 0) {
            r2cmd(line);
          }
        }
      } else if (mode.endsWith("j")) {
        r2log(res);
      } else {
        r2log(r2jadxFormatOutput(res, mode));
      }
      return res;
    } catch (e) {
      const error = e;
      console.error("Oops", e, error.output ? error.output.toString() : "");
      throw e;
    }
  }
  function r2jadxPdCommand(cmd) {
    const flags = cmd.substring(4).trim();
    if (flags.indexOf("?") !== -1) {
      r2log(R2JADX_HELP);
      return;
    }
    if (flags.indexOf("j") !== -1) {
      r2jadxMain(["-dj"]);
      return;
    }
    if (flags.indexOf("*") !== -1) {
      r2jadxMain(["-d*"]);
      return;
    }
    if (flags.indexOf("=") !== -1 || flags.indexOf("a") !== -1) {
      r2jadxMain(["-a"]);
      return;
    }
    r2jadxWithAddr(flags.indexOf("o") !== -1, () => r2jadxMain(["-d"]));
  }
  function r2jadxBegin() {
    r2unload("core", "r2jadx");
    r2plugin("core", function() {
      function coreCall(cmd) {
        const r2jadxCmd = r2jadxConfig.alias && cmd.startsWith("j-") ? "r2jadx" + cmd.substring(1) : cmd;
        if (r2jadxCmd.startsWith("r2jadx")) {
          const argv = r2jadxCmd.replace(/^r2jadx(?=-)/, "r2jadx ").substring(6).trim().split(" ");
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

  // src/r2jadx.ts
  r2jadxBegin();
})();
