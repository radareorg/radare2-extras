const sarifTemplate = {
  $schema: 'http://json.schemastore.org/sarif-2.1.0',
  version: '2.1.0',
  runs: [
    {
      tool: {
        driver: {
          name: 'radare2',
          semanticVersion: '1.0.0',
          rules: [
          ]
        }
      },
      results: [
      ]
    }
  ]
};

class R2Sarif {
  constructor () {
    this.doc = sarifTemplate;
  }

  addRule (id, description, helpUri) {
    if (this.doc.runs[0].tool.driver.rules.filter((x) => x.id === id).length !== 0) {
      return false;
    }
    const rule = {
      id: id,
      shortDescription: {
        text: description
      },
      helpUri: helpUri
    };
    this.doc.runs[0].tool.driver.rules.push(rule);
    return true;
  }

  reset () {
    this.doc.runs[0].results = [];
    this.doc.runs[0].tool.driver.rules = [];
  }

  addRuleOverflow () {
    const ruleId = 'VULN-OVERFLOW';
    this.addRule(ruleId, 'Potential Buffer Overflow',
      'http://example.com/vulnerability/EXAMPLE-VULN-001');
    return ruleId;
  }

  addRuleWeakCrypto () {
    const ruleId = 'VULN-WEAKCRYPTO';
    this.addRule(ruleId, 'Weak Crypto Usage',
      'http://example.com/vulnerability/EXAMPLE-VULN-002');
    return ruleId;
  }

  addResultWeakCrypto (artifact, comment, locations) {
    const ruleId = this.addRuleWeakCrypto();
    this.addResult(ruleId, 'error', comment, artifact, locations);
  }

  addResultOverflow (artifact, comment, locations) {
    const ruleId = this.addRuleOverflow();
    this.addResult(ruleId, 'error', comment, artifact, locations);
  }

  addResult (ruleId, level, message, artifact, locations) {
    const sarifLocations = [];
    const result = {
      ruleId: ruleId,
      level: level,
      message: {
        text: message
      },
      locations: []
    };
    const locationTemplate = {
      physicalLocation: {
        artifactLocation: {
          uri: 'binary://' + artifact,
          uriBaseId: '%SRCROOT%'
        },
        region: {
          startByteOffset: locations,
          byteLength: 128
        }
      },
      properties: {
        memoryAddress: '0x0040321A'
      }
    };
    for (const loc of locations) {
      const myLoc = locationTemplate;
      myLoc.physicalLocation.region = {
        startByteOffset: loc.pa,
        byteLength: loc.sz
      };
      myLoc.properties = {
        memoryAddress: loc.va
      };
      result.locations.push(myLoc);
    }
    this.doc.runs[0].results.push(result);
  }

  toString () {
    return JSON.stringify(this.doc, null, 2) + '\n';
  }

  toScript () {
    let script = '# r2sarif script\n';
    const results = this.doc.runs[0].results;
    let counter = 0;
    for (const res of results) {
      const text = res.message.text;
      for (const loc of res.locations) {
        console.log(JSON.stringify(res));
        const address = loc.properties.memoryAddress;
        const size = loc.physicalLocation.region.byteLength;
        script += `CC ${text} @ ${address}\n`;
        script += `f bug.${counter} ${size} ${address}\n`;
        counter++;
      }
    }
    return script;
  }
}

function sarifTest () {
  const s = new R2Sarif();
  s.addResultOverflow('/bin/ls', 'buffer overflow detected', [
    { va: 0x804804, pa: 0x804, sz: 32 }
  ]);
  console.log(s.toString());
  console.log(s.toScript());
}

function sarifRegisterPlugin () {
  const sarif = new R2Sarif();
  function sarifCommand (args) {
    function sarifHelp () {
      console.log('sarif [action] [arguments]');
      console.log('sarif help          - show this help message');
      console.log('sarif import [file] - import sarif info from given file');
      console.log('sarif export [file] - export sarif findings into given file or stdout');
      console.log('sarif script        - generate r2 script with loaded sarif info');
      console.log('sarif reset         - reset all loaded sarif reports');
    }
    function sarifImport (fileName) {
      console.log('Importing from ' + fileName);
    }
    function sarifExport (fileName) {
      console.log(fileName);
      if (fileName === '') {
        console.log(sarif.toString());
      } else {
        console.log('Exporting to ' + fileName);
      }
    }
    function sarifScript (fileName) {
      console.log(sarif.toScript());
    }
    function sarifAdd (args) {
      if (args === "") {
	console.log("");
      }
      console.log(args);
    }
    let arg = args.substr('sarif'.length).trim();
    const space = arg.indexOf(' ');
    let action = arg.trim();
    if (space !== -1) {
      action = arg.substr(0, space);
      arg = arg.substr(space + 1);
    } else {
      arg = '';
    }
    switch (action) {
      case '':
      case '?':
      case '-h':
      case 'help':
        sarifHelp();
        break;
      case '-a':
      case 'add':
        sarifAdd(arg);
        break;
      case '-i':
      case 'import':
        sarifImport(arg);
        break;
      case '-e':
      case 'export':
        sarifExport(arg);
        break;
      case '*':
      case '-r':
      case 'r2':
      case 'script':
        sarifScript(arg);
        break;
      default:
        console.error('Unknown action');
        break;
    }
  }
  r2.unload('core', 'sarif');
  r2.plugin('core', function () {
    function coreCall (cmd) {
      if (cmd.startsWith('sarif')) {
        sarifCommand(cmd);
        return true;
      }
      return false;
    }
    return {
      name: 'sarif',
      license: 'MIT',
      desc: 'support importing and exporting sarif format',
      call: coreCall
    };
  });
}
sarifRegisterPlugin();
