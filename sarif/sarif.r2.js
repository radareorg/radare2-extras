const sarifTemplate = {
  "$schema": "http://json.schemastore.org/sarif-2.1.0",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "radare2",
          "semanticVersion": "1.0.0",
          "rules": [
          ]
        }
      },
      "results": [
      ]
    }
  ]
};

class R2Sarif {
	constructor() {
		this.doc = sarifTemplate;
	}
	addRule(id, description, helpUri) {
		if (this.doc.runs[0].tool.driver.rules.filter((x) => x.id === id).length !== 0) {
			return false;
		}	
		const rule = {
			"id": id,
			"shortDescription": {
				"text": description
			},
			"helpUri": helpUri
		}
		this.doc.runs[0].tool.driver.rules.push (rule);
		return true;
	}
	addRuleOverflow() {
		const ruleId = "VULN-OVERFLOW";
		this.addRule(ruleId, "Potential Buffer overflow",
				"http://example.com/vulnerability/EXAMPLE-VULN-001");
		return ruleId;
	}
	addResultOverflow(artifact, locations) {
		const ruleId = this.addRuleOverflow();
		this.addResult (ruleId, "error", "Buffer overflow detected", artifact, locations);
	}
	addResult(ruleId, level, message, artifact, locations) {
		const sarifLocations = [];
		const result = {
			"ruleId": ruleId,
			"level": level,
			"message": {
				"text": message
			},
			"locations": []
		};
		const locationTemplate = {
			"physicalLocation": {
				"artifactLocation": {
					"uri": "binary://" + artifact,
					"uriBaseId": "%SRCROOT%"
				},
				"region": {
					"startByteOffset": locations,
					"byteLength": 128
				}
			},
			"properties": {
				"memoryAddress": "0x0040321A"
			}
		}
		for (let loc of locations) {
			const myLoc = locationTemplate;
			myLoc.physicalLocation.region = {
				startByteOffset: loc.pa,
				byteLength: loc.sz,
			}
			myLoc.properties = {
				memoryAddress: loc.va
			};
			result.locations.push(myLoc);
		}
		this.doc.runs[0].results.push(result);
	}
	toString() {
		return JSON.stringify(this.doc);
	}
	toScript() {
		let script = "";
		const results = this.doc.runs[0].results;
		let counter = 0;
		for (let res of results) {
			const text = res.message.text;
			for (let loc of res.locations) {
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


const s = new R2Sarif();
s.addResultOverflow('/bin/ls', [
		{ va: 0x804804, pa: 0x804, sz: 32 }
]);

console.log(s.toString());
console.log(s.toScript());
