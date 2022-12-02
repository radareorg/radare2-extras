import { Configuration, OpenAIApi } from "openai";
const r2pipe = require ("r2pipe");
// import { open, r2node } from "r2pipe"; /// XXX we need types!

const useTTS = process.env.R2AI_TTS === '1';

const configuration = new Configuration({
    organization: "org-ges0Q9PvVCq5zJEpqwVgM6YC",
    apiKey: process.env.OPENAI_API_KEY,
});
async function main() {
	const openai = new OpenAIApi(configuration);
	const response = await openai.listEngines();
	var r2 = r2pipe.open()
	const input = "Can you explain what this decompiled function do?\n```c\n" + r2.cmd("af;pdc") + "\n```\n";
	const completion = await openai.createCompletion({
		model: "text-davinci-002",
		prompt: input,
	});
	const text = completion.data.choices[0].text;
	if (useTTS) {
		const filtered = text.replace(/[\n\*"]/, '');
		console.log(r2.cmd("\"?E " + text + "\""));
		r2.cmd("\"!say " + text + "\"");
	} else {
		console.log(text);
	}
}
main().then(function() {}).catch(function(err) {
	console.error(err.toString());
});
