// tools/testdata/node_driver.js
//
// Drives Rapyd's REAL, verbatim, unedited official sign-node.js
// (fetched from Rapyd-Samples/rapyd-api-signature-snippets, saved
// alongside this file as tools/testdata/sign-node.js) against a fixed
// set of test vectors, and prints one JSON object per line to stdout.
//
// This is the cross-validation oracle for tests/test_rapyd_sign.py: no
// official worked input->output example exists anywhere in Rapyd's repo
// or docs (confirmed by direct fetch, not assumed), so instead of
// trusting a second manual transcription of the algorithm, the Python
// port is diffed byte-for-byte against this real official code running
// for real, via a local `node` binary, on the SAME fixed inputs.
//
// No network access — sign-node.js's generateSignature() is pure/local
// (just crypto.createHmac), so requiring and calling it here touches
// nothing but this file and sign-node.js.

// sign-node.js (as fetched from Rapyd's repo) declares generateSignature
// as a bare top-level function with no module.exports -- require()-ing
// it directly would just return {} (Node's default module.exports),
// silently giving `generateSignature: undefined` rather than a load
// error. Rather than editing that file (it must stay byte-for-byte what
// was fetched, so a diff against the repo is always possible), load its
// source text and run it in its own VM context, appending the export
// statement to the code handed to vm.runInContext() only -- the string
// in memory here, never the file on disk.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const srcPath = path.join(__dirname, "sign-node.js");
const src = fs.readFileSync(srcPath, "utf8");
const sandbox = { module: { exports: {} }, require, console, Buffer };
vm.createContext(sandbox);
vm.runInContext(src + "\nmodule.exports = { generateSignature };", sandbox, {
    filename: srcPath,
});
const { generateSignature } = sandbox.module.exports;
if (typeof generateSignature !== "function") {
    throw new Error("failed to load generateSignature from sign-node.js");
}

const cases = [
    {
        name: "empty_body_get",
        httpMethod: "GET",
        urlPath: "/v1/data/countries",
        salt: "abcd1234",
        timestamp: "1700000000",
        accessKey: "test_access_key_fixture",
        secretKey: "test_secret_key_fixture",
        body: null,
    },
    {
        name: "json_body_post",
        httpMethod: "POST",
        urlPath: "/v1/checkout",
        salt: "Xy9Zq2Ab7Lm1",
        timestamp: "1700000042",
        accessKey: "test_access_key_fixture",
        secretKey: "test_secret_key_fixture",
        // Key order here is deliberate: JSON.stringify preserves object
        // literal insertion order, and the Python side must serialize
        // its own equivalent object in this exact order (with no extra
        // whitespace, i.e. separators=(",", ":")) to land on the same
        // body string. Test harness owns keeping these in sync — see
        // test_rapyd_sign.py's FIXTURES.
        body: { amount: 100, currency: "USD", country: "US" },
    },
    {
        name: "mixed_case_method_and_path_with_query",
        httpMethod: "GeT",
        urlPath: "/v1/checkout/client/checkout_deadbeefdeadbeefdeadbeefdeadbeef?expand=payment",
        salt: "9",
        timestamp: "1",
        accessKey: "ak",
        secretKey: "sk",
        body: null,
    },
];

for (const c of cases) {
    const signature = generateSignature(
        c.httpMethod,
        c.urlPath,
        c.salt,
        c.timestamp,
        c.accessKey,
        c.secretKey,
        c.body
    );
    console.log(JSON.stringify({ name: c.name, signature }));
}
