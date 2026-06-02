// Sample file with planted misconfigurations for testing.
const { exec } = require("child_process");
const cors = require("cors");

function runUserCommand(userInput) {
  // Command injection: user input interpolated into a shell string.
  exec(`ls ${userInput}`, (err, stdout) => {
    console.log(stdout);
  });
}

function evaluate(expr) {
  // Arbitrary code execution.
  return eval(expr);
}

// Overly permissive CORS.
const corsOptions = cors({ origin: "*" });

// TLS verification disabled.
const agentOptions = { rejectUnauthorized: false };

module.exports = { runUserCommand, evaluate, corsOptions, agentOptions };
