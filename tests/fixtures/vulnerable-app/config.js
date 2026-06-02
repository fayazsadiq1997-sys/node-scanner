// Sample file with planted issues for testing the scanner.
// None of these are real credentials.

const config = {
  awsAccessKey: "AKIAIOSFODNN7EXAMPLE",
  jwt_secret: "supersecretjwtsigningkey123",
  password: "hunter2password",
  apiKey: "abcd1234efgh5678ijkl9012",
};

const endpoint = "http://api.example.com/v1/data";

function makeToken() {
  // Insecure: Math.random for a token value.
  const token = Math.random().toString(36);
  return token;
}

module.exports = { config, endpoint, makeToken };
