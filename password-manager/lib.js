function encode(data) {
  return Buffer.from(data, "utf-8");
}

function decode(data) {
  return Buffer.from(data).toString("utf-8");
}

module.exports = { encode, decode };
