const Hashids = require('hashids');

const hashids = new Hashids('morti-projects-2026', 8);

function encodeProjectId(id) {
  return hashids.encode(Number(id));
}

function resolveProjectId(val) {
  if (!val) return val;
  if (/^\d+$/.test(val)) return val;
  const decoded = hashids.decode(val);
  return decoded.length ? decoded[0].toString() : val;
}

module.exports = { hashids, encodeProjectId, resolveProjectId };
