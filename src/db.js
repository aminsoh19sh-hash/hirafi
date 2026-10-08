const fs = require('fs'), path = require('path');
const F = path.join(__dirname, '../data/db.json');
const load = () => { const d = JSON.parse(fs.readFileSync(F, 'utf8')); d.customers = d.customers || []; return d; };
const save = d => fs.writeFileSync(F, JSON.stringify(d, null, 2));
const id = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
const log = (d, type, text) => { d.events.unshift({ id: id(), type, text, at: new Date().toISOString() }); d.events = d.events.slice(0, 100); };
module.exports = { load, save, id, log };
