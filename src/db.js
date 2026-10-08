const { MongoClient } = require('mongodb');

const DB_NAME = process.env.MONGODB_DB || 'hirafi';
const COLS = ['craftsmen', 'customers', 'appointments', 'events'];
const SORT = {
    craftsmen: { createdAt: -1, _id: -1 },
    customers: { createdAt: -1, _id: -1 },
    appointments: { createdAt: -1, _id: -1 },
    events: { at: -1, _id: -1 }
};

/* Reuse the connection between requests (important on Vercel serverless) */
const g = global._hirafiMongo || (global._hirafiMongo = { promise: null });

const getDb = () => {
    if (!g.promise) {
        const uri = process.env.MONGODB_URI;
        if (!uri) return Promise.reject(new Error('MONGODB_URI is not set'));
        const client = new MongoClient(uri, { serverSelectionTimeoutMS: 8000, maxPoolSize: 5 });
        g.promise = client.connect().then(c => c.db(DB_NAME)).catch(e => { g.promise = null; throw e; });
    }
    return g.promise;
};

/* Read all collections. Keeps a hidden snapshot so save() writes only what changed. */
const load = async () => {
    const db = await getDb();
    const d = {}, snap = {};
    await Promise.all(COLS.map(async c => {
        const docs = await db.collection(c).find({}).sort(SORT[c]).toArray();
        snap[c] = {};
        d[c] = docs.map(({ _id, ...rest }) => {
            rest.id = rest.id || String(_id);
            snap[c][rest.id] = JSON.stringify(rest);
            return rest;
        });
    }));
    Object.defineProperty(d, '__snap', { value: snap, enumerable: false, writable: true });
    return d;
};

/* Write only new / changed / removed items */
const save = async d => {
    const db = await getDb();
    const snap = d.__snap || {};
    const next = {};
    await Promise.all(COLS.map(async c => {
        const prev = snap[c] || {}, ops = [], seen = new Set();
        next[c] = {};
        for (const item of d[c] || []) {
            const s = JSON.stringify(item);
            seen.add(item.id);
            next[c][item.id] = s;
            if (prev[item.id] !== s) ops.push({ replaceOne: { filter: { _id: item.id }, replacement: { ...item }, upsert: true } });
        }
        for (const k in prev) if (!seen.has(k)) ops.push({ deleteOne: { filter: { _id: k } } });
        if (ops.length) await db.collection(c).bulkWrite(ops, { ordered: false });
    }));
    Object.defineProperty(d, '__snap', { value: next, enumerable: false, writable: true });
};

const id = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
const log = (d, type, text) => { d.events.unshift({ id: id(), type, text, at: new Date().toISOString() }); d.events = d.events.slice(0, 100); };

/* Admin login brute-force protection (stored in MongoDB, works across serverless instances) */
const WINDOW = 6e5;
const getFail = async ip => (await getDb()).collection('fails').findOne({ _id: String(ip) });
const addFail = async ip => {
    const col = (await getDb()).collection('fails'), f = await col.findOne({ _id: String(ip) });
    const n = (f && Date.now() - f.t < WINDOW ? f.n : 0) + 1;
    await col.updateOne({ _id: String(ip) }, { $set: { n, t: Date.now() } }, { upsert: true });
};
const clearFail = async ip => (await getDb()).collection('fails').deleteOne({ _id: String(ip) });

const ping = async () => (await getDb()).command({ ping: 1 });

module.exports = { load, save, id, log, getFail, addFail, clearFail, ping };