/* ------------------------------------------------------------------
   src/db.js — MongoDB Atlas version
   Keeps the same API as the old JSON-file version:
     load()  → returns { craftsmen, customers, appointments, events }
     save(d) → persists the whole document
     id()    → unique id string
     log(d, type, text) → appends an event (mutated d is saved by save())
     init()  → connects to Mongo and loads the state into memory
   ------------------------------------------------------------------ */
const { MongoClient } = require('mongodb');
const crypto = require('crypto');

const URI = process.env.MONGO_URI;
if (!URI) {
    console.error('✖ MONGO_URI is not set. Add it in Vercel → Settings → Environment Variables.');
    process.exit(1);
}

const DB_NAME = process.env.MONGO_DB || 'hirafi';
const COLL = 'state';
const DOC_ID = 'main';

/* Single shared client across invocations (important on Vercel) */
let clientPromise = null;
function getClient() {
    if (!clientPromise) {
        const c = new MongoClient(URI, { maxPoolSize: 5 });
        clientPromise = c.connect();
    }
    return clientPromise;
}

/* In-memory mirror so the synchronous API used by server.js still works */
let cache = null;

const emptyDoc = () => ({
    _id: DOC_ID,
    craftsmen: [],
    customers: [],
    appointments: [],
    events: []
});

/* Load from Mongo into the in-memory cache (called once per cold start) */
async function init() {
    if (cache) return;
    const client = await getClient();
    const col = client.db(DB_NAME).collection(COLL);
    let doc = await col.findOne({ _id: DOC_ID });
    if (!doc) {
        doc = emptyDoc();
        await col.insertOne(doc);
    }
    cache = doc;
}

/* ---------- Public sync API (same as before) ---------- */
function load() {
    if (!cache) throw new Error('DB not initialised — call init() first');
    return cache;
}

function save(d) {
    cache = d;
    /* Fire-and-forget write. server.js calls save() synchronously; we
       persist to Mongo in the background. */
    (async () => {
        try {
            const client = await getClient();
            const col = client.db(DB_NAME).collection(COLL);
            const { _id, ...rest } = d;
            await col.updateOne(
                { _id: DOC_ID },
                { $set: rest },
                { upsert: true }
            );
        } catch (e) {
            console.error('Mongo save error:', e.message);
        }
    })();
}

function id() {
    return crypto.randomBytes(12).toString('hex');
}

function log(d, type, text) {
    d.events.unshift({
        id: id(),
        type,
        text,
        at: new Date().toISOString()
    });
    if (d.events.length > 500) d.events.length = 500;
}

module.exports = { load, save, id, log, init };