const express = require('express');
const path = require('path');
const crypto = require('crypto');
const chalk = require('chalk');
const { encrypt } = require('./helper');
const { kv } = require('@vercel/kv');

const app = express();
const PORT = 3000;

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// --- PENGATURAN DATABASE & MASTER KEY ---
const DB_KEY = 'token_database';
const MASTER_KEY_KEY = 'master_key_server'; 
const JIN_KEY_KEY = 'jin_api_key';

let MASTER_KEY_SERVER;
let JIN_KEY_SERVER;

const buatHashSha256 = (teks) => {
    return crypto.createHash('sha256').update(teks).digest('hex');
};

async function inisialisasiServer() {
    try {
        MASTER_KEY_SERVER = await kv.get(MASTER_KEY_KEY);
        if (MASTER_KEY_SERVER) {
            console.log(chalk.green(`Master Key berhasil dimuat dari '${MASTER_KEY_FILE}'.`));
        } else {
            console.log(chalk.yellow(`Master Key tidak ditemukan. Membuat Master Key baru...`));
            MASTER_KEY_SERVER = crypto.randomBytes(8).toString('hex');
            await kv.set(MASTER_KEY_KEY, MASTER_KEY_SERVER);
            
            console.log(chalk.red.bold("\n==================== PERHATIAN ===================="));
            console.log(chalk.white(`Master Key Anda adalah: ${MASTER_KEY_SERVER}`));
            console.log(chalk.yellow(`CATAT!!! Gunakan Master Key untuk menambah token baru.`));
            console.log(chalk.red.bold("===================================================\n"));
        }

        JIN_KEY_SERVER = process.env.JIN_KEY;
        if (JIN_KEY_SERVER) {
            console.log(chalk.green(`JIN_KEY berhasil dimuat.`));
        } else {
            console.error(chalk.red(`FATAL: Environment Variable 'JIN_KEY' tidak ditemukan!`));
            console.log(chalk.yellow(`Silakan tambahkan JIN_KEY di pengaturan Environment Variables Vercel.`));
            process.exit(1);
        }

        const db = await kv.get(DB_KEY);
        if (!db) {
            console.log(chalk.yellow(`Database token tidak ditemukan. Membuat key '${DB_KEY}' baru.`));
            await kv.set(DB_KEY, {});
        } else {
            console.log(chalk.green(`Database token '${DB_KEY}' berhasil dimuat.`));
        }        
    } catch (error) {
        console.error(chalk.red("FATAL: Gagal menginisialisasi server!"), error);
        process.exit(1);
    }
}

async function readDatabase() {
    try {
        const data = await kv.get(DB_KEY);
        return data || {};
    } catch (error) {
        console.error(chalk.red(`Error membaca database:`), error);
        return {};
    }
}

async function writeDatabase(data) {
    try {
        await kv.set(DB_KEY, data);
    } catch (error) {
        console.error(chalk.red(`Error menulis ke database:`), error);
    }
}

// --- MIDDLEWARE ---
app.use(express.json());
app.get('/', (req, res) => {
    res.render('admin');
});

app.post('/validasi-token', async (req, res) => {
    const hashTokenDariBot = req.body.tokenHash;
    console.log(`Menerima permintaan validasi...`);

    if (!hashTokenDariBot) {
        console.log("-> Permintaan ditolak: token tidak ada.");
        return res.status(400).json({ status: 'error', pesan: 'Token tidak terdaftar.' });
    }

    const db = await readDatabase();

    if (db.hasOwnProperty(hashTokenDariBot)) {
        console.log(chalk.green(`-> Validasi BERHASIL untuk hash: ${hashTokenDariBot.substring(0, 8)}...`));
        
        const sessionSecret = crypto.randomBytes(16).toString('hex');
        db[hashTokenDariBot].terakhirDilihat = new Date().toISOString(); 
        await writeDatabase(db);
        
        const payload = { 
            status: 'ok',
            session_secret: sessionSecret,
            jin_key: JIN_KEY_SERVER
        };
        const encryptedPayload = encrypt(JSON.stringify(payload));
        res.json({ payload: encryptedPayload });
    } else {
        console.log(chalk.red(`-> Validasi GAGAL untuk hash: ${hashTokenDariBot.substring(0, 8)}...`));
        res.json({ status: 'ditolak' });
    }
});

app.post('/heartbeat', async (req, res) => {
    const hashTokenDariBot = req.body.tokenHash;
    const db = await readDatabase();

    if (db.hasOwnProperty(hashTokenDariBot)) {
        const newSessionSecret = crypto.randomBytes(16).toString('hex');
        db[hashTokenDariBot].terakhirDilihat = new Date().toISOString(); // Update lagi
        await writeDatabase(db);
        
        const payload = { 
            status: 'ok',
            session_secret: newSessionSecret 
        };
        const encryptedPayload = encrypt(JSON.stringify(payload));
        res.json({ payload: encryptedPayload });
    } else {
        console.log(chalk.red(`-> Heartbeat GAGAL: Token ${hashTokenDariBot.substring(0, 8)}... telah dihapus.`));
        res.json({ status: 'ditolak' });
    }
});

app.post('/addtoken', async (req, res) => {
    const { tokenAsli, masterKey } = req.body;

    if (masterKey !== MASTER_KEY_SERVER) {
        console.warn(chalk.red("PERINGATAN: Upaya menambah token GAGAL (Master key salah)."));
        return res.status(401).json({ status: 'error', pesan: 'Akses ditolak.' });
    }
    
    if (!tokenAsli) {
        return res.status(400).json({ status: 'error', pesan: 'tokenHash diperlukan.' });
    }
    const hashToken = buatHashSha256(tokenAsli);
  
    const db = await readDatabase();

    if (db.hasOwnProperty(hashToken)) {
        console.log(chalk.yellow(`Token ${hashToken.substring(0, 8)}... sudah ada di database.`));
        return res.status(409).json({ status: 'error', pesan: 'Token hash ini sudah ada.' });
    }

    db[hashToken] = {
        ditambahkan: new Date().toISOString(),
        terakhirDilihat: null
    };

    await writeDatabase(db);

    console.log(chalk.green(`BERHASIL: Token ${hashToken.substring(0, 8)}... telah ditambahkan.`));
    res.json({ 
        status: 'ok', 
        pesan: `Token hash ${hashToken.substring(0, 8)}... berhasil ditambahkan.` 
    });
});

app.listen(PORT, async () => {
    await inisialisasiServer();
    console.log(chalk.blue(`🚀 Server aktivasi berjalan di port ${PORT}`));
});

module.exports = app;
