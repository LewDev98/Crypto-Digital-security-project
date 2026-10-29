// Shared test setup: isolated database and a fixed secret. Import this first in every test file.
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
process.env.BG_NO_DOTENV = '1'; // never load your real .env (and real API keys) during tests
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bg-test-'));
process.env.DB_FILE = path.join(dir, 'test.db');
process.env.DATA_DIR = dir;
process.env.APP_SECRET = 'test-secret-test-secret-test-secret-123';
process.env.NO_JOBS = '1';
process.env.ANTHROPIC_API_KEY = '';
process.env.TELEGRAM_BOT_TOKEN = '';
process.env.RESEND_API_KEY = '';
