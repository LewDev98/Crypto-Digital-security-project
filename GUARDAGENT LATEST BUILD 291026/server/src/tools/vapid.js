// npm run vapid  -> prints a key pair for web push alerts. Put them in .env.
import { generateVapidKeys } from '../lib/webpush.js';
const k = generateVapidKeys();
console.log(`VAPID_PUBLIC_KEY=${k.publicKey}\nVAPID_PRIVATE_KEY=${k.privateKey}`);
