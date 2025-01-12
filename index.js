const { spawn } = require("child_process");
const path = require('path');

const SCRIPT_FILE = "ddos.js";
const SCRIPT_PATH = path.join(__dirname, SCRIPT_FILE);

const MAX_MEMORY_USAGE = Number.MAX_SAFE_INTEGER || 2000 * 1024 * 1024; // 2000 MB

let mainProcess;

function start() {
    mainProcess = spawn("node", [SCRIPT_PATH], {
        cwd: __dirname,
        stdio: "inherit",
        shell: true
    });

    mainProcess.on("error", (err) => {
        console.error("Error occurred:", err);
    });

    mainProcess.on("close", (exitCode) => {
        if (exitCode === 0) {
            console.log(`STATUS: [${exitCode}] - Process Exited > SYSTEM Rebooting!...`);
            start();
        } else if (exitCode === 1) {
            console.log(`ERROR: [${exitCode}] - System Rebooting!...`);
            start();
        } else if (exitCode === 137) {
            console.log(`POTENTIAL DDOS: [${exitCode}] - Out Of Memory Restarting...`);
            start();
        } else if (exitCode === 134) {
            console.log(`REACHED HEAP LIMIT ALLOCATION: [${exitCode}] - Out Of Memory Restarting...`);
            start();
        } else {
            console.error(`[${exitCode}] - Process Exited!`);
        }
    });

    // Monitor memory usage
    const memoryCheckInterval = setInterval(() => {
        const memoryUsage = process.memoryUsage().heapUsed;
        /*  console.log(`Current memory usage: ${(memoryUsage / 1024 / 1024).toFixed(2)} MB`);*/

        if (memoryUsage > MAX_MEMORY_USAGE) {
            console.error(`Memory usage exceeded ${MAX_MEMORY_USAGE / 1024 / 1024} MB. Restarting server...`);

            // Graceful shutdown procedure
            if (mainProcess && mainProcess.pid) {
                mainProcess.kill('SIGTERM');
                clearInterval(memoryCheckInterval);
            }
        }
    }, 5000);
}

function gracefulShutdown() {
    console.log("Starting graceful shutdown...");
    if (mainProcess && mainProcess.pid) {
        mainProcess.kill('SIGTERM');
    }
}

process.on('SIGINT', () => {
    gracefulShutdown();
    process.exit(0);
});

process.on('SIGTERM', () => {
    gracefulShutdown();
    process.exit(0);
});

start();
