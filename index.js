const { spawn } = require("child_process");
const path = require('path');

const SCRIPT_FILE = "kokoro.js";
const SCRIPT_PATH = path.join(__dirname, SCRIPT_FILE);

// Set the memory limit to 100% of 8 GB (10,240 MB)
const MAX_MEMORY_THRESHOLD = 8 * 1024 * 1024 * 1024; 
let mainProcess;

function calculateMaxMemoryUsage() {
    let newMemoryLimit = MAX_MEMORY_THRESHOLD;

    // Return memory in MB (convert bytes to MB)
    return Math.floor(newMemoryLimit / 1024 / 1024);
}

function start() {
    const memoryLimitMB = calculateMaxMemoryUsage();
    console.log(`Allocating ${memoryLimitMB} MB of memory for the Node.js process`);

    mainProcess = spawn("node", [`--max-old-space-size=${memoryLimitMB}`, SCRIPT_PATH], {
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
        if (memoryUsage > MAX_MEMORY_THRESHOLD) {
            console.error(`Memory usage exceeded threshold. Restarting server...`);

            // No graceful shutdown, just restart
            if (mainProcess && mainProcess.pid) {
                mainProcess.kill('SIGKILL');
                clearInterval(memoryCheckInterval);
                start(); // Restart process
            }
        }
    }, 5000);
}

start();
