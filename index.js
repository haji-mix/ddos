const { spawn } = require("child_process");
const path = require("path");
const { execSync } = require("child_process");

const SCRIPT_FILE = "ddos.js";
const SCRIPT_PATH = path.join(__dirname, SCRIPT_FILE);

const npmPackages = [];

const restartEnabled = process.env.PID !== "0";

let mainProcess;

function isPackageUpToDate(pkg) {
    const [packageName] = pkg.split("@");
    try {
        const localVersion = execSync(`npm list ${packageName} --depth=0 --json`, { cwd: __dirname, encoding: "utf8" });
        const installedVersion = JSON.parse(localVersion).dependencies[packageName]?.version;

        if (installedVersion) {
            const latestVersion = execSync(`npm show ${packageName} version`, { encoding: "utf8" }).trim();
            return installedVersion === latestVersion;
        }
    } catch (err) {
        return false;
    }
    return false;
}

function installPackages(callback) {
    console.log("Checking npm packages...");

    let installCount = 0;
    let totalPackages = npmPackages.length;

    npmPackages.forEach((pkg) => {
        if (isPackageUpToDate(pkg)) {
            console.log(`Package ${pkg} is already up to date.`);
            installCount++;
            if (installCount === totalPackages) callback();
            return;
        }

        console.log(`Installing package: ${pkg}...`);

        const installProcess = spawn("npm", ["install", pkg], {
            cwd: __dirname,
            stdio: "inherit",
            shell: true,
        });

        installProcess.on("error", (err) => {
            console.error(`Error installing package ${pkg}:`, err);
        });

        installProcess.on("close", (exitCode) => {
            installCount++;
            if (exitCode !== 0) {
                console.error(`Failed to install package ${pkg} with exit code [${exitCode}]`);
            } else {
                console.log(`Package ${pkg} installed successfully.`);
            }

            if (installCount === totalPackages) callback();
        });
    });
}

function start() {
    console.log("Starting main process...");

    mainProcess = spawn("node", ["--no-warnings", SCRIPT_PATH], {
        cwd: __dirname,
        stdio: "inherit",
        shell: true,
    });

    mainProcess.on("error", (err) => {
        console.error("Error occurred while starting the process:", err);
    });

    mainProcess.on("close", (exitCode) => {
        console.log(`Process exited with code [${exitCode}]`);
        if (restartEnabled) {
            console.log("Restarting process...");
            restartProcess();
        } else {
            console.log("Shutdown initiated...");
            process.exit(exitCode);
        }
    });
}

function restartProcess() {
    if (mainProcess && mainProcess.pid) {
        mainProcess.kill("SIGKILL");
        console.log("Main process killed. Restarting...");
    }
    start();
}

installPackages(start);
