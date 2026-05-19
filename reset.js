const fs = require("fs");
const path = require("path");

const dataFiles = [
    "users.json",
    "videos.json",
    "comments.json",
    "subscriptions.json",
    "views.json",
    "bookmarks.json"
];

const dirsToClean = [
    "uploads",
    path.join("uploads", "hls"),
    "temp",
    "chunks"
];

for (const file of dataFiles) {
    fs.writeFileSync(path.join(__dirname, file), "{}\n");
    console.log("  \u2713", file, "reset");
}

for (const dir of dirsToClean) {
    const dirPath = path.join(__dirname, dir);
    if (fs.existsSync(dirPath)) {
        const entries = fs.readdirSync(dirPath);
        for (const entry of entries) {
            const entryPath = path.join(dirPath, entry);
            fs.rmSync(entryPath, { recursive: true, force: true });
        }
        console.log("  \u2713", dir + "/", "cleaned");
    } else {
        fs.mkdirSync(dirPath, { recursive: true });
        console.log("  \u2713", dir + "/", "created");
    }
}

console.log("\nReset complete. All data has been cleared.");
