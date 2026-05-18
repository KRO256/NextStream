const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = 3000;

app.use(express.json({ limit: "1gb" }));

app.use(express.urlencoded({
    extended: true,
    limit: "1gb"
}));

const uploadDir = path.join(__dirname, "uploads");
const tempDir = path.join(__dirname, "temp");
const chunksDir = path.join(__dirname, "chunks");
const metadataPath = path.join(__dirname, "videos.json");

[uploadDir, tempDir, chunksDir].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir);
    }
});

function loadMetadata() {
    try {
        return JSON.parse(fs.readFileSync(metadataPath, "utf8"));
    } catch {
        return {};
    }
}

function saveMetadata(data) {
    fs.writeFileSync(metadataPath, JSON.stringify(data, null, 2));
}

app.use("/videos", express.static(uploadDir));
app.use(express.static("public"));

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, tempDir);
    },

    filename: (req, file, cb) => {
        cb(null, Date.now() + "_" + Math.random());
    }
});

const upload = multer({
    storage,

    limits: {
        fileSize: 10 * 1024 * 1024
    }
});

app.post("/upload-chunk", upload.single("chunk"), (req, res) => {

    try {

        const {
            fileId,
            chunkIndex,
            totalChunks,
            fileName,
            title
        } = req.body;

        const dir = path.join(chunksDir, fileId);

        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir);
        }

        const chunkPath = path.join(dir, String(chunkIndex));

        fs.renameSync(req.file.path, chunkPath);

        const uploadedChunks = fs.readdirSync(dir);

        if (uploadedChunks.length == totalChunks) {

            const safeName =
                Date.now() +
                "_" +
                fileName.replace(/[^a-zA-Z0-9._-]/g, "_");

            const finalPath = path.join(uploadDir, safeName);

            const writeStream = fs.createWriteStream(finalPath);

            for (let i = 0; i < totalChunks; i++) {

                const chunkFile = path.join(dir, String(i));

                const chunkData = fs.readFileSync(chunkFile);

                writeStream.write(chunkData);
            }

            writeStream.end();

            writeStream.on("finish", () => {

                fs.rmSync(dir, {
                    recursive: true,
                    force: true
                });

                const metadata = loadMetadata();
                metadata[safeName] = { title: title || safeName };
                saveMetadata(metadata);

                console.log("UPLOAD COMPLETE:", safeName);
            });
        }

        res.json({
            success: true
        });

    } catch (err) {

        console.error(err);

        res.status(500).json({
            success: false,
            error: err.message
        });
    }
});

app.patch("/video/:filename", (req, res) => {

    try {

        const { title } = req.body;

        const metadata = loadMetadata();

        if (metadata[req.params.filename]) {

            metadata[req.params.filename].title = title;

            saveMetadata(metadata);

            res.json({ success: true });

        } else {

            res.status(404).json({
                success: false,
                error: "Video not found"
            });
        }

    } catch (err) {

        res.status(500).json({
            success: false,
            error: err.message
        });
    }
});

app.get("/list", (req, res) => {

    const files = fs.readdirSync(uploadDir);

    const metadata = loadMetadata();

    const videos = files.map(file => ({
        name: file,
        url: "/videos/" + file,
        title: metadata[file]?.title || file
    }));

    videos.reverse();

    res.json(videos);
});

app.listen(PORT, () => {
    console.log(`http://localhost:${PORT}`);
});