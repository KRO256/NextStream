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

// ======================
// フォルダ作成
// ======================

const uploadDir = path.join(__dirname, "uploads");
const tempDir = path.join(__dirname, "temp");
const chunksDir = path.join(__dirname, "chunks");

[uploadDir, tempDir, chunksDir].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir);
    }
});

// ======================
// static
// ======================

app.use("/videos", express.static(uploadDir));
app.use(express.static("public"));

// ======================
// multer
// ======================

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

// ======================
// chunk upload
// ======================

app.post("/upload-chunk", upload.single("chunk"), (req, res) => {

    try {

        const {
            fileId,
            chunkIndex,
            totalChunks,
            fileName
        } = req.body;

        const dir = path.join(chunksDir, fileId);

        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir);
        }

        const chunkPath = path.join(dir, String(chunkIndex));

        fs.renameSync(req.file.path, chunkPath);

        const uploadedChunks = fs.readdirSync(dir);

        // 全チャンク受信
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

// ======================
// 動画一覧
// ======================

app.get("/list", (req, res) => {

    const files = fs.readdirSync(uploadDir);

    const videos = files.map(file => ({
        name: file,
        url: "/videos/" + file
    }));

    videos.reverse();

    res.json(videos);
});

// ======================
// 起動
// ======================

app.listen(PORT, () => {
    console.log(`http://localhost:${PORT}`);
});