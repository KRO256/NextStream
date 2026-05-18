const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();
const PORT = 3000;

app.use(express.json({ limit: "1gb" }));

app.use(express.urlencoded({
    extended: true,
    limit: "1gb"
}));

app.use(session({
    secret: "nextstream-secret-key-change-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

const uploadDir = path.join(__dirname, "uploads");
const tempDir = path.join(__dirname, "temp");
const chunksDir = path.join(__dirname, "chunks");
const metadataPath = path.join(__dirname, "videos.json");
const usersPath = path.join(__dirname, "users.json");

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

function loadUsers() {
    try {
        return JSON.parse(fs.readFileSync(usersPath, "utf8"));
    } catch {
        return {};
    }
}

function saveUsers(data) {
    fs.writeFileSync(usersPath, JSON.stringify(data, null, 2));
}

function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, error: "ログインが必要です" });
    }
    next();
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

app.post("/api/register", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ success: false, error: "ユーザー名とパスワードを入力してください" });
        }

        if (username.length < 3 || username.length > 20) {
            return res.status(400).json({ success: false, error: "ユーザー名は3〜20文字で入力してください" });
        }

        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            return res.status(400).json({ success: false, error: "ユーザー名は英数字とアンダースコアのみ使用できます" });
        }

        if (password.length < 6) {
            return res.status(400).json({ success: false, error: "パスワードは6文字以上で入力してください" });
        }

        const users = loadUsers();

        if (users[username]) {
            return res.status(409).json({ success: false, error: "このユーザー名は既に使用されています" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        users[username] = { password: hashedPassword, createdAt: new Date().toISOString() };
        saveUsers(users);

        req.session.userId = username;
        res.json({ success: true, user: username });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post("/api/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ success: false, error: "ユーザー名とパスワードを入力してください" });
        }

        const users = loadUsers();
        const user = users[username];

        if (!user) {
            return res.status(401).json({ success: false, error: "ユーザー名またはパスワードが間違っています" });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ success: false, error: "ユーザー名またはパスワードが間違っています" });
        }

        req.session.userId = username;
        res.json({ success: true, user: username });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post("/api/logout", (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get("/api/me", (req, res) => {
    if (req.session.userId) {
        res.json({ success: true, user: req.session.userId });
    } else {
        res.json({ success: false, user: null });
    }
});

app.delete("/api/account", requireAuth, async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) {
            return res.status(400).json({ success: false, error: "パスワードを入力してください" });
        }

        const users = loadUsers();
        const user = users[req.session.userId];

        if (!user) {
            return res.status(404).json({ success: false, error: "ユーザーが見つかりません" });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ success: false, error: "パスワードが間違っています" });
        }

        delete users[req.session.userId];
        saveUsers(users);

        req.session.destroy();
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post("/upload-chunk", requireAuth, upload.single("chunk"), (req, res) => {

    try {

        const {
            fileId,
            chunkIndex,
            totalChunks,
            fileName,
            title,
            tags
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

                if (title && title.length > 100) {
                    return res.status(400).json({ success: false, error: "タイトルは100文字以内で入力してください" });
                }

                const tagList = tags
                    ? tags.split(",").map(t => t.trim()).filter(Boolean)
                    : [];
                if (tagList.some(t => t.length > 20)) {
                    return res.status(400).json({ success: false, error: "各タグは20文字以内で入力してください" });
                }
                if (tagList.length > 10) {
                    return res.status(400).json({ success: false, error: "タグは最大10個までです" });
                }
                metadata[safeName] = {
                    title: title || safeName,
                    tags: tagList,
                    uploadedBy: req.session.userId
                };
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

        const { title, tags } = req.body;

        const metadata = loadMetadata();

        if (metadata[req.params.filename]) {

            if (title !== undefined) {
                if (title.length > 100) {
                    return res.status(400).json({ success: false, error: "タイトルは100文字以内で入力してください" });
                }
                metadata[req.params.filename].title = title;
            }

            if (tags !== undefined) {
                const tagList = Array.isArray(tags)
                    ? tags
                    : tags.split(",").map(t => t.trim()).filter(Boolean);
                if (tagList.some(t => t.length > 20)) {
                    return res.status(400).json({ success: false, error: "各タグは20文字以内で入力してください" });
                }
                if (tagList.length > 10) {
                    return res.status(400).json({ success: false, error: "タグは最大10個までです" });
                }
                metadata[req.params.filename].tags = tagList;
            }

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
        title: metadata[file]?.title || file,
        tags: metadata[file]?.tags || [],
        uploadedBy: metadata[file]?.uploadedBy || null
    }));

    videos.reverse();

    res.json(videos);
});

app.get("/search", (req, res) => {

    const q = (req.query.q || "").toLowerCase().trim();

    if (!q) {
        return res.json([]);
    }

    const files = fs.readdirSync(uploadDir);
    const metadata = loadMetadata();

    const results = files.filter(file => {
        const meta = metadata[file];
        if (!meta || !meta.tags) return false;
        return meta.tags.some(tag => tag.toLowerCase().includes(q));
    }).map(file => ({
        name: file,
        url: "/videos/" + file,
        title: metadata[file]?.title || file,
        tags: metadata[file]?.tags || [],
        uploadedBy: metadata[file]?.uploadedBy || null
    }));

    results.reverse();
    res.json(results);
});

app.listen(PORT, () => {
    console.log(`http://localhost:${PORT}`);
});