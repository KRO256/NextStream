const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");
const crypto = require("crypto");
const helmet = require("helmet");
const { spawn } = require("child_process");
require("dotenv").config();

const app = express();
const PORT = 3000;

app.use(express.json({ limit: "1gb" }));

app.use(express.urlencoded({
    extended: true,
    limit: "1gb"
}));

const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
    console.error("SESSION_SECRET environment variable is not set");
    process.exit(1);
}

app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "https://cdn.jsdelivr.net", "'unsafe-inline'"],
            styleSrc: ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
            fontSrc: ["https://fonts.gstatic.com"],
            connectSrc: ["'self'"],
            imgSrc: ["'self'", "data:"],
            mediaSrc: ["'self'"],
            frameAncestors: ["'none'"]
        }
    },
    crossOriginEmbedderPolicy: false
}));

app.use((req, res, next) => {
    if (req.session && !req.session.csrfToken) {
        req.session.csrfToken = crypto.randomUUID();
    }
    next();
});

function csrfProtection(req, res, next) {
    const token = req.headers["x-csrf-token"];
    if (!token || token !== req.session.csrfToken) {
        return res.status(403).json({ success: false, error: "CSRFトークンが無効です" });
    }
    next();
}

const uploadDir = path.join(__dirname, "uploads");
const hlsDir = path.join(uploadDir, "hls");
const tempDir = path.join(__dirname, "temp");
const chunksDir = path.join(__dirname, "chunks");
const metadataPath = path.join(__dirname, "videos.json");
const usersPath = path.join(__dirname, "users.json");
const subscriptionsPath = path.join(__dirname, "subscriptions.json");
const viewsPath = path.join(__dirname, "views.json");
const commentsPath = path.join(__dirname, "comments.json");
const bookmarksPath = path.join(__dirname, "bookmarks.json");

[uploadDir, hlsDir, tempDir, chunksDir].forEach(dir => {
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

function loadSubscriptions() {
    try {
        return JSON.parse(fs.readFileSync(subscriptionsPath, "utf8"));
    } catch {
        return {};
    }
}

function saveSubscriptions(data) {
    fs.writeFileSync(subscriptionsPath, JSON.stringify(data, null, 2));
}

function loadViews() {
    try {
        return JSON.parse(fs.readFileSync(viewsPath, "utf8"));
    } catch {
        return {};
    }
}

function saveViews(data) {
    fs.writeFileSync(viewsPath, JSON.stringify(data, null, 2));
}

function loadComments() {
    try {
        return JSON.parse(fs.readFileSync(commentsPath, "utf8"));
    } catch {
        return {};
    }
}

function saveComments(data) {
    fs.writeFileSync(commentsPath, JSON.stringify(data, null, 2));
}

function loadBookmarks() {
    try {
        return JSON.parse(fs.readFileSync(bookmarksPath, "utf8"));
    } catch {
        return {};
    }
}

function saveBookmarks(data) {
    fs.writeFileSync(bookmarksPath, JSON.stringify(data, null, 2));
}

function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, error: "ログインが必要です" });
    }
    next();
}

const rateLimitStore = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of rateLimitStore) {
        if (now > entry.resetAt) {
            rateLimitStore.delete(key);
        }
    }
}, 60000);

function rateLimit({ windowMs, max, keyFn, message }) {
    return (req, res, next) => {
        const key = keyFn(req);
        const now = Date.now();
        let entry = rateLimitStore.get(key);
        if (!entry || now > entry.resetAt) {
            entry = { count: 0, resetAt: now + windowMs };
            rateLimitStore.set(key, entry);
        }
        entry.count++;
        if (entry.count > max) {
            const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
            res.set("Retry-After", String(retryAfter));
            return res.status(429).json({ success: false, error: message });
        }
        next();
    };
}

app.use("/videos", express.static(uploadDir));
app.use("/hls", express.static(hlsDir));
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

app.post("/api/register", rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    keyFn: req => req.ip,
    message: "登録は1時間に3回までです"
}), async (req, res) => {
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
        res.json({ success: true, user: username, csrfToken: req.session.csrfToken });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post("/api/login", rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    keyFn: req => req.ip,
    message: "ログイン試行回数が多すぎます。しばらくしてから再試行してください"
}), async (req, res) => {
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
        res.json({ success: true, user: username, csrfToken: req.session.csrfToken });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get("/api/csrf-token", (req, res) => {
    res.json({ success: true, csrfToken: req.session.csrfToken });
});

app.post("/api/logout", csrfProtection, (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get("/api/me", (req, res) => {
    if (req.session.userId) {
        res.json({ success: true, user: req.session.userId, csrfToken: req.session.csrfToken });
    } else {
        res.json({ success: false, user: null, csrfToken: req.session.csrfToken });
    }
});

app.delete("/api/account", requireAuth, csrfProtection, async (req, res) => {
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

function readVideoFiles() {
    return fs.readdirSync(uploadDir).filter(f => {
        try { return fs.statSync(path.join(uploadDir, f)).isFile(); }
        catch { return false; }
    });
}

function getVideoUrl(file, meta) {
    return meta && meta.hls ? "/hls/" + file + "/index.m3u8" : "/videos/" + file;
}

app.post("/upload-chunk", requireAuth, csrfProtection, rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    keyFn: req => "upload:" + req.session.userId,
    message: "アップロードは1時間に5回までです"
}), upload.single("chunk"), (req, res) => {

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
                    uploadedBy: req.session.userId,
                    likes: [],
                    views: 0
                };
                saveMetadata(metadata);

                console.log("UPLOAD COMPLETE:", safeName);

                const videoHlsDir = path.join(hlsDir, safeName);
                if (!fs.existsSync(videoHlsDir)) {
                    fs.mkdirSync(videoHlsDir);
                }

                const ffmpeg = spawn("ffmpeg", [
                    "-i", finalPath,
                    "-c:v", "libx264",
                    "-preset", "fast",
                    "-crf", "23",
                    "-c:a", "aac",
                    "-b:a", "128k",
                    "-hls_time", "10",
                    "-hls_playlist_type", "vod",
                    "-hls_segment_filename",
                    path.join(videoHlsDir, "segment_%03d.ts"),
                    path.join(videoHlsDir, "index.m3u8")
                ]);

                ffmpeg.stderr.on("data", data => {
                    console.log("ffmpeg:", data.toString());
                });

                ffmpeg.on("close", code => {
                    if (code === 0) {
                        const meta = loadMetadata();
                        if (meta[safeName]) {
                            meta[safeName].hls = true;
                            saveMetadata(meta);
                        }
                        console.log("HLS READY:", safeName);
                    } else {
                        console.error("ffmpeg failed for", safeName, "code:", code);
                    }
                });
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

app.patch("/video/:filename", requireAuth, csrfProtection, (req, res) => {

    try {

        const { title, tags } = req.body;

        const metadata = loadMetadata();
        const video = metadata[req.params.filename];

        if (video) {
            if (video.uploadedBy !== req.session.userId) {
                return res.status(403).json({ success: false, error: "自分の動画のみ編集できます" });
            }

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

app.post("/api/video/:filename/like", requireAuth, csrfProtection, (req, res) => {
    try {
        const metadata = loadMetadata();
        const video = metadata[req.params.filename];

        if (!video) {
            return res.status(404).json({ success: false, error: "Video not found" });
        }

        if (!video.likes) {
            video.likes = [];
        }

        const userIndex = video.likes.indexOf(req.session.userId);
        if (userIndex === -1) {
            video.likes.push(req.session.userId);
        } else {
            video.likes.splice(userIndex, 1);
        }

        saveMetadata(metadata);

        res.json({
            success: true,
            liked: userIndex === -1,
            likes: video.likes.length
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post("/api/video/:filename/bookmark", requireAuth, csrfProtection, (req, res) => {
    try {
        const bookmarks = loadBookmarks();
        const user = req.session.userId;
        if (!bookmarks[user]) {
            bookmarks[user] = [];
        }
        const idx = bookmarks[user].indexOf(req.params.filename);
        if (idx === -1) {
            bookmarks[user].push(req.params.filename);
        } else {
            bookmarks[user].splice(idx, 1);
        }
        saveBookmarks(bookmarks);
        res.json({
            success: true,
            bookmarked: idx === -1
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get("/api/bookmarks", requireAuth, (req, res) => {
    try {
        const bookmarks = loadBookmarks();
        const userBookmarks = bookmarks[req.session.userId] || [];
        const files = readVideoFiles();
        const metadata = loadMetadata();
        const videos = userBookmarks
            .filter(file => files.includes(file) && metadata[file])
            .map(file => ({
                name: file,
                url: getVideoUrl(file, metadata[file]),
                title: metadata[file]?.title || file,
                tags: metadata[file]?.tags || [],
                uploadedBy: metadata[file]?.uploadedBy || null,
                likes: metadata[file]?.likes?.length || 0,
                likedByUser: req.session.userId && metadata[file]?.likes?.includes(req.session.userId) || false,
                bookmarkedByUser: true,
                views: metadata[file]?.views || 0
            }));
        videos.reverse();

        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 30, 100);
        const start = (page - 1) * limit;
        const total = videos.length;
        const totalPages = Math.ceil(total / limit);
        const paged = videos.slice(start, start + limit);

        res.json({ videos: paged, total, page, limit, totalPages });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post("/api/channel/:username/subscribe", requireAuth, csrfProtection, (req, res) => {
    try {
        const channel = req.params.username;
        const user = req.session.userId;

        if (channel === user) {
            return res.status(400).json({ success: false, error: "自分自身を登録できません" });
        }

        const users = loadUsers();
        if (!users[channel]) {
            return res.status(404).json({ success: false, error: "チャンネルが見つかりません" });
        }

        const subscriptions = loadSubscriptions();
        if (!subscriptions[channel]) {
            subscriptions[channel] = [];
        }

        const idx = subscriptions[channel].indexOf(user);
        if (idx === -1) {
            subscriptions[channel].push(user);
        } else {
            subscriptions[channel].splice(idx, 1);
        }

        saveSubscriptions(subscriptions);

        res.json({
            success: true,
            subscribed: idx === -1,
            subscribers: subscriptions[channel].length
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get("/api/channel/:username/subscribers", (req, res) => {
    try {
        const channel = req.params.username;
        const subscriptions = loadSubscriptions();
        const subs = subscriptions[channel] || [];

        res.json({
            success: true,
            subscribers: subs.length,
            subscribed: req.session.userId ? subs.includes(req.session.userId) : false
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post("/api/video/:filename/comment", requireAuth, csrfProtection, rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    keyFn: req => "comment:" + req.session.userId,
    message: "コメントの投稿は15分間に20回までです"
}), (req, res) => {
    try {
        const { text } = req.body;
        if (!text || !text.trim()) {
            return res.status(400).json({ success: false, error: "コメントを入力してください" });
        }
        if (text.length > 500) {
            return res.status(400).json({ success: false, error: "コメントは500文字以内で入力してください" });
        }

        const metadata = loadMetadata();
        if (!metadata[req.params.filename]) {
            return res.status(404).json({ success: false, error: "Video not found" });
        }

        const comments = loadComments();
        if (!comments[req.params.filename]) {
            comments[req.params.filename] = [];
        }

        const comment = {
            id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
            username: req.session.userId,
            text: text.trim(),
            createdAt: new Date().toISOString()
        };

        comments[req.params.filename].push(comment);
        saveComments(comments);

        res.json({ success: true, comment });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get("/api/video/:filename/comments", (req, res) => {
    try {
        const comments = loadComments();
        const list = comments[req.params.filename] || [];
        res.json({ success: true, comments: list });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.delete("/api/video/:filename/comment/:id", requireAuth, csrfProtection, (req, res) => {
    try {
        const comments = loadComments();
        const list = comments[req.params.filename];
        if (!list) {
            return res.status(404).json({ success: false, error: "コメントが見つかりません" });
        }

        const idx = list.findIndex(c => c.id === req.params.id);
        if (idx === -1) {
            return res.status(404).json({ success: false, error: "コメントが見つかりません" });
        }

        if (list[idx].username !== req.session.userId) {
            return res.status(403).json({ success: false, error: "自分のコメントのみ削除できます" });
        }

        list.splice(idx, 1);
        saveComments(comments);

        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post("/api/video/:filename/view", csrfProtection, (req, res) => {
    try {
        const metadata = loadMetadata();
        const video = metadata[req.params.filename];

        if (!video) {
            return res.status(404).json({ success: false, error: "Video not found" });
        }

        video.views = (video.views || 0) + 1;
        saveMetadata(metadata);

        const now = Date.now();
        const views = loadViews();
        if (!views[req.params.filename]) {
            views[req.params.filename] = [];
        }
        views[req.params.filename].push(now);
        saveViews(views);

        let periodViews = null;
        if (req.query.period) {
            let cutoff;
            switch (req.query.period) {
                case "year": cutoff = now - 365 * 24 * 60 * 60 * 1000; break;
                case "month": cutoff = now - 30 * 24 * 60 * 60 * 1000; break;
                case "week": cutoff = now - 7 * 24 * 60 * 60 * 1000; break;
                case "day": cutoff = now - 24 * 60 * 60 * 1000; break;
                default: cutoff = 0;
            }
            periodViews = views[req.params.filename].filter(ts => ts >= cutoff).length;
        }

        res.json({ success: true, views: video.views, periodViews });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.delete("/api/video/:filename", requireAuth, csrfProtection, (req, res) => {
    try {
        const metadata = loadMetadata();
        const video = metadata[req.params.filename];

        if (!video) {
            return res.status(404).json({ success: false, error: "Video not found" });
        }

        if (video.uploadedBy !== req.session.userId) {
            return res.status(403).json({ success: false, error: "自分の動画のみ削除できます" });
        }

        const filePath = path.join(uploadDir, req.params.filename);
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }

        const videoHlsDir = path.join(hlsDir, req.params.filename);
        if (fs.existsSync(videoHlsDir)) {
            fs.rmSync(videoHlsDir, { recursive: true, force: true });
        }

        delete metadata[req.params.filename];
        saveMetadata(metadata);

        const comments = loadComments();
        delete comments[req.params.filename];
        saveComments(comments);

        const views = loadViews();
        delete views[req.params.filename];
        saveViews(views);

        const bookmarks = loadBookmarks();
        for (const user of Object.keys(bookmarks)) {
            const idx = bookmarks[user].indexOf(req.params.filename);
            if (idx !== -1) {
                bookmarks[user].splice(idx, 1);
            }
        }
        saveBookmarks(bookmarks);

        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get("/api/video/:filename", (req, res) => {
    try {
        const metadata = loadMetadata();
        const video = metadata[req.params.filename];
        if (!video) {
            return res.status(404).json({ success: false, error: "Video not found" });
        }
        const bookmarks = loadBookmarks();
        const userBookmarks = bookmarks[req.session.userId] || [];
        res.json({
            success: true,
            video: {
                name: req.params.filename,
                url: getVideoUrl(req.params.filename, video),
                title: video.title || req.params.filename,
                tags: video.tags || [],
                uploadedBy: video.uploadedBy || null,
                likes: video.likes?.length || 0,
                likedByUser: req.session.userId && video.likes?.includes(req.session.userId) || false,
                bookmarkedByUser: req.session.userId && userBookmarks.includes(req.params.filename) || false,
                views: video.views || 0
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get("/list", (req, res) => {

    const files = readVideoFiles();

    const metadata = loadMetadata();
    const bookmarks = loadBookmarks();
    const userBookmarks = bookmarks[req.session.userId] || [];

    const videos = files.map(file => ({
        name: file,
        url: getVideoUrl(file, metadata[file]),
        title: metadata[file]?.title || file,
        tags: metadata[file]?.tags || [],
        uploadedBy: metadata[file]?.uploadedBy || null,
        likes: metadata[file]?.likes?.length || 0,
        likedByUser: req.session.userId && metadata[file]?.likes?.includes(req.session.userId) || false,
        bookmarkedByUser: req.session.userId && userBookmarks.includes(file) || false,
        views: metadata[file]?.views || 0
    }));

    videos.reverse();

    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 30, 100);
    const start = (page - 1) * limit;
    const total = videos.length;
    const totalPages = Math.ceil(total / limit);
    const paged = videos.slice(start, start + limit);

    res.json({ videos: paged, total, page, limit, totalPages });
});

app.get("/channel/:username", (req, res) => {
    const username = req.params.username;
    const files = readVideoFiles();
    const metadata = loadMetadata();
    const bookmarks = loadBookmarks();
    const userBookmarks = bookmarks[req.session.userId] || [];

    const videos = files.filter(file => {
        const meta = metadata[file];
        return meta && meta.uploadedBy === username;
    }).map(file => ({
        name: file,
        url: getVideoUrl(file, metadata[file]),
        title: metadata[file]?.title || file,
        tags: metadata[file]?.tags || [],
        uploadedBy: metadata[file]?.uploadedBy || null,
        likes: metadata[file]?.likes?.length || 0,
        likedByUser: req.session.userId && metadata[file]?.likes?.includes(req.session.userId) || false,
        bookmarkedByUser: req.session.userId && userBookmarks.includes(file) || false,
        views: metadata[file]?.views || 0
    }));

    videos.reverse();

    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 30, 100);
    const start = (page - 1) * limit;
    const total = videos.length;
    const totalPages = Math.ceil(total / limit);
    const paged = videos.slice(start, start + limit);

    res.json({ videos: paged, total, page, limit, totalPages });
});

app.get("/search", (req, res) => {

    const q = (req.query.q || "").toLowerCase().trim();

    if (!q) {
        return res.json({ videos: [], total: 0, page: 1, limit: 30, totalPages: 0 });
    }

    const files = readVideoFiles();
    const metadata = loadMetadata();
    const bookmarks = loadBookmarks();
    const userBookmarks = bookmarks[req.session.userId] || [];

    const results = files.filter(file => {
        const meta = metadata[file];
        if (!meta || !meta.tags) return false;
        return meta.tags.some(tag => tag.toLowerCase().includes(q));
    }).map(file => ({
        name: file,
        url: getVideoUrl(file, metadata[file]),
        title: metadata[file]?.title || file,
        tags: metadata[file]?.tags || [],
        uploadedBy: metadata[file]?.uploadedBy || null,
        likes: metadata[file]?.likes?.length || 0,
        likedByUser: req.session.userId && metadata[file]?.likes?.includes(req.session.userId) || false,
        bookmarkedByUser: req.session.userId && userBookmarks.includes(file) || false,
        views: metadata[file]?.views || 0
    }));

    results.reverse();

    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 30, 100);
    const start = (page - 1) * limit;
    const total = results.length;
    const totalPages = Math.ceil(total / limit);
    const paged = results.slice(start, start + limit);

    res.json({ videos: paged, total, page, limit, totalPages });
});

app.get("/api/ranking", (req, res) => {
    try {
        const period = req.query.period || "all";
        const now = Date.now();
        let cutoff;

        switch (period) {
            case "year": cutoff = now - 365 * 24 * 60 * 60 * 1000; break;
            case "month": cutoff = now - 30 * 24 * 60 * 60 * 1000; break;
            case "week": cutoff = now - 7 * 24 * 60 * 60 * 1000; break;
            case "day": cutoff = now - 24 * 60 * 60 * 1000; break;
            default: cutoff = 0;
        }

        const files = readVideoFiles();
        const metadata = loadMetadata();
        const views = loadViews();
        const bookmarks = loadBookmarks();
        const userBookmarks = bookmarks[req.session.userId] || [];

        const videos = files.map(file => {
            const meta = metadata[file];
            let periodViews = 0;

            if (views[file]) {
                if (period === "all") {
                    periodViews = views[file].length;
                } else {
                    periodViews = views[file].filter(ts => ts >= cutoff).length;
                }
            }

            return {
                name: file,
                url: getVideoUrl(file, meta),
                title: meta?.title || file,
                tags: meta?.tags || [],
                uploadedBy: meta?.uploadedBy || null,
                likes: meta?.likes?.length || 0,
                likedByUser: req.session.userId && meta?.likes?.includes(req.session.userId) || false,
                bookmarkedByUser: req.session.userId && userBookmarks.includes(file) || false,
                views: periodViews,
                totalViews: meta?.views || 0
            };
        });

        videos.sort((a, b) => b.views - a.views);

        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 30, 100);
        const start = (page - 1) * limit;
        const total = videos.length;
        const totalPages = Math.ceil(total / limit);
        const paged = videos.slice(start, start + limit);

        res.json({ videos: paged, total, page, limit, totalPages });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get("/watch/*", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
    console.log(`http://localhost:${PORT}`);
});