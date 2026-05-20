const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");
const crypto = require("crypto");
const helmet = require("helmet");
const { spawn, spawnSync } = require("child_process");
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

const adminUsername = process.env.ADMIN_USERNAME;

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
            scriptSrcAttr: ["'unsafe-inline'"],
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
const progressPath = path.join(__dirname, "progress.json");
const thumbnailsDir = path.join(uploadDir, "thumbnails");
const profilesPath = path.join(__dirname, "profiles.json");
const avatarsDir = path.join(uploadDir, "avatars");
const notificationsPath = path.join(__dirname, "notifications.json");
const playlistsPath = path.join(__dirname, "playlists.json");

[uploadDir, hlsDir, tempDir, chunksDir, thumbnailsDir, avatarsDir].forEach(dir => {
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
        const data = JSON.parse(fs.readFileSync(viewsPath, "utf8"));
        return (data && typeof data === "object" && !Array.isArray(data)) ? data : {};
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

function loadProgress() {
    try {
        return JSON.parse(fs.readFileSync(progressPath, "utf8"));
    } catch {
        return {};
    }
}

function saveProgress(data) {
    fs.writeFileSync(progressPath, JSON.stringify(data, null, 2));
}

function loadProfiles() {
    try {
        return JSON.parse(fs.readFileSync(profilesPath, "utf8"));
    } catch {
        return {};
    }
}

function saveProfiles(data) {
    fs.writeFileSync(profilesPath, JSON.stringify(data, null, 2));
}

function loadNotifications() {
    try {
        return JSON.parse(fs.readFileSync(notificationsPath, "utf8"));
    } catch {
        return {};
    }
}

function saveNotifications(data) {
    fs.writeFileSync(notificationsPath, JSON.stringify(data, null, 2));
}

function loadPlaylists() {
    try {
        return JSON.parse(fs.readFileSync(playlistsPath, "utf8"));
    } catch {
        return {};
    }
}

function savePlaylists(data) {
    fs.writeFileSync(playlistsPath, JSON.stringify(data, null, 2));
}

function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, error: "ログインが必要です" });
    }
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.isAdmin) {
        return res.status(403).json({ success: false, error: "管理者権限が必要です" });
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
app.use("/thumbnails", express.static(thumbnailsDir));
app.use("/avatars", express.static(avatarsDir));
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
        const isAdmin = adminUsername && username === adminUsername;
        users[username] = { password: hashedPassword, createdAt: new Date().toISOString(), admin: isAdmin || undefined };
        saveUsers(users);

        req.session.userId = username;
        if (isAdmin) req.session.isAdmin = true;
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
        if (user.admin) req.session.isAdmin = true;
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
        res.json({ success: true, user: req.session.userId, isAdmin: req.session.isAdmin || false, csrfToken: req.session.csrfToken });
    } else {
        res.json({ success: false, user: null, isAdmin: false, csrfToken: req.session.csrfToken });
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

        const profiles = loadProfiles();
        if (profiles[req.session.userId]) {
            if (profiles[req.session.userId].avatar) {
                const avatarFile = path.join(avatarsDir, path.basename(profiles[req.session.userId].avatar));
                if (fs.existsSync(avatarFile)) fs.unlinkSync(avatarFile);
            }
            delete profiles[req.session.userId];
            saveProfiles(profiles);
        }

        const notifications = loadNotifications();
        delete notifications[req.session.userId];
        saveNotifications(notifications);

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

function getVideoThumbnailUrl(file) {
    const thumbPath = path.join(thumbnailsDir, file + ".jpg");
    return fs.existsSync(thumbPath) ? "/thumbnails/" + file + ".jpg" : null;
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
            description,
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

                if (description && description.length > 2000) {
                    return res.status(400).json({ success: false, error: "説明文は2000文字以内で入力してください" });
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
                let duration = 0;
                try {
                    const probe = spawnSync("ffprobe", [
                        "-v", "error",
                        "-show_entries", "format=duration",
                        "-of", "default=noprint_wrappers=1:nokey=1",
                        finalPath
                    ], { timeout: 10000 });
                    if (probe.status === 0) {
                        duration = parseFloat(probe.stdout.toString().trim()) || 0;
                    }
                } catch (e) {
                    console.error("ffprobe failed for", safeName, e.message);
                }

                metadata[safeName] = {
                    title: title || safeName,
                    description: description || "",
                    tags: tagList,
                    uploadedBy: req.session.userId,
                    likes: [],
                    views: 0,
                    duration: duration
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

                        const uploader = req.session.userId;
                        const videoTitle = meta[safeName]?.title || safeName;
                        try {
                            const subs = loadSubscriptions();
                            const subscribers = subs[uploader] || [];
                            if (subscribers.length > 0) {
                                const notifications = loadNotifications();
                                const notification = {
                                    id: crypto.randomUUID(),
                                    type: "new_video",
                                    from: uploader,
                                    videoFilename: safeName,
                                    videoTitle: videoTitle,
                                    createdAt: new Date().toISOString(),
                                    read: false
                                };
                                for (const subscriber of subscribers) {
                                    if (!notifications[subscriber]) {
                                        notifications[subscriber] = [];
                                    }
                                    notifications[subscriber].unshift({ ...notification });
                                }
                                saveNotifications(notifications);
                                console.log("NOTIFICATIONS SENT to", subscribers.length, "subscribers of", uploader);
                            }
                        } catch (notifErr) {
                            console.error("notification error:", notifErr);
                        }

                        const thumbPath = path.join(thumbnailsDir, safeName + ".jpg");
                        const ffmpegThumb = spawn("ffmpeg", [
                            "-i", finalPath,
                            "-ss", "00:00:01",
                            "-vframes", "1",
                            "-q:v", "2",
                            thumbPath
                        ]);
                        ffmpegThumb.on("close", thumbCode => {
                            if (thumbCode === 0) {
                                console.log("THUMBNAIL READY:", safeName);
                            } else {
                                console.error("thumbnail failed for", safeName, "code:", thumbCode);
                            }
                        });
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

        const { title, description, tags } = req.body;

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

            if (description !== undefined) {
                if (description.length > 2000) {
                    return res.status(400).json({ success: false, error: "説明文は2000文字以内で入力してください" });
                }
                metadata[req.params.filename].description = description;
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
            .map(file => {
                const meta = metadata[file] || {};
                return {
                    name: file,
                    url: getVideoUrl(file, meta),
                    title: meta.title || file,
                    description: meta.description || "",
                    tags: meta.tags || [],
                    uploadedBy: meta.uploadedBy || null,
                    likes: meta.likes?.length || 0,
                    likedByUser: req.session.userId && meta.likes?.includes(req.session.userId) || false,
                    bookmarkedByUser: true,
                    views: meta.views || 0,
                    thumbnailUrl: getVideoThumbnailUrl(file),
                    duration: meta.duration || 0
                };
            });
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

app.post("/api/video/:filename/progress", requireAuth, csrfProtection, (req, res) => {
    try {
        const { time } = req.body;
        if (typeof time !== "number" || time < 0) {
            return res.status(400).json({ success: false, error: "再生時間が無効です" });
        }
        const progress = loadProgress();
        const user = req.session.userId;
        if (!progress[user]) progress[user] = {};
        progress[user][req.params.filename] = time;
        saveProgress(progress);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get("/api/video/:filename/progress", requireAuth, (req, res) => {
    try {
        const progress = loadProgress();
        const userData = progress[req.session.userId];
        const time = userData ? userData[req.params.filename] : null;
        res.json({ success: true, time: time || 0 });
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

app.get("/api/notifications", requireAuth, (req, res) => {
    try {
        const notifications = loadNotifications();
        const userNotifs = notifications[req.session.userId] || [];

        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 20, 50);
        const start = (page - 1) * limit;
        const total = userNotifs.length;
        const totalPages = Math.ceil(total / limit);
        const paged = userNotifs.slice(start, start + limit);

        res.json({ success: true, notifications: paged, total, page, limit, totalPages, unread: userNotifs.filter(n => !n.read).length });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get("/api/notifications/unread-count", requireAuth, (req, res) => {
    try {
        const notifications = loadNotifications();
        const userNotifs = notifications[req.session.userId] || [];
        const unread = userNotifs.filter(n => !n.read).length;
        res.json({ success: true, unread });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post("/api/notifications/read", requireAuth, csrfProtection, (req, res) => {
    try {
        const notifications = loadNotifications();
        if (notifications[req.session.userId]) {
            for (const n of notifications[req.session.userId]) {
                n.read = true;
            }
            saveNotifications(notifications);
        }
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post("/api/notifications/read/:id", requireAuth, csrfProtection, (req, res) => {
    try {
        const notifications = loadNotifications();
        const userNotifs = notifications[req.session.userId];
        if (userNotifs) {
            const notif = userNotifs.find(n => n.id === req.params.id);
            if (notif) {
                notif.read = true;
                saveNotifications(notifications);
            }
        }
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get("/api/profile/:username", (req, res) => {
    try {
        const profiles = loadProfiles();
        const profile = profiles[req.params.username] || {};
        res.json({
            success: true,
            profile: {
                bio: profile.bio || "",
                avatar: profile.avatar || null
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.put("/api/profile", requireAuth, csrfProtection, (req, res) => {
    try {
        const { bio, removeAvatar } = req.body;
        if (bio !== undefined && bio.length > 500) {
            return res.status(400).json({ success: false, error: "プロフィール文は500文字以内で入力してください" });
        }
        const profiles = loadProfiles();
        if (!profiles[req.session.userId]) {
            profiles[req.session.userId] = {};
        }
        if (bio !== undefined) {
            profiles[req.session.userId].bio = bio;
        }
        if (removeAvatar) {
            if (profiles[req.session.userId].avatar) {
                const avatarFile = path.join(avatarsDir, path.basename(profiles[req.session.userId].avatar));
                if (fs.existsSync(avatarFile)) fs.unlinkSync(avatarFile);
            }
            profiles[req.session.userId].avatar = null;
        }
        saveProfiles(profiles);
        res.json({ success: true, profile: { bio: profiles[req.session.userId].bio || "", avatar: profiles[req.session.userId].avatar || null } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

const avatarUpload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => cb(null, avatarsDir),
        filename: (req, file, cb) => {
            const ext = path.extname(file.originalname) || ".jpg";
            cb(null, req.session.userId + ext);
        }
    }),
    limits: { fileSize: 2 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowed = [".jpg", ".jpeg", ".png", ".gif", ".webp"];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowed.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error("対応形式: jpg, png, gif, webp"));
        }
    }
});

app.post("/api/profile/avatar", requireAuth, csrfProtection, (req, res) => {
    avatarUpload.single("avatar")(req, res, err => {
        if (err) {
            if (err instanceof multer.MulterError) {
                if (err.code === "LIMIT_FILE_SIZE") {
                    return res.status(400).json({ success: false, error: "ファイルサイズは2MB以下にしてください" });
                }
                return res.status(400).json({ success: false, error: err.message });
            }
            return res.status(400).json({ success: false, error: err.message });
        }
        if (!req.file) {
            return res.status(400).json({ success: false, error: "画像ファイルを選択してください" });
        }
        try {
            const profiles = loadProfiles();
            if (!profiles[req.session.userId]) {
                profiles[req.session.userId] = {};
            }
            if (profiles[req.session.userId].avatar) {
                const oldAvatar = path.join(avatarsDir, path.basename(profiles[req.session.userId].avatar));
                if (fs.existsSync(oldAvatar)) fs.unlinkSync(oldAvatar);
            }
            const avatarUrl = "/avatars/" + req.file.filename;
            profiles[req.session.userId].avatar = avatarUrl;
            saveProfiles(profiles);
            res.json({ success: true, avatar: avatarUrl });
        } catch (e) {
            console.error(e);
            res.status(500).json({ success: false, error: e.message });
        }
    });
});

app.get("/api/settings/notifications", requireAuth, (req, res) => {
    try {
        const profiles = loadProfiles();
        const profile = profiles[req.session.userId] || {};
        res.json({ success: true, enabled: profile.notificationsEnabled !== false });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.put("/api/settings/notifications", requireAuth, csrfProtection, (req, res) => {
    try {
        const { enabled } = req.body;
        const profiles = loadProfiles();
        if (!profiles[req.session.userId]) {
            profiles[req.session.userId] = {};
        }
        profiles[req.session.userId].notificationsEnabled = enabled === true;
        saveProfiles(profiles);
        res.json({ success: true, enabled: profiles[req.session.userId].notificationsEnabled });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post("/api/settings/password", requireAuth, csrfProtection, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ success: false, error: "現在のパスワードと新しいパスワードを入力してください" });
        }
        if (newPassword.length < 4) {
            return res.status(400).json({ success: false, error: "新しいパスワードは4文字以上で入力してください" });
        }
        if (currentPassword === newPassword) {
            return res.status(400).json({ success: false, error: "新しいパスワードは現在のパスワードと異なるものを設定してください" });
        }

        const users = loadUsers();
        const user = users[req.session.userId];
        if (!user) {
            return res.status(404).json({ success: false, error: "ユーザーが見つかりません" });
        }

        const match = await bcrypt.compare(currentPassword, user.password);
        if (!match) {
            return res.status(401).json({ success: false, error: "現在のパスワードが間違っています" });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        saveUsers(users);
        res.json({ success: true });
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

        const playlists = loadPlaylists();
        for (const playlist of Object.values(playlists)) {
            const idx = playlist.videoFilenames.indexOf(req.params.filename);
            if (idx !== -1) {
                playlist.videoFilenames.splice(idx, 1);
            }
        }
        savePlaylists(playlists);

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
                description: video.description || "",
                tags: video.tags || [],
                uploadedBy: video.uploadedBy || null,
                likes: video.likes?.length || 0,
                likedByUser: req.session.userId && video.likes?.includes(req.session.userId) || false,
                bookmarkedByUser: req.session.userId && userBookmarks.includes(req.params.filename) || false,
                views: video.views || 0,
                thumbnailUrl: getVideoThumbnailUrl(req.params.filename),
                duration: video.duration || 0
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

    const videos = files.map(file => {
        const meta = metadata[file] || {};
        return {
            name: file,
            url: getVideoUrl(file, meta),
            title: meta.title || file,
            description: meta.description || "",
            tags: meta.tags || [],
            uploadedBy: meta.uploadedBy || null,
            likes: meta.likes?.length || 0,
            likedByUser: req.session.userId && meta.likes?.includes(req.session.userId) || false,
            bookmarkedByUser: req.session.userId && userBookmarks.includes(file) || false,
            views: meta.views || 0,
            thumbnailUrl: getVideoThumbnailUrl(file),
            duration: meta.duration || 0
        };
    });

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
    }).map(file => {
        const meta = metadata[file] || {};
        return {
            name: file,
            url: getVideoUrl(file, meta),
            title: meta.title || file,
            description: meta.description || "",
            tags: meta.tags || [],
            uploadedBy: meta.uploadedBy || null,
            likes: meta.likes?.length || 0,
            likedByUser: req.session.userId && meta.likes?.includes(req.session.userId) || false,
            bookmarkedByUser: req.session.userId && userBookmarks.includes(file) || false,
            views: meta.views || 0,
            thumbnailUrl: getVideoThumbnailUrl(file),
            duration: meta.duration || 0
        };
    });

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
    }).map(file => {
        const meta = metadata[file] || {};
        return {
            name: file,
            url: getVideoUrl(file, meta),
            title: meta.title || file,
            description: meta.description || "",
            tags: meta.tags || [],
            uploadedBy: meta.uploadedBy || null,
            likes: meta.likes?.length || 0,
            likedByUser: req.session.userId && meta.likes?.includes(req.session.userId) || false,
            bookmarkedByUser: req.session.userId && userBookmarks.includes(file) || false,
            views: meta.views || 0,
            thumbnailUrl: getVideoThumbnailUrl(file),
            duration: meta.duration || 0
        };
    });

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

            if (Array.isArray(views[file])) {
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
                description: meta?.description || "",
                tags: meta?.tags || [],
                uploadedBy: meta?.uploadedBy || null,
                likes: meta?.likes?.length || 0,
                likedByUser: req.session.userId && meta?.likes?.includes(req.session.userId) || false,
                bookmarkedByUser: req.session.userId && userBookmarks.includes(file) || false,
                views: periodViews,
                totalViews: meta?.views || 0,
                thumbnailUrl: getVideoThumbnailUrl(file),
                duration: meta?.duration || 0
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

app.get("/admin", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("/api/admin/users", requireAuth, requireAdmin, (req, res) => {
    try {
        const users = loadUsers();
        const metadata = loadMetadata();
        const comments = loadComments();

        const userList = Object.entries(users).map(([username, data]) => {
            const videoCount = Object.values(metadata).filter(v => v.uploadedBy === username).length;
            const commentCount = Object.values(comments).reduce((sum, list) =>
                sum + list.filter(c => c.username === username).length, 0
            );
            return {
                username,
                createdAt: data.createdAt,
                admin: data.admin || false,
                videoCount,
                commentCount
            };
        });

        userList.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        res.json({ success: true, users: userList, total: userList.length });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get("/api/admin/videos", requireAuth, requireAdmin, (req, res) => {
    try {
        const metadata = loadMetadata();
        const files = readVideoFiles();
        const comments = loadComments();

        const videoList = files.map(file => ({
            name: file,
            title: metadata[file]?.title || file,
            description: metadata[file]?.description || "",
            tags: metadata[file]?.tags || [],
            uploadedBy: metadata[file]?.uploadedBy || null,
            likes: metadata[file]?.likes?.length || 0,
            views: metadata[file]?.views || 0,
            hls: metadata[file]?.hls || false,
            commentCount: (comments[file] || []).length,
            thumbnailUrl: getVideoThumbnailUrl(file)
        }));

        videoList.sort((a, b) => b.views - a.views);
        res.json({ success: true, videos: videoList, total: videoList.length });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get("/api/admin/comments", requireAuth, requireAdmin, (req, res) => {
    try {
        const comments = loadComments();
        const metadata = loadMetadata();
        const allComments = [];

        for (const [filename, list] of Object.entries(comments)) {
            for (const c of list) {
                allComments.push({
                    id: c.id,
                    username: c.username,
                    text: c.text,
                    createdAt: c.createdAt,
                    filename,
                    videoTitle: metadata[filename]?.title || filename
                });
            }
        }

        allComments.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        res.json({ success: true, comments: allComments, total: allComments.length });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.delete("/api/admin/user/:username", requireAuth, requireAdmin, csrfProtection, (req, res) => {
    try {
        const targetUser = req.params.username;
        if (targetUser === req.session.userId) {
            return res.status(400).json({ success: false, error: "自分自身を削除することはできません" });
        }

        const users = loadUsers();
        if (!users[targetUser]) {
            return res.status(404).json({ success: false, error: "ユーザーが見つかりません" });
        }

        if (users[targetUser].admin) {
            return res.status(403).json({ success: false, error: "他の管理者を削除することはできません" });
        }

        const metadata = loadMetadata();
        const userVideos = Object.keys(metadata).filter(k => metadata[k].uploadedBy === targetUser);

        for (const filename of userVideos) {
            const filePath = path.join(uploadDir, filename);
            if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
            const videoHlsDir = path.join(hlsDir, filename);
            if (fs.existsSync(videoHlsDir)) fs.rmSync(videoHlsDir, { recursive: true, force: true });
            delete metadata[filename];
        }
        saveMetadata(metadata);

        const comments = loadComments();
        for (const filename of Object.keys(comments)) {
            comments[filename] = comments[filename].filter(c => c.username !== targetUser);
            if (comments[filename].length === 0) delete comments[filename];
        }
        saveComments(comments);

        const views = loadViews();
        for (const filename of userVideos) {
            delete views[filename];
        }
        saveViews(views);

        const bookmarks = loadBookmarks();
        delete bookmarks[targetUser];
        for (const user of Object.keys(bookmarks)) {
            bookmarks[user] = bookmarks[user].filter(f => !userVideos.includes(f));
        }
        saveBookmarks(bookmarks);

        const subscriptions = loadSubscriptions();
        delete subscriptions[targetUser];
        for (const channel of Object.keys(subscriptions)) {
            subscriptions[channel] = subscriptions[channel].filter(s => s !== targetUser);
        }
        saveSubscriptions(subscriptions);

        const profiles = loadProfiles();
        if (profiles[targetUser]) {
            if (profiles[targetUser].avatar) {
                const avatarFile = path.join(avatarsDir, path.basename(profiles[targetUser].avatar));
                if (fs.existsSync(avatarFile)) fs.unlinkSync(avatarFile);
            }
            delete profiles[targetUser];
            saveProfiles(profiles);
        }

        const notifications = loadNotifications();
        delete notifications[targetUser];
        saveNotifications(notifications);

        const playlists = loadPlaylists();
        for (const [pid, pl] of Object.entries(playlists)) {
            if (pl.username === targetUser) {
                delete playlists[pid];
            } else {
                pl.videoFilenames = pl.videoFilenames.filter(f => !userVideos.includes(f));
            }
        }
        savePlaylists(playlists);

        delete users[targetUser];
        saveUsers(users);

        console.log(`[ADMIN] ${req.session.userId} deleted user ${targetUser} with ${userVideos.length} videos`);
        res.json({ success: true, deletedVideos: userVideos.length });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.delete("/api/admin/video/:filename", requireAuth, requireAdmin, csrfProtection, (req, res) => {
    try {
        const metadata = loadMetadata();
        const filename = req.params.filename;

        if (!metadata[filename]) {
            return res.status(404).json({ success: false, error: "動画が見つかりません" });
        }

        const filePath = path.join(uploadDir, filename);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        const videoHlsDir = path.join(hlsDir, filename);
        if (fs.existsSync(videoHlsDir)) fs.rmSync(videoHlsDir, { recursive: true, force: true });

        delete metadata[filename];
        saveMetadata(metadata);

        const comments = loadComments();
        delete comments[filename];
        saveComments(comments);

        const views = loadViews();
        delete views[filename];
        saveViews(views);

        const bookmarks = loadBookmarks();
        for (const user of Object.keys(bookmarks)) {
            const idx = bookmarks[user].indexOf(filename);
            if (idx !== -1) bookmarks[user].splice(idx, 1);
        }
        saveBookmarks(bookmarks);

        console.log(`[ADMIN] ${req.session.userId} deleted video ${filename}`);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.delete("/api/admin/video/:filename/comment/:id", requireAuth, requireAdmin, csrfProtection, (req, res) => {
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

        const removed = list.splice(idx, 1)[0];
        if (list.length === 0) delete comments[req.params.filename];
        saveComments(comments);

        console.log(`[ADMIN] ${req.session.userId} deleted comment ${req.params.id} by ${removed.username} on ${req.params.filename}`);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// --- Playlist API ---

app.post("/api/playlists", requireAuth, csrfProtection, (req, res) => {
    try {
        const { title, description, isPublic } = req.body;
        if (!title || !title.trim()) {
            return res.status(400).json({ success: false, error: "プレイリスト名を入力してください" });
        }
        if (title.trim().length > 100) {
            return res.status(400).json({ success: false, error: "プレイリスト名は100文字以内で入力してください" });
        }
        if (description && description.length > 500) {
            return res.status(400).json({ success: false, error: "説明文は500文字以内で入力してください" });
        }

        const playlists = loadPlaylists();
        const id = crypto.randomUUID();
        playlists[id] = {
            id,
            title: title.trim(),
            description: (description || "").trim(),
            isPublic: !!isPublic,
            username: req.session.userId,
            videoFilenames: [],
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        savePlaylists(playlists);
        res.json({ success: true, playlist: playlists[id] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get("/api/playlists", requireAuth, (req, res) => {
    try {
        const playlists = loadPlaylists();
        const userPlaylists = Object.values(playlists)
            .filter(p => p.username === req.session.userId)
            .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
        res.json({ success: true, playlists: userPlaylists });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get("/api/playlists/:id", (req, res) => {
    try {
        const playlists = loadPlaylists();
        const playlist = playlists[req.params.id];
        if (!playlist) {
            return res.status(404).json({ success: false, error: "プレイリストが見つかりません" });
        }
        if (!playlist.isPublic && (!req.session.userId || req.session.userId !== playlist.username)) {
            return res.status(403).json({ success: false, error: "このプレイリストは非公開です" });
        }

        const metadata = loadMetadata();
        const files = readVideoFiles();
        const bookmarks = loadBookmarks();
        const userBookmarks = bookmarks[req.session.userId] || [];

        const videos = playlist.videoFilenames
            .filter(file => files.includes(file) && metadata[file])
            .map(file => {
                const meta = metadata[file] || {};
                return {
                    name: file,
                    url: getVideoUrl(file, meta),
                    title: meta.title || file,
                    description: meta.description || "",
                    tags: meta.tags || [],
                    uploadedBy: meta.uploadedBy || null,
                    likes: meta.likes?.length || 0,
                    likedByUser: req.session.userId && meta.likes?.includes(req.session.userId) || false,
                    bookmarkedByUser: req.session.userId && userBookmarks.includes(file) || false,
                    views: meta.views || 0,
                    thumbnailUrl: getVideoThumbnailUrl(file),
                    duration: meta.duration || 0
                };
            });

        res.json({
            success: true,
            playlist: {
                ...playlist,
                videoFilenames: undefined
            },
            videos
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.patch("/api/playlists/:id", requireAuth, csrfProtection, (req, res) => {
    try {
        const playlists = loadPlaylists();
        const playlist = playlists[req.params.id];
        if (!playlist) {
            return res.status(404).json({ success: false, error: "プレイリストが見つかりません" });
        }
        if (playlist.username !== req.session.userId) {
            return res.status(403).json({ success: false, error: "自分のプレイリストのみ編集できます" });
        }

        const { title, description, isPublic } = req.body;
        if (title !== undefined) {
            if (!title.trim()) {
                return res.status(400).json({ success: false, error: "プレイリスト名を入力してください" });
            }
            if (title.trim().length > 100) {
                return res.status(400).json({ success: false, error: "プレイリスト名は100文字以内で入力してください" });
            }
            playlist.title = title.trim();
        }
        if (description !== undefined) {
            if (description.length > 500) {
                return res.status(400).json({ success: false, error: "説明文は500文字以内で入力してください" });
            }
            playlist.description = description.trim();
        }
        if (isPublic !== undefined) {
            playlist.isPublic = !!isPublic;
        }
        playlist.updatedAt = new Date().toISOString();
        savePlaylists(playlists);
        res.json({ success: true, playlist });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.delete("/api/playlists/:id", requireAuth, csrfProtection, (req, res) => {
    try {
        const playlists = loadPlaylists();
        const playlist = playlists[req.params.id];
        if (!playlist) {
            return res.status(404).json({ success: false, error: "プレイリストが見つかりません" });
        }
        if (playlist.username !== req.session.userId) {
            return res.status(403).json({ success: false, error: "自分のプレイリストのみ削除できます" });
        }
        delete playlists[req.params.id];
        savePlaylists(playlists);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post("/api/playlists/:id/videos", requireAuth, csrfProtection, (req, res) => {
    try {
        const { filename } = req.body;
        if (!filename) {
            return res.status(400).json({ success: false, error: "動画が指定されていません" });
        }

        const metadata = loadMetadata();
        if (!metadata[filename]) {
            return res.status(404).json({ success: false, error: "動画が見つかりません" });
        }

        const playlists = loadPlaylists();
        const playlist = playlists[req.params.id];
        if (!playlist) {
            return res.status(404).json({ success: false, error: "プレイリストが見つかりません" });
        }
        if (playlist.username !== req.session.userId) {
            return res.status(403).json({ success: false, error: "自分のプレイリストのみ編集できます" });
        }

        if (!playlist.videoFilenames.includes(filename)) {
            playlist.videoFilenames.push(filename);
            playlist.updatedAt = new Date().toISOString();
            savePlaylists(playlists);
        }

        res.json({ success: true, playlist });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.delete("/api/playlists/:id/videos/:filename", requireAuth, csrfProtection, (req, res) => {
    try {
        const playlists = loadPlaylists();
        const playlist = playlists[req.params.id];
        if (!playlist) {
            return res.status(404).json({ success: false, error: "プレイリストが見つかりません" });
        }
        if (playlist.username !== req.session.userId) {
            return res.status(403).json({ success: false, error: "自分のプレイリストのみ編集できます" });
        }

        const idx = playlist.videoFilenames.indexOf(req.params.filename);
        if (idx !== -1) {
            playlist.videoFilenames.splice(idx, 1);
            playlist.updatedAt = new Date().toISOString();
            savePlaylists(playlists);
        }

        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get("/api/playlists/public/:username", (req, res) => {
    try {
        const playlists = loadPlaylists();
        const userPlaylists = Object.values(playlists)
            .filter(p => p.username === req.params.username && p.isPublic)
            .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));

        const result = userPlaylists.map(p => {
            const metadata = loadMetadata();
            const files = readVideoFiles();
            const validVideos = p.videoFilenames.filter(f => files.includes(f) && metadata[f]);
            const firstVideo = validVideos.length > 0 ? metadata[validVideos[0]] : null;
            return {
                id: p.id,
                title: p.title,
                description: p.description,
                username: p.username,
                videoCount: validVideos.length,
                firstVideoThumbnail: validVideos.length > 0 ? getVideoThumbnailUrl(validVideos[0]) : null,
                createdAt: p.createdAt,
                updatedAt: p.updatedAt
            };
        });

        res.json({ success: true, playlists: result });
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