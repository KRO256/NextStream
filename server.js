const express = require("express");
const multer = require("multer");
const fs = require("fs");
const fsp = fs.promises;
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");
const crypto = require("crypto");
const helmet = require("helmet");
const { spawn, spawnSync } = require("child_process");
require("dotenv").config();

const app = express();
const PORT = 3000;

app.use(express.json({ limit: "10mb" }));

app.use(express.urlencoded({
    extended: true,
    limit: "10mb"
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
        sameSite: "strict",
        secure: process.env.NODE_ENV === "production",
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
const historyPath = path.join(__dirname, "history.json");
const reportsPath = path.join(__dirname, "reports.json");

[uploadDir, hlsDir, tempDir, chunksDir, thumbnailsDir, avatarsDir].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir);
    }
});

async function loadMetadata() {
    try {
        return JSON.parse(await fsp.readFile(metadataPath, "utf8"));
    } catch {
        return {};
    }
}

async function saveMetadata(data) {
    await fsp.writeFile(metadataPath, JSON.stringify(data, null, 2));
}

async function loadUsers() {
    try {
        return JSON.parse(await fsp.readFile(usersPath, "utf8"));
    } catch {
        return {};
    }
}

async function saveUsers(data) {
    await fsp.writeFile(usersPath, JSON.stringify(data, null, 2));
}

async function loadSubscriptions() {
    try {
        return JSON.parse(await fsp.readFile(subscriptionsPath, "utf8"));
    } catch {
        return {};
    }
}

async function saveSubscriptions(data) {
    await fsp.writeFile(subscriptionsPath, JSON.stringify(data, null, 2));
}

async function loadViews() {
    try {
        const data = JSON.parse(await fsp.readFile(viewsPath, "utf8"));
        return (data && typeof data === "object" && !Array.isArray(data)) ? data : {};
    } catch {
        return {};
    }
}

async function saveViews(data) {
    await fsp.writeFile(viewsPath, JSON.stringify(data, null, 2));
}

async function loadComments() {
    try {
        return JSON.parse(await fsp.readFile(commentsPath, "utf8"));
    } catch {
        return {};
    }
}

async function saveComments(data) {
    await fsp.writeFile(commentsPath, JSON.stringify(data, null, 2));
}

async function loadBookmarks() {
    try {
        return JSON.parse(await fsp.readFile(bookmarksPath, "utf8"));
    } catch {
        return {};
    }
}

async function saveBookmarks(data) {
    await fsp.writeFile(bookmarksPath, JSON.stringify(data, null, 2));
}

async function loadProgress() {
    try {
        return JSON.parse(await fsp.readFile(progressPath, "utf8"));
    } catch {
        return {};
    }
}

async function saveProgress(data) {
    await fsp.writeFile(progressPath, JSON.stringify(data, null, 2));
}

async function loadProfiles() {
    try {
        return JSON.parse(await fsp.readFile(profilesPath, "utf8"));
    } catch {
        return {};
    }
}

async function saveProfiles(data) {
    await fsp.writeFile(profilesPath, JSON.stringify(data, null, 2));
}

async function loadNotifications() {
    try {
        return JSON.parse(await fsp.readFile(notificationsPath, "utf8"));
    } catch {
        return {};
    }
}

async function saveNotifications(data) {
    await fsp.writeFile(notificationsPath, JSON.stringify(data, null, 2));
}

async function loadPlaylists() {
    try {
        return JSON.parse(await fsp.readFile(playlistsPath, "utf8"));
    } catch {
        return {};
    }
}

async function savePlaylists(data) {
    await fsp.writeFile(playlistsPath, JSON.stringify(data, null, 2));
}

async function loadHistory() {
    try {
        return JSON.parse(await fsp.readFile(historyPath, "utf8"));
    } catch {
        return {};
    }
}

async function saveHistory(data) {
    await fsp.writeFile(historyPath, JSON.stringify(data, null, 2));
}

async function loadReports() {
    try {
        return JSON.parse(await fsp.readFile(reportsPath, "utf8"));
    } catch {
        return [];
    }
}

async function saveReports(data) {
    await fsp.writeFile(reportsPath, JSON.stringify(data, null, 2));
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

function authStatic(dir) {
    return (req, res, next) => {
        if (!req.session || !req.session.userId) {
            return res.status(401).json({ success: false, error: "認証が必要です" });
        }
        express.static(dir)(req, res, next);
    };
}

function isValidFilename(name) {
    return typeof name === "string" && name.length > 0 && name.length <= 255 && /^[a-zA-Z0-9._-]+$/.test(name) && !name.includes("..");
}

app.use("/videos", authStatic(uploadDir));
app.use("/hls", authStatic(hlsDir));
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

        const users = await loadUsers();

        if (users[username]) {
            return res.status(409).json({ success: false, error: "このユーザー名は既に使用されています" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const isAdmin = adminUsername && username === adminUsername && Object.keys(users).length === 0;
        users[username] = { password: hashedPassword, createdAt: new Date().toISOString(), admin: isAdmin || undefined };
        await saveUsers(users);

        await new Promise((resolve, reject) => {
            req.session.regenerate(err => {
                if (err) return reject(err);
                resolve();
            });
        });
        req.session.userId = username;
        if (isAdmin) req.session.isAdmin = true;
        req.session.csrfToken = crypto.randomUUID();
        res.json({ success: true, user: username, csrfToken: req.session.csrfToken });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
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

        const users = await loadUsers();
        const user = users[username];

        if (!user) {
            return res.status(401).json({ success: false, error: "ユーザー名またはパスワードが間違っています" });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ success: false, error: "ユーザー名またはパスワードが間違っています" });
        }

        await new Promise((resolve, reject) => {
            req.session.regenerate(err => {
                if (err) return reject(err);
                resolve();
            });
        });
        req.session.userId = username;
        if (user.admin) req.session.isAdmin = true;
        req.session.csrfToken = crypto.randomUUID();
        res.json({ success: true, user: username, csrfToken: req.session.csrfToken });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.get("/api/csrf-token", async (req, res) => {
    res.json({ success: true, csrfToken: req.session.csrfToken });
});

app.post("/api/logout", csrfProtection, async (req, res) => {
    req.session.destroy(err => {
        if (err) console.error(err);
        res.json({ success: true });
    });
});

app.get("/api/me", async (req, res) => {
    if (req.session.userId) {
        res.json({ success: true, user: req.session.userId, isAdmin: req.session.isAdmin || false, csrfToken: req.session.csrfToken });
    } else {
        res.json({ success: false, user: null, isAdmin: false });
    }
});

app.delete("/api/account", requireAuth, csrfProtection, async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) {
            return res.status(400).json({ success: false, error: "パスワードを入力してください" });
        }

        const users = await loadUsers();
        const user = users[req.session.userId];

        if (!user) {
            return res.status(404).json({ success: false, error: "ユーザーが見つかりません" });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ success: false, error: "パスワードが間違っています" });
        }

        const username = req.session.userId;
        delete users[username];
        await saveUsers(users);

        const profiles = await loadProfiles();
        if (profiles[username]) {
            if (profiles[username].avatar) {
                const avatarFile = path.join(avatarsDir, path.basename(profiles[username].avatar));
                try { await fsp.unlink(avatarFile); } catch {}
            }
            delete profiles[username];
            await saveProfiles(profiles);
        }

        const notifications = await loadNotifications();
        delete notifications[username];
        await saveNotifications(notifications);

        const metadata = await loadMetadata();
        const userVideos = Object.keys(metadata).filter(k => metadata[k].uploadedBy === username);
        for (const fn of userVideos) {
            const fp = path.join(uploadDir, fn);
            try { await fsp.unlink(fp); } catch {}
            const hls = path.join(hlsDir, fn);
            try { await fsp.rm(hls, { recursive: true, force: true }); } catch {}
            delete metadata[fn];
        }
        await saveMetadata(metadata);

        const comments = await loadComments();
        for (const fn of Object.keys(comments)) {
            comments[fn] = comments[fn].filter(c => c.username !== username);
            if (comments[fn].length === 0) delete comments[fn];
        }
        await saveComments(comments);

        const bookmarks = await loadBookmarks();
        delete bookmarks[username];
        for (const user of Object.keys(bookmarks)) {
            bookmarks[user] = bookmarks[user].filter(f => !userVideos.includes(f));
        }
        await saveBookmarks(bookmarks);

        const subs = await loadSubscriptions();
        delete subs[username];
        for (const user of Object.keys(subs)) {
            subs[user] = subs[user].filter(s => s !== username);
        }
        await saveSubscriptions(subs);

        const history = await loadHistory();
        delete history[username];
        await saveHistory(history);

        const playlists = await loadPlaylists();
        for (const [pid, pl] of Object.entries(playlists)) {
            if (pl.username === username) {
                delete playlists[pid];
            } else {
                pl.videoFilenames = pl.videoFilenames.filter(f => !userVideos.includes(f));
            }
        }
        await savePlaylists(playlists);

        await new Promise((resolve, reject) => {
            req.session.destroy(err => {
                if (err) return reject(err);
                resolve();
            });
        });
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

async function readVideoFiles() {
    try {
        const entries = await fsp.readdir(uploadDir);
        const results = [];
        for (const f of entries) {
            try {
                const stat = await fsp.stat(path.join(uploadDir, f));
                if (stat.isFile()) results.push(f);
            } catch {}
        }
        return results;
    } catch {
        return [];
    }
}

function getVideoUrl(file, meta) {
    return meta && meta.hls ? "/hls/" + file + "/index.m3u8" : "/videos/" + file;
}

async function getVideoThumbnailUrl(file) {
    try {
        await fsp.access(path.join(thumbnailsDir, file + ".jpg"));
        return "/thumbnails/" + file + ".jpg";
    } catch {
        return null;
    }
}

app.post("/upload-chunk", requireAuth, csrfProtection, rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    keyFn: req => "upload:" + req.session.userId,
    message: "アップロードは1時間に5回までです"
}), upload.single("chunk"), async (req, res) => {

    try {

        const {
            fileId,
            chunkIndex,
            totalChunks,
            fileName,
            title,
            description,
            tags,
            license
        } = req.body;

        if (typeof fileId !== "string" || !/^[a-zA-Z0-9_-]+$/.test(fileId)) {
            return res.status(400).json({ success: false, error: "無効なファイルIDです" });
        }

        const parsedChunkIndex = parseInt(chunkIndex, 10);
        if (!Number.isInteger(parsedChunkIndex) || parsedChunkIndex < 0) {
            return res.status(400).json({ success: false, error: "無効なチャンクインデックスです" });
        }

        const parsedTotalChunks = parseInt(totalChunks, 10);
        if (!Number.isInteger(parsedTotalChunks) || parsedTotalChunks < 1 || parsedTotalChunks > 200) {
            return res.status(400).json({ success: false, error: "無効なチャンク総数です" });
        }

        const dir = path.join(chunksDir, fileId);

        try { await fsp.mkdir(dir, { recursive: true }); } catch {}

        const chunkPath = path.join(dir, String(parsedChunkIndex));

        try {
            await fsp.rename(req.file.path, chunkPath);
        } catch (e) {
            if (e.code === "EXDEV") {
                await fsp.copyFile(req.file.path, chunkPath);
                await fsp.unlink(req.file.path);
            } else {
                throw e;
            }
        }

        const uploadedChunks = await fsp.readdir(dir);

        if (uploadedChunks.length === parsedTotalChunks) {

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

            const validLicenses = ["all_rights_reserved", "cc_by", "cc_by_sa", "cc_by_nc", "cc_by_nc_sa", "cc_by_nd", "cc_by_nc_nd", "public_domain", "royalty_free", "other"];
            const licenseVal = license && validLicenses.includes(license) ? license : "all_rights_reserved";

            const safeName =
                Date.now() +
                "_" +
                (fileName || "video").replace(/[^a-zA-Z0-9._-]/g, "_");

            const finalPath = path.join(uploadDir, safeName);

            let writeError = null;
            const writeStream = fs.createWriteStream(finalPath);
            writeStream.on("error", err => {
                writeError = err;
                console.error("writeStream error:", err);
            });

            for (let i = 0; i < parsedTotalChunks; i++) {

                const chunkFile = path.join(dir, String(i));

                const chunkData = await fsp.readFile(chunkFile);

                writeStream.write(chunkData);
            }

            writeStream.end();

            writeStream.on("finish", async () => {
                if (writeError) {
                    try { await fsp.rm(dir, { recursive: true, force: true }); } catch {}
                    try { await fsp.unlink(finalPath); } catch {}
                    return res.status(500).json({ success: false, error: "ファイル書き込みエラーが発生しました" });
                }

                try { await fsp.rm(dir, { recursive: true, force: true }); } catch {}

                const metadata = await loadMetadata();

                let duration = 0;
                try {
                    const result = await new Promise((resolve, reject) => {
                        const proc = spawn("ffprobe", [
                            "-v", "error",
                            "-show_entries", "format=duration",
                            "-of", "default=noprint_wrappers=1:nokey=1",
                            finalPath
                        ]);
                        let stdout = "";
                        let stderr = "";
                        proc.stdout.on("data", d => stdout += d.toString());
                        proc.stderr.on("data", d => stderr += d.toString());
                        proc.on("close", code => {
                            if (code === 0) resolve(stdout.trim());
                            else reject(new Error(stderr));
                        });
                        proc.on("error", reject);
                    });
                    duration = parseFloat(result) || 0;
                } catch (e) {
                    console.error("ffprobe failed for", safeName, e.message);
                }

                metadata[safeName] = {
                    title: title || safeName,
                    description: description || "",
                    tags: tagList,
                    license: licenseVal,
                    uploadedBy: req.session.userId,
                    likes: [],
                    views: 0,
                    duration: duration,
                    qualities: ["360p", "480p", "720p"]
                };
                await saveMetadata(metadata);

                console.log("UPLOAD COMPLETE:", safeName);

                res.json({ success: true });

                const videoHlsDir = path.join(hlsDir, safeName);
                try { await fsp.mkdir(videoHlsDir, { recursive: true }); } catch {}

                const ffmpeg = spawn("ffmpeg", [
                    "-i", finalPath,
                    "-filter_complex",
                    "[0:v]split=3[v1][v2][v3];[v1]scale=-2:360[v1out];[v2]scale=-2:480[v2out];[v3]scale=-2:720[v3out]",
                    "-preset", "fast",
                    "-map", "[v1out]", "-c:v:0", "libx264", "-b:v:0", "800k", "-maxrate:v:0", "856k", "-bufsize:v:0", "1200k",
                    "-map", "[v2out]", "-c:v:1", "libx264", "-b:v:1", "1400k", "-maxrate:v:1", "1498k", "-bufsize:v:1", "2100k",
                    "-map", "[v3out]", "-c:v:2", "libx264", "-b:v:2", "2800k", "-maxrate:v:2", "2996k", "-bufsize:v:2", "4200k",
                    "-map", "a:0", "-c:a", "aac", "-b:a", "128k",
                    "-f", "hls",
                    "-hls_time", "10",
                    "-hls_playlist_type", "vod",
                    "-hls_segment_filename",
                    path.join(videoHlsDir, "segment_%v_%03d.ts"),
                    "-master_pl_name", "index.m3u8",
                    "-var_stream_map", "v:0,a:0 v:1,a:0 v:2,a:0",
                    path.join(videoHlsDir, "%v.m3u8")
                ]);

                const ffmpegTimeout = setTimeout(() => {
                    console.error("ffmpeg HLS timeout for", safeName);
                    ffmpeg.kill("SIGKILL");
                }, 5 * 60 * 1000);

                ffmpeg.stderr.on("data", data => {
                    console.log("ffmpeg:", data.toString());
                });

                ffmpeg.on("close", async (code) => {
                    clearTimeout(ffmpegTimeout);
                    if (code === 0) {
                        const meta = await loadMetadata();
                        if (meta[safeName]) {
                            meta[safeName].hls = true;
                            await saveMetadata(meta);
                        }
                        console.log("HLS READY:", safeName);

                        const uploader = req.session.userId;
                        const videoTitle = meta[safeName]?.title || safeName;
                        try {
                            const subs = await loadSubscriptions();
                            const subscribers = subs[uploader] || [];
                            if (subscribers.length > 0) {
                                const notifications = await loadNotifications();
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
                                await saveNotifications(notifications);
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
                        const thumbTimeout = setTimeout(() => {
                            console.error("ffmpeg thumbnail timeout for", safeName);
                            ffmpegThumb.kill("SIGKILL");
                        }, 60 * 1000);

                        ffmpegThumb.on("close", thumbCode => {
                            clearTimeout(thumbTimeout);
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
        } else {
            res.json({ success: true });
        }

    } catch (err) {

        console.error(err);

        try { await fsp.rm(dir, { recursive: true, force: true }); } catch {}
        try { await fsp.unlink(finalPath); } catch {}

        res.status(500).json({
            success: false,
            error: "サーバーエラーが発生しました"
        });
    }
});

app.patch("/video/:filename", requireAuth, csrfProtection, async (req, res) => {

    try {

        const { title, description, tags, license } = req.body;

        const metadata = await loadMetadata();
        const video = metadata[req.params.filename];

        if (video) {
            if (video.uploadedBy !== req.session.userId) {
                return res.status(403).json({ success: false, error: "自分の動画のみ編集できます" });
            }

            if (!isValidFilename(req.params.filename)) {
                return res.status(400).json({ success: false, error: "無効なファイル名です" });
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
                const tagList = (Array.isArray(tags) ? tags : tags.split(",").map(t => t.trim()).filter(Boolean))
                    .filter(t => typeof t === "string");
                if (tagList.some(t => t.length > 20)) {
                    return res.status(400).json({ success: false, error: "各タグは20文字以内で入力してください" });
                }
                if (tagList.length > 10) {
                    return res.status(400).json({ success: false, error: "タグは最大10個までです" });
                }
                metadata[req.params.filename].tags = tagList;
            }

            if (license !== undefined) {
                const validLicenses = ["all_rights_reserved", "cc_by", "cc_by_sa", "cc_by_nc", "cc_by_nc_sa", "cc_by_nd", "cc_by_nc_nd", "public_domain", "royalty_free", "other"];
                if (!validLicenses.includes(license)) {
                    return res.status(400).json({ success: false, error: "無効なライセンスです" });
                }
                metadata[req.params.filename].license = license;
            }

            await saveMetadata(metadata);

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
            error: "サーバーエラーが発生しました"
        });
    }
});

app.post("/api/video/:filename/like", requireAuth, csrfProtection, async (req, res) => {
    try {
        const metadata = await loadMetadata();
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

        await saveMetadata(metadata);

        res.json({
            success: true,
            liked: userIndex === -1,
            likes: video.likes.length
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.post("/api/video/:filename/bookmark", requireAuth, csrfProtection, async (req, res) => {
    try {
        const bookmarks = await loadBookmarks();
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
        await saveBookmarks(bookmarks);
        res.json({
            success: true,
            bookmarked: idx === -1
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.get("/api/bookmarks", requireAuth, async (req, res) => {
    try {
        const bookmarks = await loadBookmarks();
        const userBookmarks = bookmarks[req.session.userId] || [];
        const files = await readVideoFiles();
        const metadata = await loadMetadata();
        const videos = [];
        for (const file of userBookmarks) {
            if (!files.includes(file) || !metadata[file]) continue;
            const meta = metadata[file] || {};
            videos.push({
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
                thumbnailUrl: await getVideoThumbnailUrl(file),
                duration: meta.duration || 0
            });
        }
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
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.post("/api/video/:filename/progress", requireAuth, csrfProtection, async (req, res) => {
    try {
        const { time } = req.body;
        if (typeof time !== "number" || time < 0) {
            return res.status(400).json({ success: false, error: "再生時間が無効です" });
        }
        const progress = await loadProgress();
        const user = req.session.userId;
        if (!progress[user]) progress[user] = {};
        progress[user][req.params.filename] = time;
        await saveProgress(progress);

        const metadata = await loadMetadata();
        const meta = metadata[req.params.filename];
        const history = await loadHistory();
        if (!history[user]) history[user] = [];
        const existingIdx = history[user].findIndex(h => h.filename === req.params.filename);
        const entry = {
            filename: req.params.filename,
            title: meta?.title || req.params.filename,
            watchedAt: Date.now(),
            progress: time,
            duration: meta?.duration || 0
        };
        if (existingIdx !== -1) {
            history[user][existingIdx] = entry;
        } else {
            history[user].push(entry);
        }
        await saveHistory(history);

        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.get("/api/video/:filename/progress", requireAuth, async (req, res) => {
    try {
        const progress = await loadProgress();
        const userData = progress[req.session.userId];
        const time = userData ? userData[req.params.filename] : null;
        res.json({ success: true, time: time || 0 });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.get("/api/history", requireAuth, async (req, res) => {
    try {
        const history = await loadHistory();
        const userHistory = history[req.session.userId] || [];
        userHistory.sort((a, b) => b.watchedAt - a.watchedAt);

        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 30, 100);
        const start = (page - 1) * limit;
        const total = userHistory.length;
        const totalPages = Math.ceil(total / limit);
        const paged = userHistory.slice(start, start + limit);

        const metadata = await loadMetadata();
        const videos = [];
        for (const h of paged) {
            const meta = metadata[h.filename] || {};
            videos.push({
                name: h.filename,
                url: getVideoUrl(h.filename, meta),
                title: meta.title || h.filename,
                description: meta.description || "",
                tags: meta.tags || [],
                uploadedBy: meta.uploadedBy || null,
                likes: meta.likes?.length || 0,
                views: meta.views || 0,
                thumbnailUrl: await getVideoThumbnailUrl(h.filename),
                progress: h.progress || 0,
                duration: meta.duration || 0
            });
        }

        res.json({ videos, total, page, limit, totalPages });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.delete("/api/history", requireAuth, csrfProtection, async (req, res) => {
    try {
        const history = await loadHistory();
        delete history[req.session.userId];
        await saveHistory(history);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.post("/api/video/:filename/report", requireAuth, csrfProtection, rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    keyFn: req => "report:" + req.session.userId,
    message: "通報は1時間に3回までです"
}), async (req, res) => {
    try {
        const { reason, details } = req.body;
        if (!reason || !reason.trim()) {
            return res.status(400).json({ success: false, error: "通報理由を選択してください" });
        }
        const validReasons = ["spam", "inappropriate", "copyright", "harassment", "other"];
        if (!validReasons.includes(reason)) {
            return res.status(400).json({ success: false, error: "無効な通報理由です" });
        }
        if (details && details.length > 1000) {
            return res.status(400).json({ success: false, error: "詳細は1000文字以内で入力してください" });
        }

        const metadata = await loadMetadata();
        if (!metadata[req.params.filename]) {
            return res.status(404).json({ success: false, error: "Video not found" });
        }

        const reports = await loadReports();
        const report = {
            id: crypto.randomUUID(),
            filename: req.params.filename,
            videoTitle: metadata[req.params.filename]?.title || req.params.filename,
            reportedBy: req.session.userId,
            reason,
            details: (details || "").trim(),
            createdAt: new Date().toISOString()
        };
        reports.push(report);
        await saveReports(reports);

        res.json({ success: true, report });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.post("/api/channel/:username/subscribe", requireAuth, csrfProtection, async (req, res) => {
    try {
        const channel = req.params.username;
        const user = req.session.userId;

        if (channel === user) {
            return res.status(400).json({ success: false, error: "自分自身を登録できません" });
        }

        const users = await loadUsers();
        if (!users[channel]) {
            return res.status(404).json({ success: false, error: "チャンネルが見つかりません" });
        }

        const subscriptions = await loadSubscriptions();
        if (!subscriptions[channel]) {
            subscriptions[channel] = [];
        }

        const idx = subscriptions[channel].indexOf(user);
        if (idx === -1) {
            subscriptions[channel].push(user);
        } else {
            subscriptions[channel].splice(idx, 1);
        }

        await saveSubscriptions(subscriptions);

        res.json({
            success: true,
            subscribed: idx === -1,
            subscribers: subscriptions[channel].length
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.get("/api/channel/:username/subscribers", async (req, res) => {
    try {
        const channel = req.params.username;
        const subscriptions = await loadSubscriptions();
        const subs = subscriptions[channel] || [];

        res.json({
            success: true,
            subscribers: subs.length,
            subscribed: req.session.userId ? subs.includes(req.session.userId) : false
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.get("/api/notifications", requireAuth, async (req, res) => {
    try {
        const notifications = await loadNotifications();
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
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.get("/api/notifications/unread-count", requireAuth, async (req, res) => {
    try {
        const notifications = await loadNotifications();
        const userNotifs = notifications[req.session.userId] || [];
        const unread = userNotifs.filter(n => !n.read).length;
        res.json({ success: true, unread });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.post("/api/notifications/read", requireAuth, csrfProtection, async (req, res) => {
    try {
        const notifications = await loadNotifications();
        if (notifications[req.session.userId]) {
            for (const n of notifications[req.session.userId]) {
                n.read = true;
            }
            await saveNotifications(notifications);
        }
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.post("/api/notifications/read/:id", requireAuth, csrfProtection, async (req, res) => {
    try {
        const notifications = await loadNotifications();
        const userNotifs = notifications[req.session.userId];
        if (userNotifs) {
            const notif = userNotifs.find(n => n.id === req.params.id);
            if (notif) {
                notif.read = true;
                await saveNotifications(notifications);
            }
        }
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.get("/api/profile/:username", async (req, res) => {
    try {
        const profiles = await loadProfiles();
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
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.put("/api/profile", requireAuth, csrfProtection, async (req, res) => {
    try {
        const { bio, removeAvatar } = req.body;
        if (bio !== undefined && bio.length > 500) {
            return res.status(400).json({ success: false, error: "プロフィール文は500文字以内で入力してください" });
        }
        const profiles = await loadProfiles();
        if (!profiles[req.session.userId]) {
            profiles[req.session.userId] = {};
        }
        if (bio !== undefined) {
            profiles[req.session.userId].bio = bio;
        }
        if (removeAvatar) {
            if (profiles[req.session.userId].avatar) {
                const avatarFile = path.join(avatarsDir, path.basename(profiles[req.session.userId].avatar));
                try { await fsp.unlink(avatarFile); } catch {}
            }
            profiles[req.session.userId].avatar = null;
        }
        await saveProfiles(profiles);
        res.json({ success: true, profile: { bio: profiles[req.session.userId].bio || "", avatar: profiles[req.session.userId].avatar || null } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
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

app.post("/api/profile/avatar", requireAuth, csrfProtection, async (req, res) => {
    avatarUpload.single("avatar")(req, res, async err => {
        if (err) {
            if (err instanceof multer.MulterError) {
                if (err.code === "LIMIT_FILE_SIZE") {
                    return res.status(400).json({ success: false, error: "ファイルサイズは2MB以下にしてください" });
                }
                return res.status(400).json({ success: false, error: "サーバーエラーが発生しました" });
            }
            return res.status(400).json({ success: false, error: "サーバーエラーが発生しました" });
        }
        if (!req.file) {
            return res.status(400).json({ success: false, error: "画像ファイルを選択してください" });
        }
        try {
            const profiles = await loadProfiles();
            if (!profiles[req.session.userId]) {
                profiles[req.session.userId] = {};
            }
            if (profiles[req.session.userId].avatar) {
                const oldAvatar = path.join(avatarsDir, path.basename(profiles[req.session.userId].avatar));
                try { await fsp.unlink(oldAvatar); } catch {}
            }
            const avatarUrl = "/avatars/" + req.file.filename;
            profiles[req.session.userId].avatar = avatarUrl;
            await saveProfiles(profiles);
            res.json({ success: true, avatar: avatarUrl });
        } catch (e) {
            console.error(e);
            res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
        }
    });
});

app.get("/api/settings/notifications", requireAuth, async (req, res) => {
    try {
        const profiles = await loadProfiles();
        const profile = profiles[req.session.userId] || {};
        res.json({ success: true, enabled: profile.notificationsEnabled !== false });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.put("/api/settings/notifications", requireAuth, csrfProtection, async (req, res) => {
    try {
        const { enabled } = req.body;
        const profiles = await loadProfiles();
        if (!profiles[req.session.userId]) {
            profiles[req.session.userId] = {};
        }
        profiles[req.session.userId].notificationsEnabled = enabled === true;
        await saveProfiles(profiles);
        res.json({ success: true, enabled: profiles[req.session.userId].notificationsEnabled });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.post("/api/settings/password", requireAuth, csrfProtection, async (req, res) => {
    try {
        const { currentPassword, newPassword, confirmPassword } = req.body;
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ success: false, error: "現在のパスワードと新しいパスワードを入力してください" });
        }
        if (newPassword.length < 6) {
            return res.status(400).json({ success: false, error: "新しいパスワードは6文字以上で入力してください" });
        }
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ success: false, error: "新しいパスワードと確認用パスワードが一致しません" });
        }
        if (currentPassword === newPassword) {
            return res.status(400).json({ success: false, error: "新しいパスワードは現在のパスワードと異なるものを設定してください" });
        }

        const users = await loadUsers();
        const user = users[req.session.userId];
        if (!user) {
            return res.status(404).json({ success: false, error: "ユーザーが見つかりません" });
        }

        const match = await bcrypt.compare(currentPassword, user.password);
        if (!match) {
            return res.status(401).json({ success: false, error: "現在のパスワードが間違っています" });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        await saveUsers(users);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.post("/api/video/:filename/comment", requireAuth, csrfProtection, rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    keyFn: req => "comment:" + req.session.userId,
    message: "コメントの投稿は15分間に20回までです"
}), async (req, res) => {
    try {
        const { text } = req.body;
        if (!text || !text.trim()) {
            return res.status(400).json({ success: false, error: "コメントを入力してください" });
        }
        if (text.length > 500) {
            return res.status(400).json({ success: false, error: "コメントは500文字以内で入力してください" });
        }

        const metadata = await loadMetadata();
        if (!metadata[req.params.filename]) {
            return res.status(404).json({ success: false, error: "Video not found" });
        }

        const comments = await loadComments();
        if (!comments[req.params.filename]) {
            comments[req.params.filename] = [];
        }

        const comment = {
            id: crypto.randomUUID(),
            username: req.session.userId,
            text: text.trim(),
            createdAt: new Date().toISOString()
        };

        comments[req.params.filename].push(comment);
        await saveComments(comments);

        res.json({ success: true, comment });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.get("/api/video/:filename/comments", async (req, res) => {
    try {
        const comments = await loadComments();
        const list = comments[req.params.filename] || [];
        res.json({ success: true, comments: list });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.delete("/api/video/:filename/comment/:id", requireAuth, csrfProtection, async (req, res) => {
    try {
        const comments = await loadComments();
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
        await saveComments(comments);

        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.post("/api/video/:filename/view", requireAuth, rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    keyFn: req => "view:" + req.session.userId + ":" + req.params.filename,
    message: "視聴数の更新は1分間に10回までです"
}), csrfProtection, async (req, res) => {
    try {
        const metadata = await loadMetadata();
        const video = metadata[req.params.filename];

        if (!video) {
            return res.status(404).json({ success: false, error: "Video not found" });
        }

        video.views = (video.views || 0) + 1;
        await saveMetadata(metadata);

        const now = Date.now();
        const views = await loadViews();
        if (!views[req.params.filename]) {
            views[req.params.filename] = [];
        }
        views[req.params.filename].push(now);
        await saveViews(views);

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
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.delete("/api/video/:filename", requireAuth, csrfProtection, async (req, res) => {
    try {
        if (!isValidFilename(req.params.filename)) {
            return res.status(400).json({ success: false, error: "無効なファイル名です" });
        }
        const metadata = await loadMetadata();
        const video = metadata[req.params.filename];

        if (!video) {
            return res.status(404).json({ success: false, error: "Video not found" });
        }

        if (video.uploadedBy !== req.session.userId) {
            return res.status(403).json({ success: false, error: "自分の動画のみ削除できます" });
        }

        const filePath = path.join(uploadDir, req.params.filename);
        try { await fsp.unlink(filePath); } catch {}

        const videoHlsDir = path.join(hlsDir, req.params.filename);
        try { await fsp.rm(videoHlsDir, { recursive: true, force: true }); } catch {}

        delete metadata[req.params.filename];
        await saveMetadata(metadata);

        const comments = await loadComments();
        delete comments[req.params.filename];
        await saveComments(comments);

        const views = await loadViews();
        delete views[req.params.filename];
        await saveViews(views);

        const bookmarks = await loadBookmarks();
        for (const user of Object.keys(bookmarks)) {
            const idx = bookmarks[user].indexOf(req.params.filename);
            if (idx !== -1) {
                bookmarks[user].splice(idx, 1);
            }
        }
        await saveBookmarks(bookmarks);

        const playlists = await loadPlaylists();
        for (const playlist of Object.values(playlists)) {
            const idx = playlist.videoFilenames.indexOf(req.params.filename);
            if (idx !== -1) {
                playlist.videoFilenames.splice(idx, 1);
            }
        }
        await savePlaylists(playlists);

        const history = await loadHistory();
        for (const user of Object.keys(history)) {
            history[user] = history[user].filter(h => h.filename !== req.params.filename);
            if (history[user].length === 0) delete history[user];
        }
        await saveHistory(history);

        const reports = await loadReports();
        const remainingReports = reports.filter(r => r.filename !== req.params.filename);
        if (remainingReports.length !== reports.length) {
            await saveReports(remainingReports);
        }

        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.get("/api/video/:filename", async (req, res) => {
    try {
        const metadata = await loadMetadata();
        const video = metadata[req.params.filename];
        if (!video) {
            return res.status(404).json({ success: false, error: "Video not found" });
        }
        const bookmarks = await loadBookmarks();
        const userBookmarks = bookmarks[req.session.userId] || [];
        res.json({
            success: true,
            video: {
                name: req.params.filename,
                url: getVideoUrl(req.params.filename, video),
                title: video.title || req.params.filename,
                description: video.description || "",
                tags: video.tags || [],
                license: video.license || "all_rights_reserved",
                uploadedBy: video.uploadedBy || null,
                likes: video.likes?.length || 0,
                likedByUser: req.session.userId && video.likes?.includes(req.session.userId) || false,
                bookmarkedByUser: req.session.userId && userBookmarks.includes(req.params.filename) || false,
                views: video.views || 0,
                thumbnailUrl: await getVideoThumbnailUrl(req.params.filename),
                duration: video.duration || 0
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.get("/list", async (req, res) => {

    const files = await readVideoFiles();

    const metadata = await loadMetadata();
    const bookmarks = await loadBookmarks();
    const userBookmarks = bookmarks[req.session.userId] || [];

    const videos = [];
    for (const file of files) {
        const meta = metadata[file] || {};
        videos.push({
            name: file,
            url: getVideoUrl(file, meta),
            title: meta.title || file,
            description: meta.description || "",
            tags: meta.tags || [],
            license: meta.license || "all_rights_reserved",
            uploadedBy: meta.uploadedBy || null,
            likes: meta.likes?.length || 0,
            likedByUser: req.session.userId && meta.likes?.includes(req.session.userId) || false,
            bookmarkedByUser: req.session.userId && userBookmarks.includes(file) || false,
            views: meta.views || 0,
            thumbnailUrl: await getVideoThumbnailUrl(file),
            duration: meta.duration || 0
        });
    }

    videos.reverse();

    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 30, 100);
    const start = (page - 1) * limit;
    const total = videos.length;
    const totalPages = Math.ceil(total / limit);
    const paged = videos.slice(start, start + limit);

    res.json({ videos: paged, total, page, limit, totalPages });
});

app.get("/channel/:username", async (req, res) => {
    const username = req.params.username;
    const files = await readVideoFiles();
    const metadata = await loadMetadata();
    const bookmarks = await loadBookmarks();
    const userBookmarks = bookmarks[req.session.userId] || [];

    const videos = [];
    for (const file of files) {
        const meta = metadata[file];
        if (!meta || meta.uploadedBy !== username) continue;
        videos.push({
            name: file,
            url: getVideoUrl(file, meta),
            title: meta.title || file,
            description: meta.description || "",
            tags: meta.tags || [],
            license: meta.license || "all_rights_reserved",
            uploadedBy: meta.uploadedBy || null,
            likes: meta.likes?.length || 0,
            likedByUser: req.session.userId && meta.likes?.includes(req.session.userId) || false,
            bookmarkedByUser: req.session.userId && userBookmarks.includes(file) || false,
            views: meta.views || 0,
            thumbnailUrl: await getVideoThumbnailUrl(file),
            duration: meta.duration || 0
        });
    }

    videos.reverse();

    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 30, 100);
    const start = (page - 1) * limit;
    const total = videos.length;
    const totalPages = Math.ceil(total / limit);
    const paged = videos.slice(start, start + limit);

    res.json({ videos: paged, total, page, limit, totalPages });
});

app.get("/search", async (req, res) => {

    const q = (req.query.q || "").toLowerCase().trim();

    if (!q) {
        return res.json({ videos: [], total: 0, page: 1, limit: 30, totalPages: 0 });
    }

    const files = await readVideoFiles();
    const metadata = await loadMetadata();
    const bookmarks = await loadBookmarks();
    const userBookmarks = bookmarks[req.session.userId] || [];

    const results = [];
    for (const file of files) {
        const meta = metadata[file];
        if (!meta) continue;
        const qLower = q.toLowerCase();
        if (!(meta.title && meta.title.toLowerCase().includes(qLower)) &&
            !(meta.description && meta.description.toLowerCase().includes(qLower)) &&
            !(meta.tags && meta.tags.some(tag => tag.toLowerCase().includes(qLower)))) continue;
        results.push({
            name: file,
            url: getVideoUrl(file, meta),
            title: meta.title || file,
            description: meta.description || "",
            tags: meta.tags || [],
            license: meta.license || "all_rights_reserved",
            uploadedBy: meta.uploadedBy || null,
            likes: meta.likes?.length || 0,
            likedByUser: req.session.userId && meta.likes?.includes(req.session.userId) || false,
            bookmarkedByUser: req.session.userId && userBookmarks.includes(file) || false,
            views: meta.views || 0,
            thumbnailUrl: await getVideoThumbnailUrl(file),
            duration: meta.duration || 0
        });
    }

    results.reverse();

    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 30, 100);
    const start = (page - 1) * limit;
    const total = results.length;
    const totalPages = Math.ceil(total / limit);
    const paged = results.slice(start, start + limit);

    res.json({ videos: paged, total, page, limit, totalPages });
});

app.get("/api/ranking", async (req, res) => {
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

        const files = await readVideoFiles();
        const metadata = await loadMetadata();
        const views = await loadViews();
        const bookmarks = await loadBookmarks();
        const userBookmarks = bookmarks[req.session.userId] || [];

        const videos = [];
        for (const file of files) {
            const meta = metadata[file];
            let periodViews = 0;

            if (Array.isArray(views[file])) {
                if (period === "all") {
                    periodViews = views[file].length;
                } else {
                    periodViews = views[file].filter(ts => ts >= cutoff).length;
                }
            }

            videos.push({
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
                thumbnailUrl: await getVideoThumbnailUrl(file),
                duration: meta?.duration || 0
            });
        }

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
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.get("/admin", async (req, res) => {
    res.sendFile(path.join(__dirname, "public", "admin.html"));
});

const adminRateLimit = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    keyFn: req => "admin:" + req.session.userId,
    message: "リクエストが多すぎます"
});

app.get("/api/admin/users", requireAuth, requireAdmin, adminRateLimit, async (req, res) => {
    try {
        const users = await loadUsers();
        const metadata = await loadMetadata();
        const comments = await loadComments();

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
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.get("/api/admin/videos", requireAuth, requireAdmin, adminRateLimit, async (req, res) => {
    try {
        const metadata = await loadMetadata();
        const files = await readVideoFiles();
        const comments = await loadComments();

        const videoList = [];
        for (const file of files) {
            videoList.push({
                name: file,
                title: metadata[file]?.title || file,
                description: metadata[file]?.description || "",
                tags: metadata[file]?.tags || [],
                uploadedBy: metadata[file]?.uploadedBy || null,
                likes: metadata[file]?.likes?.length || 0,
                views: metadata[file]?.views || 0,
                hls: metadata[file]?.hls || false,
                commentCount: (comments[file] || []).length,
                thumbnailUrl: await getVideoThumbnailUrl(file)
            });
        }

        videoList.sort((a, b) => b.views - a.views);
        res.json({ success: true, videos: videoList, total: videoList.length });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.get("/api/admin/comments", requireAuth, requireAdmin, adminRateLimit, async (req, res) => {
    try {
        const comments = await loadComments();
        const metadata = await loadMetadata();
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
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.delete("/api/admin/user/:username", requireAuth, requireAdmin, adminRateLimit, csrfProtection, async (req, res) => {
    try {
        const targetUser = req.params.username;
        if (targetUser === req.session.userId) {
            return res.status(400).json({ success: false, error: "自分自身を削除することはできません" });
        }

        const users = await loadUsers();
        if (!users[targetUser]) {
            return res.status(404).json({ success: false, error: "ユーザーが見つかりません" });
        }

        if (users[targetUser].admin) {
            return res.status(403).json({ success: false, error: "他の管理者を削除することはできません" });
        }

        const metadata = await loadMetadata();
        const userVideos = Object.keys(metadata).filter(k => metadata[k].uploadedBy === targetUser);

        for (const filename of userVideos) {
            const filePath = path.join(uploadDir, filename);
            try { await fsp.unlink(filePath); } catch {}
            const videoHlsDir = path.join(hlsDir, filename);
            try { await fsp.rm(videoHlsDir, { recursive: true, force: true }); } catch {}
            delete metadata[filename];
        }
        await saveMetadata(metadata);

        const comments = await loadComments();
        for (const filename of Object.keys(comments)) {
            comments[filename] = comments[filename].filter(c => c.username !== targetUser);
            if (comments[filename].length === 0) delete comments[filename];
        }
        await saveComments(comments);

        const views = await loadViews();
        for (const filename of userVideos) {
            delete views[filename];
        }
        await saveViews(views);

        const bookmarks = await loadBookmarks();
        delete bookmarks[targetUser];
        for (const user of Object.keys(bookmarks)) {
            bookmarks[user] = bookmarks[user].filter(f => !userVideos.includes(f));
        }
        await saveBookmarks(bookmarks);

        const subscriptions = await loadSubscriptions();
        delete subscriptions[targetUser];
        for (const channel of Object.keys(subscriptions)) {
            subscriptions[channel] = subscriptions[channel].filter(s => s !== targetUser);
        }
        await saveSubscriptions(subscriptions);

        const profiles = await loadProfiles();
        if (profiles[targetUser]) {
            if (profiles[targetUser].avatar) {
                const avatarFile = path.join(avatarsDir, path.basename(profiles[targetUser].avatar));
                try { await fsp.unlink(avatarFile); } catch {}
            }
            delete profiles[targetUser];
            await saveProfiles(profiles);
        }

        const notifications = await loadNotifications();
        delete notifications[targetUser];
        await saveNotifications(notifications);

        const playlists = await loadPlaylists();
        for (const [pid, pl] of Object.entries(playlists)) {
            if (pl.username === targetUser) {
                delete playlists[pid];
            } else {
                pl.videoFilenames = pl.videoFilenames.filter(f => !userVideos.includes(f));
            }
        }
        await savePlaylists(playlists);

        const history = await loadHistory();
        delete history[targetUser];
        for (const user of Object.keys(history)) {
            history[user] = history[user].filter(h => !userVideos.includes(h.filename));
            if (history[user].length === 0) delete history[user];
        }
        await saveHistory(history);

        const reports = await loadReports();
        const filteredReports = reports.filter(r => r.reportedBy !== targetUser && !userVideos.includes(r.filename));
        if (filteredReports.length !== reports.length) {
            await saveReports(filteredReports);
        }

        delete users[targetUser];
        await saveUsers(users);

        console.log(`[ADMIN] ${req.session.userId} deleted user ${targetUser} with ${userVideos.length} videos`);
        res.json({ success: true, deletedVideos: userVideos.length });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.delete("/api/admin/video/:filename", requireAuth, requireAdmin, adminRateLimit, csrfProtection, async (req, res) => {
    try {
        if (!isValidFilename(req.params.filename)) {
            return res.status(400).json({ success: false, error: "無効なファイル名です" });
        }
        const metadata = await loadMetadata();
        const filename = req.params.filename;

        if (!metadata[filename]) {
            return res.status(404).json({ success: false, error: "動画が見つかりません" });
        }

        const filePath = path.join(uploadDir, filename);
        try { await fsp.unlink(filePath); } catch {}
        const videoHlsDir = path.join(hlsDir, filename);
        try { await fsp.rm(videoHlsDir, { recursive: true, force: true }); } catch {}

        delete metadata[filename];
        await saveMetadata(metadata);

        const comments = await loadComments();
        delete comments[filename];
        await saveComments(comments);

        const views = await loadViews();
        delete views[filename];
        await saveViews(views);

        const bookmarks = await loadBookmarks();
        for (const user of Object.keys(bookmarks)) {
            const idx = bookmarks[user].indexOf(filename);
            if (idx !== -1) bookmarks[user].splice(idx, 1);
        }
        await saveBookmarks(bookmarks);

        const history = await loadHistory();
        for (const user of Object.keys(history)) {
            history[user] = history[user].filter(h => h.filename !== filename);
            if (history[user].length === 0) delete history[user];
        }
        await saveHistory(history);

        const reports = await loadReports();
        const remainingReports = reports.filter(r => r.filename !== filename);
        if (remainingReports.length !== reports.length) {
            await saveReports(remainingReports);
        }

        console.log(`[ADMIN] ${req.session.userId} deleted video ${filename}`);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.delete("/api/admin/video/:filename/comment/:id", requireAuth, requireAdmin, adminRateLimit, csrfProtection, async (req, res) => {
    try {
        const comments = await loadComments();
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
        await saveComments(comments);

        console.log(`[ADMIN] ${req.session.userId} deleted comment ${req.params.id} by ${removed.username} on ${req.params.filename}`);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.get("/api/admin/reports", requireAuth, requireAdmin, adminRateLimit, async (req, res) => {
    try {
        const reports = await loadReports();
        const list = [...reports].reverse();
        res.json({ success: true, reports: list, total: list.length });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.delete("/api/admin/report/:id", requireAuth, requireAdmin, adminRateLimit, csrfProtection, async (req, res) => {
    try {
        const reports = await loadReports();
        const idx = reports.findIndex(r => r.id === req.params.id);
        if (idx === -1) {
            return res.status(404).json({ success: false, error: "通報が見つかりません" });
        }
        const removed = reports.splice(idx, 1)[0];
        await saveReports(reports);
        console.log(`[ADMIN] ${req.session.userId} dismissed report ${req.params.id} for ${removed.filename}`);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

// --- Playlist API ---

app.post("/api/playlists", requireAuth, csrfProtection, async (req, res) => {
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

        const playlists = await loadPlaylists();
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
        await savePlaylists(playlists);
        res.json({ success: true, playlist: playlists[id] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.get("/api/playlists", requireAuth, async (req, res) => {
    try {
        const playlists = await loadPlaylists();
        const userPlaylists = Object.values(playlists)
            .filter(p => p.username === req.session.userId)
            .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
        res.json({ success: true, playlists: userPlaylists });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.get("/api/playlists/:id", async (req, res) => {
    try {
        const playlists = await loadPlaylists();
        const playlist = playlists[req.params.id];
        if (!playlist) {
            return res.status(404).json({ success: false, error: "プレイリストが見つかりません" });
        }
        if (!playlist.isPublic && (!req.session.userId || req.session.userId !== playlist.username)) {
            return res.status(403).json({ success: false, error: "このプレイリストは非公開です" });
        }

        const metadata = await loadMetadata();
        const files = await readVideoFiles();
        const bookmarks = await loadBookmarks();
        const userBookmarks = bookmarks[req.session.userId] || [];

        const videos = [];
        for (const file of playlist.videoFilenames) {
            if (!files.includes(file) || !metadata[file]) continue;
            const meta = metadata[file] || {};
            videos.push({
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
                thumbnailUrl: await getVideoThumbnailUrl(file),
                duration: meta.duration || 0
            });
        }

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
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.patch("/api/playlists/:id", requireAuth, csrfProtection, async (req, res) => {
    try {
        const playlists = await loadPlaylists();
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
        await savePlaylists(playlists);
        res.json({ success: true, playlist });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.delete("/api/playlists/:id", requireAuth, csrfProtection, async (req, res) => {
    try {
        const playlists = await loadPlaylists();
        const playlist = playlists[req.params.id];
        if (!playlist) {
            return res.status(404).json({ success: false, error: "プレイリストが見つかりません" });
        }
        if (playlist.username !== req.session.userId) {
            return res.status(403).json({ success: false, error: "自分のプレイリストのみ削除できます" });
        }
        delete playlists[req.params.id];
        await savePlaylists(playlists);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.post("/api/playlists/:id/videos", requireAuth, csrfProtection, async (req, res) => {
    try {
        const { filename } = req.body;
        if (!filename) {
            return res.status(400).json({ success: false, error: "動画が指定されていません" });
        }

        const metadata = await loadMetadata();
        if (!metadata[filename]) {
            return res.status(404).json({ success: false, error: "動画が見つかりません" });
        }

        const playlists = await loadPlaylists();
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
            await savePlaylists(playlists);
        }

        res.json({ success: true, playlist });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.delete("/api/playlists/:id/videos/:filename", requireAuth, csrfProtection, async (req, res) => {
    try {
        const playlists = await loadPlaylists();
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
            await savePlaylists(playlists);
        }

        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.get("/api/playlists/public/:username", async (req, res) => {
    try {
        const playlists = await loadPlaylists();
        const userPlaylists = Object.values(playlists)
            .filter(p => p.username === req.params.username && p.isPublic)
            .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));

        const result = [];
        for (const p of userPlaylists) {
            const metadata = await loadMetadata();
            const files = await readVideoFiles();
            const validVideos = p.videoFilenames.filter(f => files.includes(f) && metadata[f]);
            const firstVideo = validVideos.length > 0 ? metadata[validVideos[0]] : null;
            result.push({
                id: p.id,
                title: p.title,
                description: p.description,
                username: p.username,
                videoCount: validVideos.length,
                firstVideoThumbnail: validVideos.length > 0 ? await getVideoThumbnailUrl(validVideos[0]) : null,
                createdAt: p.createdAt,
                updatedAt: p.updatedAt
            });
        }

        res.json({ success: true, playlists: result });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "サーバーエラーが発生しました" });
    }
});

app.get("/watch", async (req, res) => {
    res.redirect("/");
});

app.get("/watch/*", async (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
    console.log(`http://localhost:${PORT}`);
});