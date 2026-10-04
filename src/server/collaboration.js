import { randomUUID } from "node:crypto";
import jwt from "jsonwebtoken";
import fs from "node:fs/promises";
import path from "node:path";
import { WebSocket, WebSocketServer } from "ws";
import * as Y from "yjs";

import app from "../app.js";
import * as vars from "./vars.js";
import {
	validateId,
	securityCheck,
	verifyAuth
} from "./helpers.js";
import * as storage from "./storage.js";

const collaborationRooms = new Map();

class CollaborationError extends Error {
	constructor(status, message) {
		super(message);
		this.status = status;
	}
}

export const resolveProjectAccess = (index, projectId, userId) => {
	const user = Object.values(index.users).find((entry) => String(entry.id) === String(userId));
	if (!user) throw new CollaborationError(401, "Account not found");
	if (user.banned) throw new CollaborationError(403, "Account banned");

	const owner = Object.values(index.users).find((entry) =>
		(entry.projects || []).some((project) => String(project.id) === String(projectId))
	);
	if (!owner) throw new CollaborationError(404, "Project not found");

	const project = (owner.projects || []).find((entry) => String(entry.id) === String(projectId));
	if (!project) throw new CollaborationError(404, "Project not found");
	if (owner.banned) throw new CollaborationError(403, "Project owner is banned");

	const collaborators = project.collaborators || [];

	const seen = new Set();
	for (const member of collaborators) {
		if (!member || typeof member.userId !== "string" || !/^[1-9]\d{0,19}$/.test(member.userId) ||
			seen.has(member.userId) || !["editor", "viewer"].includes(member.role) ||
			typeof member.grantId !== "string" || !member.grantId ||
			typeof member.addedAt !== "string" || !Number.isFinite(Date.parse(member.addedAt))) {
			throw new Error("Invalid collaborator record");
		}
		seen.add(member.userId);
	}

	if (String(owner.id) === String(user.id)) {
		return {
			user,
			owner,
			project,
			collaborators,
			role: "owner",
			grantId: "owner"
		};
	}

	const position = collaborators.findIndex((member) => member.userId === String(user.id));
	if (position === -1) throw new CollaborationError(403, "Collaboration access denied");
	if (position >= ((owner.role === "dash-supporter" || owner.role === "dashteam") ? 5 : 2)) {
		throw new CollaborationError(
			403,
			"Project collaborators limit reached" +
			(
				owner.role !== "dash-supporter" && owner.role !== "dashteam"
					? " - donate Dash to add more collaborators: https://dashblocks.org/donate"
					: ""
			)
		);
	}

	const member = collaborators[position];
	return {
		user,
		owner,
		project,
		collaborators,
		role: member.role,
		grantId: member.grantId
	};
};

export const verifyCollaborationToken = async (token, projectId) => {
	let claims;
	try {
		claims = jwt.verify(token, vars.JWT_SECRET, {
			algorithms: ["HS256"],
			audience: "dash-collaboration",
			issuer: "dash-api"
		});
	} catch (_) {
		throw new CollaborationError(401, "Invalid collaboration token");
	}

	if (claims.tokenType !== "collaboration" || claims.projectId !== String(projectId) ||
		claims.sub !== String(claims.userId)) {
		throw new CollaborationError(403, "Token does not match this project");
	}

	const access = resolveProjectAccess(await storage.getIndex(), projectId, claims.userId);
	if (access.role !== claims.role || access.grantId !== claims.grantId) {
		throw new CollaborationError(403, "Collaboration permission changed");
	}
	return access;
};

const checkOrigin = (req, res, next) => {
	if (!["https://dashblocks.org", "https://www.dashblocks.org", "http://localhost:3000"].includes(req.get("Origin"))) {
		return res.status(403).json({ ok: false, error: "who are you" });
	}
	next();
};

const formatCollaboration = (index, access) => {
	const limit = (access.owner.role === "dash-supporter" || access.owner.role === "dashteam") ? 5 : 2;
	return {
		ok: true,
		projectId: String(access.project.id),
		revision: access.project.collaborationRevision || 0,
		role: access.role,
		collaboratorLimit: limit,
		owner: { userId: String(access.owner.id), username: access.owner.username },
		collaborators: access.collaborators.map((member, position) => ({
			userId: member.userId,
			username: Object.values(index.users).find((user) => String(user.id) === member.userId)?.username || "User",
			role: member.role,
			addedAt: member.addedAt,
			active: position < limit
		}))
	};
};

app.get("/projects/:id/collaborators", verifyAuth, securityCheck, validateId, async (req, res) => {
	try {
		res.set("Cache-Control", "no-store");
		const index = await storage.getIndex();
		res.json(formatCollaboration(index, resolveProjectAccess(index, req.params.id, req.user.userId)));
	} catch (error) {
		res.status(error instanceof CollaborationError ? error.status : 500).json({
			ok: false,
			error: error instanceof CollaborationError ? error.message : "Collaboration unavailable"
		});
	}
});

app.post("/projects/:id/collaborators", verifyAuth, securityCheck, validateId, checkOrigin, async (req, res) => {
	try {
		res.set("Cache-Control", "no-store");
		const username = typeof req.body?.username === "string" ? req.body.username.trim() : "";
		const role = req.body?.role ?? "editor";
		if (!/^(?!\d+$)[a-zA-Z0-9_-]{3,20}$/.test(username) || !["editor", "viewer"].includes(role)) {
			throw new CollaborationError(400, "Invalid username and/or editor or viewer role");
		}

		const result = await storage.mutateIndex((index) => {
			const access = resolveProjectAccess(index, req.params.id, req.user.userId);
			if (access.role !== "owner") throw new CollaborationError(403, "Only the project owner can manage collaborators");

			const user = Object.values(index.users).find((entry) =>
				entry.username.toLowerCase() === username.toLowerCase()
			);
			if (!user || user.banned) throw new CollaborationError(404, "Active account not found");
			if (String(user.id) === String(access.owner.id)) {
				throw new CollaborationError(400, "Project owner already has access");
			}

			const existing = access.collaborators.find((member) => member.userId === String(user.id));
			if (!existing) {
				if (access.collaborators.length >= ((access.owner.role === "dash-supporter" || access.owner.role === "dashteam") ? 5 : 2)) {
					throw new CollaborationError(
						403,
						`This project allows up to ${(access.owner.role === "dash-supporter" || access.owner.role === "dashteam") ? 5 : 2} collaborators`
					);
				}
				access.collaborators.push({
					userId: String(user.id),
					role,
					grantId: randomUUID(),
					addedAt: new Date().toISOString()
				});
				access.project.collaborators = access.collaborators;
				access.project.collaborationRevision = (access.project.collaborationRevision || 0) + 1;
			} else if (existing.role !== role) {
				existing.role = role;
				existing.grantId = randomUUID();
				access.project.collaborationRevision = (access.project.collaborationRevision || 0) + 1;
			}
			return formatCollaboration(index, access);
		});
		res.json(result);
	} catch (error) {
		res.status(error instanceof CollaborationError ? error.status : 500).json({
			ok: false,
			error: error instanceof CollaborationError ? error.message : "Collaboration unavailable"
		});
	}
});

app.delete("/projects/:id/collaborators/:userId", verifyAuth, securityCheck, validateId, checkOrigin, async (req, res) => {
	try {
		res.set("Cache-Control", "no-store");
		if (!/^[1-9]\d{0,19}$/.test(req.params.userId)) throw new CollaborationError(400, "Invalid user ID");

		const result = await storage.mutateIndex((index) => {
			const access = resolveProjectAccess(index, req.params.id, req.user.userId);
			if (access.role !== "owner") throw new CollaborationError(403, "Only the project owner can manage collaborators");
			if (String(access.owner.id) === req.params.userId) {
				throw new CollaborationError(400, "Cannot remove the project owner");
			}

			const remaining = access.collaborators.filter((member) => member.userId !== req.params.userId);
			if (remaining.length !== access.collaborators.length) {
				access.project.collaborators = remaining;
				access.collaborators = remaining;
				access.project.collaborationRevision = (access.project.collaborationRevision || 0) + 1;
			}
			return formatCollaboration(index, access);
		});
		res.json(result);
	} catch (error) {
		res.status(error instanceof CollaborationError ? error.status : 500).json({
			ok: false,
			error: error instanceof CollaborationError ? error.message : "Collaboration unavailable"
		});
	}
});

app.post("/projects/:id/collaboration-token", verifyAuth, securityCheck, validateId, checkOrigin, async (req, res) => {
	try {
		res.set("Cache-Control", "no-store");
		const access = resolveProjectAccess(await storage.getIndex(), req.params.id, req.user.userId);
		const token = jwt.sign({
			tokenType: "collaboration",
			projectId: String(access.project.id),
			userId: String(access.user.id),
			role: access.role,
			grantId: access.grantId
		}, vars.JWT_SECRET, {
			algorithm: "HS256",
			expiresIn: "2m",
			audience: "dash-collaboration",
			issuer: "dash-api",
			subject: String(access.user.id),
			jwtid: randomUUID()
		});
		res.json({ ok: true, projectId: String(access.project.id), role: access.role, token, expiresIn: 120 });
	} catch (error) {
		res.status(error instanceof CollaborationError ? error.status : 500).json({
			ok: false,
			error: error instanceof CollaborationError ? error.message : "Collaboration unavailable"
		});
	}
});

export const attachCollaborationWebSocket = (server) => {
	const wss = new WebSocketServer({ noServer: true, maxPayload: 384 * 1024, perMessageDeflate: false });
	const directory = path.join(vars.DATA_PATH, "collaboration");
	let closing = false;
	let checking = false;
	let checkedAt = 0;
	let upgradeWindow = Date.now();
	let upgrades = 0;

	const send = (ws, message) => {
		if (ws.readyState !== WebSocket.OPEN) return;
		if (ws.bufferedAmount > 8 * 1024 * 1024) return ws.close(1013, "Slow connection");
		ws.send(JSON.stringify(message), (error) => {
			if (error) ws.terminate();
		});
	};

	const presence = (room) => {
		const members = [...room.clients].filter((ws) => ws.readyState === WebSocket.OPEN).map((ws) => ({
			connectionId: ws.connectionId,
			userId: ws.userId,
			username: ws.username,
			role: ws.role
		}));
		for (const ws of room.clients) send(ws, { type: "members", members });
	};

	const save = async (room, update) => {
		await fs.mkdir(directory, { recursive: true });
		const file = path.join(directory, `${room.id}.json`);
		const temporary = `${file}.${randomUUID()}.tmp`;
		let handle;
		try {
			handle = await fs.open(temporary, "wx", 0o600);
			await handle.writeFile(JSON.stringify({ version: 1, epoch: room.epoch, data: Buffer.from(update).toString("base64") }));
			await handle.sync();
			await handle.close();
			handle = null;
			await fs.rename(temporary, file);
			const folder = await fs.open(directory, "r");
			try {
				await folder.sync();
			} finally {
				await folder.close();
			}
		} finally {
			if (handle) await handle.close();
			await fs.rm(temporary, { force: true });
		}
	};

	const load = (id) => {
		let room = collaborationRooms.get(id);
		if (room) return room;
		if (collaborationRooms.size >= 25) throw new CollaborationError(429, "Too many active rooms");
		room = { id, epoch: randomUUID(), doc: new Y.Doc(), clients: new Set(), pending: [], busy: false, loading: true, failed: false, touched: Date.now() };
		collaborationRooms.set(id, room);
		room.queue = (async () => {
			const file = path.join(directory, `${id}.json`);
			let data;
			try {
				const stat = await fs.stat(file);
				if (stat.size > 3 * 1024 * 1024) throw new Error("Collaboration file too large");
				data = JSON.parse(await fs.readFile(file, "utf8"));
			} catch (error) {
				if (error.code !== "ENOENT") throw error;
			}
			if (data) {
				if (data.version !== 1 || typeof data.epoch !== "string" || typeof data.data !== "string") {
					throw new Error("Invalid collaboration file");
				}
				room.epoch = data.epoch;
				const update = Buffer.from(data.data, "base64");
				if (update.length > 2 * 1024 * 1024) throw new Error("Collaboration document too large");
				Y.applyUpdate(room.doc, update);
			} else {
				await save(room, Y.encodeStateAsUpdate(room.doc));
			}
		})().catch((error) => {
			room.failed = true;
			collaborationRooms.delete(id);
			room.doc.destroy();
			throw error;
		}).finally(() => { room.loading = false; });
		return room;
	};

	const upgrade = (req, socket, head) => {
		socket.on("error", () => socket.destroy());
		if (Date.now() - upgradeWindow >= 1000) {
			upgradeWindow = Date.now();
			upgrades = 0;
		}
		const match = /^\/collaboration\/([1-9]\d{0,19})$/.exec(req.url);
		if (closing || !match || !["https://dashblocks.org", "https://www.dashblocks.org", "http://localhost:3000"].includes(req.headers.origin) ||
			++upgrades > 50 || wss.clients.size >= 100 || [...wss.clients].filter((ws) => !ws.userId).length >= 20) {
			socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
			return;
		}
		wss.handleUpgrade(req, socket, head, (ws) => {
			ws.projectId = match[1];
			ws.connectionId = randomUUID();
			ws.alive = true;
			ws.windowStart = Date.now();
			ws.messages = 0;
			ws.bytes = 0;
			ws.on("error", () => ws.terminate());
			ws.on("pong", () => { ws.alive = true; });
			const timeout = setTimeout(() => ws.close(4401, "Authentication timeout"), 5000);
			ws.on("close", () => {
				clearTimeout(timeout);
				if (ws.room) {
					ws.room.clients.delete(ws);
					ws.room.pending = ws.room.pending.filter((item) => item.ws !== ws);
					ws.room.touched = Date.now();
					presence(ws.room);
				}
			});
			ws.on("message", async (raw, binary) => {
				try {
					if (Date.now() - ws.windowStart >= 1000) {
						ws.windowStart = Date.now();
						ws.messages = 0;
						ws.bytes = 0;
					}
					ws.bytes += raw.length;
					if (binary || ++ws.messages > 30 || ws.bytes > 512 * 1024) return ws.close(4429, "Message limit");
					const message = JSON.parse(raw.toString());
					if (!message || typeof message !== "object") return ws.close(4400, "Invalid message");
					if (!ws.userId) {
						if (ws.authenticating || message.type !== "auth" || typeof message.token !== "string" || message.token.length > 4096) {
							return ws.close(4400, "Authentication required");
						}
						ws.authenticating = true;
						const access = await verifyCollaborationToken(message.token, ws.projectId);
						if (ws.readyState !== WebSocket.OPEN || closing) return;
						const room = load(ws.projectId);
						const join = room.queue.then(async () => {
							if (ws.readyState !== WebSocket.OPEN || closing) return;
							if (room.failed) throw new Error("Room unavailable");
							const current = resolveProjectAccess(await storage.getIndex(), ws.projectId, access.user.id);
							if (ws.readyState !== WebSocket.OPEN || closing) return;
							if (current.role !== access.role || current.grantId !== access.grantId) throw new CollaborationError(403, "Permission changed");
							const userId = String(current.user.id);
							if ([...room.clients].filter((peer) => peer.userId === userId).length >= 2 ||
								[...wss.clients].filter((peer) => peer.userId === userId).length >= 6) {
								throw new CollaborationError(429, "Too many connections for this account");
							}
							ws.userId = userId;
							ws.username = current.user.username;
							ws.role = current.role;
							ws.grantId = current.grantId;
							ws.room = room;
							room.clients.add(ws);
							room.touched = Date.now();
							clearTimeout(timeout);
							send(ws, {
								type: "ready", epoch: room.epoch, userId, role: ws.role, grantId: ws.grantId,
								data: Buffer.from(Y.encodeStateAsUpdate(room.doc)).toString("base64")
							});
							presence(room);
						});
						room.queue = join.catch(() => {});
						await join;
						return;
					}
					if (message.type !== "update" || typeof message.id !== "string" || !/^[a-zA-Z0-9-]{1,64}$/.test(message.id) ||
						typeof message.data !== "string" || message.data.length > 350000 ||
						!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(message.data)) {
						return ws.close(4400, "Invalid update");
					}
					if (ws.role === "viewer") return ws.close(4403, "Read-only access");
					if (message.epoch !== ws.room.epoch) return ws.close(4409, "Room changed");
					if (ws.pending) return ws.close(4429, "Wait for acknowledgement");
					const update = Buffer.from(message.data, "base64");
					if (!update.length || update.length > 256 * 1024) return ws.close(4400, "Update too large");
					ws.pending = true;
					ws.room.pending.push({ ws, id: message.id, update });
				} catch (error) {
					if (error instanceof CollaborationError) ws.close(error.status === 429 ? 4429 : 4403, error.message.slice(0,100));
					else if (error instanceof SyntaxError) ws.close(4400, "Invalid JSON");
					else ws.close(1011, "Collaboration unavailable");
				}
			});
		});
	};
	server.on("upgrade", upgrade);

	const tick = setInterval(async () => {
		if (checking || closing || !wss.clients.size) return;
		if (Date.now() - checkedAt < 1000 && ![...collaborationRooms.values()].some((room) => room.pending.length)) return;
		checking = true;
		try {
			const index = await storage.getIndex();
			if (closing) return;
			checkedAt = Date.now();
			for (const ws of wss.clients) {
				if (!ws.userId || ws.readyState !== WebSocket.OPEN) continue;
				try {
					const access = resolveProjectAccess(index, ws.projectId, ws.userId);
					if (access.role !== ws.role || access.grantId !== ws.grantId) throw new Error("Permission changed");
				} catch (_) {
					ws.close(4403, "Collaboration access changed");
				}
			}
			for (const room of collaborationRooms.values()) {
				if (room.busy || !room.pending.length) continue;
				room.busy = true;
				const batch = room.pending.splice(0);
				room.queue = room.queue.then(async () => {
					let next = new Y.Doc();
					const accepted = [];
					try {
						Y.applyUpdate(next, Y.encodeStateAsUpdate(room.doc));
						for (const item of batch) {
							if (item.ws.readyState !== WebSocket.OPEN) continue;
							const candidate = new Y.Doc();
							try {
								Y.applyUpdate(candidate, Y.encodeStateAsUpdate(next));
								Y.applyUpdate(candidate, item.update);
								if (candidate.store.pendingStructs || candidate.store.pendingDs || Y.encodeStateAsUpdate(candidate).length > 2 * 1024 * 1024) {
									throw new Error("Invalid document");
								}
								next.destroy();
								next = candidate;
								accepted.push(item);
							} catch (_) {
								candidate.destroy();
								item.ws.close(4400, "Invalid or oversized document");
							}
						}
						if (!accepted.length) return;
						await save(room, Y.encodeStateAsUpdate(next));
						room.doc.destroy();
						room.doc = next;
						next = null;
						const data = Buffer.from(Y.mergeUpdates(accepted.map((item) => item.update))).toString("base64");
						for (const ws of room.clients) send(ws, { type: "update", data });
						for (const item of accepted) send(item.ws, { type: "ack", id: item.id });
						room.touched = Date.now();
					} catch (_) {
						room.failed = true;
						collaborationRooms.delete(room.id);
						room.doc.destroy();
						for (const ws of room.clients) ws.close(1011, "Could not save collaboration");
					} finally {
						if (next) next.destroy();
						for (const item of batch) item.ws.pending = false;
					}
				}).finally(() => { room.busy = false; });
				await room.queue;
			}
		} catch (_) {
			for (const ws of wss.clients) ws.close(1011, "Could not check collaboration access");
		} finally {
			checking = false;
		}
	}, 100);

	const heartbeat = setInterval(() => {
		for (const ws of wss.clients) {
			if (!ws.alive || ws.readyState !== WebSocket.OPEN) {
				ws.terminate();
				continue;
			}
			ws.alive = false;
			ws.ping();
		}
		for (const [id, room] of collaborationRooms) {
			if (!room.clients.size && !room.loading && !room.busy && !room.pending.length && Date.now() - room.touched > 60000) {
				collaborationRooms.delete(id);
				room.doc.destroy();
			}
		}
	}, 15000);

	return async () => {
		closing = true;
		clearInterval(tick);
		clearInterval(heartbeat);
		server.off("upgrade", upgrade);
		for (const ws of wss.clients) ws.terminate();
		await Promise.allSettled([...collaborationRooms.values()].map((room) => room.queue));
		await new Promise((resolve) => wss.close(resolve));
		for (const room of collaborationRooms.values()) room.doc.destroy();
		collaborationRooms.clear();
	};
};
