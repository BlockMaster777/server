import { randomUUID } from "node:crypto";
import jwt from "jsonwebtoken";

import app from "../app.js";
import * as vars from "./vars.js";
import {
	validateId,
	securityCheck,
	verifyAuth
} from "./helpers.js";
import * as storage from "./storage.js";

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
