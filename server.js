require('dotenv').config();

const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const OpenAI = require('openai');

const app = express();

app.use(cors());
app.use(express.json());

function isLocalDatabaseUrl(databaseUrl) {
	if (!databaseUrl) return false;
	return databaseUrl.includes('localhost') || databaseUrl.includes('127.0.0.1');
}

function sanitizeDatabaseUrl(databaseUrl) {
	if (!databaseUrl) return databaseUrl;

	try {
		const parsedUrl = new URL(databaseUrl);
		parsedUrl.searchParams.delete('sslmode');
		parsedUrl.searchParams.delete('sslcert');
		parsedUrl.searchParams.delete('sslkey');
		parsedUrl.searchParams.delete('sslrootcert');
		parsedUrl.searchParams.delete('uselibpqcompat');
		return parsedUrl.toString();
	} catch (error) {
		return databaseUrl;
	}
}

const rawDatabaseUrl = process.env.DATABASE_URL;
const databaseUrl = sanitizeDatabaseUrl(rawDatabaseUrl);
const dbSslEnabled = (process.env.DB_SSL ?? 'true').toLowerCase() !== 'false';
const dbRejectUnauthorized = (process.env.DB_SSL_REJECT_UNAUTHORIZED ?? 'false').toLowerCase() === 'true';

const poolConfig = {
	connectionString: databaseUrl,
};

if (databaseUrl && dbSslEnabled && !isLocalDatabaseUrl(databaseUrl)) {
	poolConfig.ssl = {
		rejectUnauthorized: dbRejectUnauthorized,
	};
}

const pool = new Pool(poolConfig);

function sleep(ms) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

function isTransientDbError(error) {
	if (!error) return false;
	const message = String(error.message || '').toLowerCase();
	const code = String(error.code || '').toUpperCase();

	return (
		message.includes('connection terminated unexpectedly') ||
		message.includes('connection reset') ||
		message.includes('timeout') ||
		code === 'ECONNRESET' ||
		code === 'ETIMEDOUT' ||
		code === 'EPIPE'
	);
}

async function queryWithRetry(sql, params = [], options = {}) {
	const maxRetries = options.maxRetries ?? 4;
	const initialDelayMs = options.initialDelayMs ?? 600;

	for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
		try {
			return await pool.query(sql, params);
		} catch (error) {
			const isLastAttempt = attempt === maxRetries;
			if (!isTransientDbError(error) || isLastAttempt) {
				throw error;
			}

			const delay = initialDelayMs * (attempt + 1);
			console.warn(`Transient DB error on attempt ${attempt + 1}/${maxRetries + 1}, retrying in ${delay}ms...`);
			await sleep(delay);
		}
	}
}

async function initializeDatabase() {
	const createUsersTableSQL = `
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username VARCHAR UNIQUE NOT NULL,
			password_hash VARCHAR NOT NULL
		);
	`;

	const createVocabularyTableSQL = `
		CREATE TABLE IF NOT EXISTS vocabulary (
			id SERIAL PRIMARY KEY,
			user_id INTEGER REFERENCES users(id),
			word VARCHAR,
			phonetics TEXT,
			translation TEXT,
			example_sentence TEXT,
			paraphrase TEXT
		);
	`;

	await queryWithRetry('SELECT 1');
	await queryWithRetry(createUsersTableSQL);
	await queryWithRetry(createVocabularyTableSQL);
}

function authenticateToken(req, res, next) {
	const authHeader = req.headers.authorization;

	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		return res.status(401).json({ message: 'Missing or invalid authorization header' });
	}

	const token = authHeader.split(' ')[1];

	jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
		if (err) {
			return res.status(403).json({ message: 'Invalid or expired token' });
		}

		req.user = decoded;
		next();
	});
}

app.post('/api/register', async (req, res) => {
	try {
		const { username, password } = req.body;

		if (!username || !password) {
			return res.status(400).json({ message: 'username and password are required' });
		}

		const passwordHash = await bcrypt.hash(password, 10);

		const result = await pool.query(
			'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
			[username, passwordHash]
		);

		return res.status(201).json({
			message: 'User registered successfully',
			user: result.rows[0],
		});
	} catch (error) {
		if (error.code === '23505') {
			return res.status(409).json({ message: 'Username already exists' });
		}

		return res.status(500).json({ message: 'Internal server error' });
	}
});

app.post('/api/login', async (req, res) => {
	try {
		const { username, password } = req.body;

		if (!username || !password) {
			return res.status(400).json({ message: 'username and password are required' });
		}

		const result = await pool.query('SELECT id, username, password_hash FROM users WHERE username = $1', [username]);

		if (result.rows.length === 0) {
			return res.status(401).json({ message: 'Invalid username or password' });
		}

		const user = result.rows[0];
		const isPasswordValid = await bcrypt.compare(password, user.password_hash);

		if (!isPasswordValid) {
			return res.status(401).json({ message: 'Invalid username or password' });
		}

		const token = jwt.sign(
			{ id: user.id, username: user.username },
			process.env.JWT_SECRET,
			{ expiresIn: '7d' }
		);

		return res.json({ token });
	} catch (error) {
		return res.status(500).json({ message: 'Internal server error' });
	}
});

app.get('/api/me', authenticateToken, (req, res) => {
	res.json({ user: req.user });
});

function extractStatusCode(error) {
	if (!error) return undefined;
	return error.status || error.statusCode || error.code || error?.response?.status;
}

function extractJsonFromText(rawText) {
	if (!rawText || typeof rawText !== 'string') {
		throw new Error('Model response is empty');
	}

	try {
		return JSON.parse(rawText);
	} catch (parseError) {
		const firstBrace = rawText.indexOf('{');
		const lastBrace = rawText.lastIndexOf('}');

		if (firstBrace === -1 || lastBrace === -1 || firstBrace >= lastBrace) {
			throw parseError;
		}

		const jsonSlice = rawText.slice(firstBrace, lastBrace + 1);
		return JSON.parse(jsonSlice);
	}
}

function getModelText(response) {
	if (!response) return '';
	if (typeof response.output_text === 'string') return response.output_text;

	const candidateText = response?.output
		?.flatMap((item) => item?.content || [])
		.map((part) => part?.text || '')
		.join('');

	return candidateText || '';
}

app.post('/api/words', authenticateToken, async (req, res) => {
	try {
		const { word, user_api_key: userApiKey } = req.body;
		const apiKey = userApiKey || process.env.ARK_API_KEY;

		if (!word) {
			return res.status(400).json({ message: 'word is required' });
		}

		if (!apiKey) {
			return res.status(400).json({ message: 'user_api_key is required (or set ARK_API_KEY in .env)' });
		}

		const models = ['doubao-seed-2-0-pro-260215'];
		let parsedData = null;

		for (const model of models) {
			try {
				const client = new OpenAI({
					baseURL: 'https://ark.cn-beijing.volces.com/api/v3',
					apiKey,
				});
				const prompt = `分析单词 "${word}"。必须返回纯JSON格式，禁止Markdown格式，包含键：phonetics, translation, example_sentence, paraphrase。`;

				const response = await client.responses.create({
					model,
					input: [
						{
							role: 'user',
							content: [
								{
									type: 'input_text',
									text: prompt,
								},
							],
						},
					],
				});

				const text = getModelText(response);
				parsedData = extractJsonFromText(text);

				if (
					parsedData.phonetics === undefined ||
					parsedData.translation === undefined ||
					parsedData.example_sentence === undefined ||
					parsedData.paraphrase === undefined
				) {
					throw new Error('Invalid JSON structure from model');
				}

				break;
			} catch (error) {
				const statusCode = extractStatusCode(error);

				if (Number(statusCode) === 429) {
					console.log(`Model ${model} hit quota/token limit (429), trying next model...`);
					continue;
				}

				throw error;
			}
		}

		if (!parsedData) {
			return res.status(500).json({ message: 'All models failed to generate result' });
		}

		const insertResult = await pool.query(
			`INSERT INTO vocabulary (user_id, word, phonetics, translation, example_sentence, paraphrase)
			 VALUES ($1, $2, $3, $4, $5, $6)
			 RETURNING id, user_id, word, phonetics, translation, example_sentence, paraphrase`,
			[
				req.user.id,
				word,
				String(parsedData.phonetics ?? ''),
				String(parsedData.translation ?? ''),
				String(parsedData.example_sentence ?? ''),
				String(parsedData.paraphrase ?? ''),
			]
		);

		return res.status(201).json(insertResult.rows[0]);
	} catch (error) {
		console.error('Failed to create word record:', error);
		return res.status(500).json({ message: 'Failed to process word' });
	}
});

app.get('/api/words', authenticateToken, async (req, res) => {
	try {
		const result = await pool.query(
			`SELECT id, user_id, word, phonetics, translation, example_sentence, paraphrase
			 FROM vocabulary
			 WHERE user_id = $1
			 ORDER BY id DESC`,
			[req.user.id]
		);

		return res.json(result.rows);
	} catch (error) {
		console.error('Failed to fetch words:', error);
		return res.status(500).json({ message: 'Failed to fetch words' });
	}
});

app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
	res.sendFile(path.join(__dirname, 'index.html'));
});

async function startServer() {
	try {
		await initializeDatabase();
		app.listen(3000, () => {
			console.log('Server running on port 3000');
		});
	} catch (error) {
		console.error('Failed to initialize database or start server:', error);
		process.exit(1);
	}
}

startServer();

module.exports = {
	app,
	pool,
	authenticateToken,
};
