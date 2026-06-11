use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use anyhow::Result;
use rusqlite::Connection;

fn db_path() -> PathBuf {
    PathBuf::from("session.db")
}

fn get_db() -> &'static Mutex<Connection> {
    static DB: OnceLock<Mutex<Connection>> = OnceLock::new();
    DB.get_or_init(|| {
        let conn = Connection::open(db_path())
            .expect("failed to open database `session.db`");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS wechat_sessions (
                user_id     TEXT PRIMARY KEY,
                bot_token   TEXT NOT NULL,
                route_tag   TEXT,
                context_token TEXT NOT NULL DEFAULT '',
                updates_buf  TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auth_tokens (
                token    TEXT PRIMARY KEY,
                user_id  INTEGER NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL
            );",
        )
        .expect("failed to initialize wechat_sessions / users / auth_tokens");
        let _ = conn.execute_batch("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'");
        let admin_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM users WHERE role = 'admin'", [], |r| {
                r.get(0)
            })
            .unwrap_or(0);
        if admin_count == 0 {
            let _ = conn.execute(
                "UPDATE users SET role = 'admin' WHERE id = (SELECT id FROM users ORDER BY id LIMIT 1)",
                [],
            );
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS messages (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                wechat_user_id TEXT NOT NULL,
                direction  TEXT NOT NULL,
                content    TEXT NOT NULL DEFAULT '',
                msg_type   TEXT NOT NULL DEFAULT 'text',
                raw_json   TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )",
        )
        .expect("failed to initialize messages table");
        Mutex::new(conn)
    })
}

// ── WeChat sessions ──────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: String,
    pub bot_token: String,
    pub route_tag: Option<String>,
    pub context_token: String,
    pub updates_buf: String,
}

pub fn load_session(user_id: &str) -> Result<Option<Session>> {
    let conn = get_db().lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT user_id, bot_token, route_tag, context_token, updates_buf FROM wechat_sessions WHERE user_id = ?1",
    )?;
    let mut rows = stmt.query_map([user_id], |row| {
        Ok(Session {
            user_id: row.get(0)?,
            bot_token: row.get(1)?,
            route_tag: row.get(2)?,
            context_token: row.get(3)?,
            updates_buf: row.get(4)?,
        })
    })?;
    match rows.next() {
        Some(Ok(session)) => Ok(Some(session)),
        Some(Err(e)) => Err(e.into()),
        None => Ok(None),
    }
}

pub fn save_context_token(
    user_id: &str,
    bot_token: &str,
    route_tag: Option<&str>,
    context_token: &str,
) -> Result<()> {
    let conn = get_db().lock().unwrap();
    conn.execute(
        "INSERT INTO wechat_sessions (user_id, bot_token, route_tag, context_token, updates_buf)
         VALUES (?1, ?2, ?3, ?4, '')
         ON CONFLICT(user_id) DO UPDATE SET
            bot_token = excluded.bot_token,
            route_tag = excluded.route_tag,
            context_token = excluded.context_token",
        rusqlite::params![user_id, bot_token, route_tag, context_token],
    )?;
    Ok(())
}

pub fn save_updates_buf(user_id: &str, updates_buf: &str) -> Result<()> {
    let conn = get_db().lock().unwrap();
    conn.execute(
        "UPDATE wechat_sessions SET updates_buf = ?1 WHERE user_id = ?2",
        rusqlite::params![updates_buf, user_id],
    )?;
    Ok(())
}

pub fn list_wechat_sessions() -> Result<Vec<Session>> {
    let conn = get_db().lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT user_id, bot_token, route_tag, context_token, updates_buf FROM wechat_sessions",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(Session {
            user_id: row.get(0)?,
            bot_token: row.get(1)?,
            route_tag: row.get(2)?,
            context_token: row.get(3)?,
            updates_buf: row.get(4)?,
        })
    })?;
    let mut sessions = Vec::new();
    for row in rows {
        sessions.push(row?);
    }
    Ok(sessions)
}

// ── Users ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub role: String,
    #[allow(dead_code)]
    pub created_at: String,
}

pub fn create_user(username: &str, password: &str) -> Result<User> {
    let hash = tokio::task::block_in_place(|| bcrypt::hash(password, bcrypt::DEFAULT_COST))?;
    let conn = get_db().lock().unwrap();
    let now = chrono::Utc::now().to_rfc3339();
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
    let role = if count == 0 { "admin" } else { "user" };
    conn.execute(
        "INSERT INTO users (username, password, created_at, role) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![username, hash, now, role],
    )?;
    let id = conn.last_insert_rowid();
    Ok(User {
        id,
        username: username.to_string(),
        role: role.to_string(),
        created_at: now,
    })
}

pub fn verify_user(username: &str, password: &str) -> Result<Option<User>> {
    let conn = get_db().lock().unwrap();
    let mut stmt =
        conn.prepare("SELECT id, username, role, password, created_at FROM users WHERE username = ?1")?;
    let mut rows = stmt.query_map([username], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;
    match rows.next() {
        Some(Ok((id, uname, role, hash, created_at))) => {
            let valid = tokio::task::block_in_place(|| bcrypt::verify(password, &hash))?;
            if valid {
                Ok(Some(User { id, username: uname, role, created_at }))
            } else {
                Ok(None)
            }
        }
        Some(Err(e)) => Err(e.into()),
        None => Ok(None),
    }
}

#[allow(dead_code)]
pub fn get_user_by_id(user_id: i64) -> Result<Option<User>> {
    let conn = get_db().lock().unwrap();
    let mut stmt = conn.prepare("SELECT id, username, role, created_at FROM users WHERE id = ?1")?;
    let mut rows = stmt.query_map([user_id], |row| {
        Ok(User {
            id: row.get(0)?,
            username: row.get(1)?,
            role: row.get::<_, String>(2).unwrap_or_default(),
            created_at: row.get(3)?,
        })
    })?;
    match rows.next() {
        Some(Ok(user)) => Ok(Some(user)),
        Some(Err(e)) => Err(e.into()),
        None => Ok(None),
    }
}

pub fn list_users() -> Result<Vec<User>> {
    let conn = get_db().lock().unwrap();
    let mut stmt = conn.prepare("SELECT id, username, role, created_at FROM users ORDER BY id")?;
    let rows = stmt.query_map([], |row| {
        Ok(User {
            id: row.get(0)?,
            username: row.get(1)?,
            role: row.get::<_, String>(2).unwrap_or_default(),
            created_at: row.get(3)?,
        })
    })?;
    let mut users = Vec::new();
    for row in rows {
        users.push(row?);
    }
    Ok(users)
}

// ── Auth tokens ──────────────────────────────────────────────

pub fn create_auth_token(user_id: i64) -> Result<String> {
    let token = uuid::Uuid::new_v4().simple().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let conn = get_db().lock().unwrap();
    conn.execute(
        "INSERT INTO auth_tokens (token, user_id, created_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![token, user_id, now],
    )?;
    Ok(token)
}

pub fn validate_auth_token(token: &str) -> Result<Option<User>> {
    let conn = get_db().lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT u.id, u.username, u.role, u.created_at FROM auth_tokens t JOIN users u ON t.user_id = u.id WHERE t.token = ?1",
    )?;
    let mut rows = stmt.query_map([token], |row| {
        Ok(User {
            id: row.get(0)?,
            username: row.get(1)?,
            role: row.get::<_, String>(2).unwrap_or_default(),
            created_at: row.get(3)?,
        })
    })?;
    match rows.next() {
        Some(Ok(user)) => Ok(Some(user)),
        Some(Err(e)) => Err(e.into()),
        None => Ok(None),
    }
}

pub fn get_user_by_username(username: &str) -> Result<Option<User>> {
    let conn = get_db().lock().unwrap();
    let mut stmt = conn.prepare("SELECT id, username, role, created_at FROM users WHERE username = ?1")?;
    let mut rows = stmt.query_map([username], |row| {
        Ok(User {
            id: row.get(0)?,
            username: row.get(1)?,
            role: row.get::<_, String>(2).unwrap_or_default(),
            created_at: row.get(3)?,
        })
    })?;
    match rows.next() {
        Some(Ok(user)) => Ok(Some(user)),
        Some(Err(e)) => Err(e.into()),
        None => Ok(None),
    }
}

pub fn update_password(username: &str, new_password: &str) -> Result<()> {
    let hash = tokio::task::block_in_place(|| bcrypt::hash(new_password, bcrypt::DEFAULT_COST))?;
    let conn = get_db().lock().unwrap();
    conn.execute("UPDATE users SET password = ?1 WHERE username = ?2", rusqlite::params![hash, username])?;
    Ok(())
}

// ── Messages ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Message {
    pub id: i64,
    pub wechat_user_id: String,
    pub direction: String,
    pub content: String,
    pub msg_type: String,
    pub raw_json: String,
    pub created_at: String,
}

pub fn save_message(
    wechat_user_id: &str,
    direction: &str,
    content: &str,
    msg_type: &str,
    raw_json: &str,
) -> Result<()> {
    let conn = get_db().lock().unwrap();
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO messages (wechat_user_id, direction, content, msg_type, raw_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![wechat_user_id, direction, content, msg_type, raw_json, now],
    )?;
    Ok(())
}

pub fn list_messages(wechat_user_id: Option<&str>) -> Result<Vec<Message>> {
    list_messages_paginated(wechat_user_id, 1, 200).map(|r| r.0)
}

pub fn list_messages_paginated(wechat_user_id: Option<&str>, page: i64, page_size: i64) -> Result<(Vec<Message>, i64)> {
    let conn = get_db().lock().unwrap();
    let offset = (page - 1) * page_size;

    let total: i64 = if let Some(uid) = wechat_user_id {
        conn.query_row("SELECT COUNT(*) FROM messages WHERE wechat_user_id = ?1", [uid], |row| row.get(0))?
    } else {
        conn.query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))?
    };

    let rows: Vec<Message> = if let Some(uid) = wechat_user_id {
        let mut stmt = conn.prepare(
            "SELECT id, wechat_user_id, direction, content, msg_type, raw_json, created_at \
             FROM messages WHERE wechat_user_id = ?1 ORDER BY id DESC LIMIT ?2 OFFSET ?3"
        )?;
        stmt.query_map(rusqlite::params![uid, page_size, offset], |row| {
            Ok(Message {
                id: row.get(0)?,
                wechat_user_id: row.get(1)?,
                direction: row.get(2)?,
                content: row.get(3)?,
                msg_type: row.get(4)?,
                raw_json: row.get(5)?,
                created_at: row.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?
    } else {
        let mut stmt = conn.prepare(
            "SELECT id, wechat_user_id, direction, content, msg_type, raw_json, created_at \
             FROM messages ORDER BY id DESC LIMIT ?1 OFFSET ?2"
        )?;
        stmt.query_map(rusqlite::params![page_size, offset], |row| {
            Ok(Message {
                id: row.get(0)?,
                wechat_user_id: row.get(1)?,
                direction: row.get(2)?,
                content: row.get(3)?,
                msg_type: row.get(4)?,
                raw_json: row.get(5)?,
                created_at: row.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?
    };
    Ok((rows, total))
}
