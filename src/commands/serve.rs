use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Html,
    routing::{get, post},
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use rand::RngExt;
use tokio::sync::Semaphore;

use crate::{
    db,
    wechat::{
        api::{WeixinApiClient, is_invalid_context_token},
        models::InboundMessage,
    },
};

const CAPTCHA_EXPIRY_SECS: u64 = 300;
const MAX_CONCURRENT_POLLS: usize = 20;

struct CaptchaSession {
    code: String,
    created_at: Instant,
    used: bool,
}

// ── App state ────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    buf: std::sync::Arc<Mutex<HashMap<String, String>>>,
    session_poll_locks: std::sync::Arc<Mutex<HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>>,
    captcha_store: std::sync::Arc<Mutex<HashMap<String, CaptchaSession>>>,
    poll_semaphore: std::sync::Arc<Semaphore>,
}

impl AppState {
    fn new() -> Self {
        Self {
            buf: std::sync::Arc::new(Mutex::new(HashMap::new())),
            session_poll_locks: std::sync::Arc::new(Mutex::new(HashMap::new())),
            captcha_store: std::sync::Arc::new(Mutex::new(HashMap::new())),
            poll_semaphore: std::sync::Arc::new(Semaphore::new(MAX_CONCURRENT_POLLS)),
        }
    }

    fn get_poll_lock(&self, user_id: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.session_poll_locks.lock().unwrap();
        locks
            .entry(user_id.to_string())
            .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }
}

// ── Captcha ──────────────────────────────────────────────────

/// 5×7 bitmap characters 0-9 + A-Z (each row is a 5-bit pattern, msb = left)
const CHAR_BITMAPS: [[u8; 7]; 36] = [
    // 0-9 (indices 0-9)
    [0b01110, 0b10001, 0b10011, 0b10101, 0b11001, 0b10001, 0b01110],
    [0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110],
    [0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111],
    [0b11111, 0b00010, 0b00100, 0b00010, 0b00001, 0b10001, 0b01110],
    [0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010],
    [0b11111, 0b10000, 0b11110, 0b00001, 0b00001, 0b10001, 0b01110],
    [0b00110, 0b01000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110],
    [0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000],
    [0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110],
    [0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00010, 0b01100],
    // A-Z (indices 10-35)
    [0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001],
    [0b11110, 0b10001, 0b10001, 0b11110, 0b10001, 0b10001, 0b11110],
    [0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110],
    [0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110],
    [0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111],
    [0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000],
    [0b01110, 0b10001, 0b10000, 0b10111, 0b10001, 0b10001, 0b01110],
    [0b10001, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001],
    [0b01110, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110],
    [0b00111, 0b00010, 0b00010, 0b00010, 0b00010, 0b10010, 0b01100],
    [0b10001, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010, 0b10001],
    [0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111],
    [0b10001, 0b11011, 0b10101, 0b10101, 0b10001, 0b10001, 0b10001],
    [0b10001, 0b11001, 0b10101, 0b10011, 0b10001, 0b10001, 0b10001],
    [0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110],
    [0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000],
    [0b01110, 0b10001, 0b10001, 0b10001, 0b10101, 0b10010, 0b01101],
    [0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001],
    [0b01110, 0b10001, 0b10000, 0b01110, 0b00001, 0b10001, 0b01110],
    [0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100],
    [0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110],
    [0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01010, 0b00100],
    [0b10001, 0b10001, 0b10001, 0b10101, 0b10101, 0b11011, 0b10001],
    [0b10001, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001, 0b10001],
    [0b10001, 0b10001, 0b01010, 0b00100, 0b00100, 0b00100, 0b00100],
    [0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b10000, 0b11111],
];

fn char_to_index(c: char) -> usize {
    match c {
        '0'..='9' => c as usize - '0' as usize,
        'A'..='Z' => 10 + (c as usize - 'A' as usize),
        _ => 0,
    }
}

fn generate_captcha_code() -> String {
    let mut rng = rand::rng();
    (0..6)
        .map(|_| {
            let idx = rng.random_range(0..36);
            if idx < 10 {
                (b'0' + idx as u8) as char
            } else {
                (b'A' + (idx - 10) as u8) as char
            }
        })
        .collect()
}

fn generate_captcha_image(code: &str) -> Vec<u8> {
    use image::RgbImage;

    let dot_space = 7.0f32;
    let dot_r = 3.5f32;
    let gap = 14.0f32;
    let pad = 21.0f32;
    let total_w = (pad * 2.0 + code.len() as f32 * (5.0 * dot_space) + (code.len() - 1) as f32 * gap) as u32;
    let total_h = (pad * 2.0 + 7.0 * dot_space) as u32;

    let mut rng = rand::rng();
    let mut img = RgbImage::new(total_w, total_h);

    let bg = image::Rgb([240, 240, 235]);
    for pixel in img.pixels_mut() {
        *pixel = bg;
    }

    for _ in 0..100 {
        let x = rng.random_range(0..total_w);
        let y = rng.random_range(0..total_h);
        let v = rng.random_range(40..120);
        img.put_pixel(x, y, image::Rgb([v, v, v]));
    }

    for (i, ch) in code.chars().enumerate() {
        let idx = char_to_index(ch);
        let base_color = image::Rgb([
            rng.random_range(30..200),
            rng.random_range(30..200),
            rng.random_range(30..200),
        ]);
        let ox = pad + i as f32 * (5.0 * dot_space + gap);

        for row in 0..7 {
            let bits = CHAR_BITMAPS[idx][row];
            for col in 0..5 {
                if (bits >> (4 - col)) & 1 == 1 {
                    let jx = rng.random_range(-0.6..0.6);
                    let jy = rng.random_range(-0.6..0.6);
                    let cx = ox + col as f32 * dot_space + jx;
                    let cy = pad + row as f32 * dot_space + jy;
                    let r = (base_color[0] as i32 + rng.random_range(-15..=15)).clamp(0, 255) as u8;
                    let g = (base_color[1] as i32 + rng.random_range(-15..=15)).clamp(0, 255) as u8;
                    let b = (base_color[2] as i32 + rng.random_range(-15..=15)).clamp(0, 255) as u8;
                    draw_dot(&mut img, cx, cy, dot_r, image::Rgb([r, g, b]));
                }
            }
        }
    }

    for _ in 0..3 {
        let color = image::Rgb([
            rng.random_range(80..180),
            rng.random_range(80..180),
            rng.random_range(80..180),
        ]);
        let x1 = rng.random_range(0..total_w) as usize;
        let y1 = rng.random_range(0..total_h) as usize;
        let x2 = rng.random_range(0..total_w) as usize;
        let y2 = rng.random_range(0..total_h) as usize;
        draw_line(&mut img, x1, y1, x2, y2, color);
    }

    let mut buf = Vec::new();
    use image::ImageEncoder;
    let encoder = image::codecs::png::PngEncoder::new(&mut buf);
    encoder
        .write_image(img.as_raw(), total_w, total_h, image::ColorType::Rgb8.into())
        .expect("PNG encoding failed");
    buf
}

fn draw_dot(img: &mut image::RgbImage, cx: f32, cy: f32, radius: f32, color: image::Rgb<u8>) {
    let min_x = (cx - radius - 1.0).max(0.0) as u32;
    let max_x = (cx + radius + 1.0).min((img.width() - 1) as f32) as u32;
    let min_y = (cy - radius - 1.0).max(0.0) as u32;
    let max_y = (cy + radius + 1.0).min((img.height() - 1) as f32) as u32;
    for py in min_y..=max_y {
        for px in min_x..=max_x {
            let dx = px as f32 - cx;
            let dy = py as f32 - cy;
            let dist = (dx * dx + dy * dy).sqrt();
            if dist < radius - 0.5 {
                img.put_pixel(px, py, color);
            } else if dist < radius + 0.5 {
                let alpha = 1.0 - (dist - (radius - 0.5));
                let pixel = img.get_pixel(px, py);
                img.put_pixel(px, py, image::Rgb([
                    (color[0] as f32 * alpha + pixel[0] as f32 * (1.0 - alpha)) as u8,
                    (color[1] as f32 * alpha + pixel[1] as f32 * (1.0 - alpha)) as u8,
                    (color[2] as f32 * alpha + pixel[2] as f32 * (1.0 - alpha)) as u8,
                ]));
            }
        }
    }
}

fn draw_line(img: &mut image::RgbImage, x1: usize, y1: usize, x2: usize, y2: usize, color: image::Rgb<u8>) {
    let dx = (x2 as i32 - x1 as i32).abs();
    let dy = -(y2 as i32 - y1 as i32).abs();
    let sx = if x1 < x2 { 1 } else { -1 };
    let sy = if y1 < y2 { 1 } else { -1 };
    let mut err = dx + dy;
    let mut x = x1 as i32;
    let mut y = y1 as i32;
    loop {
        if x >= 0 && (x as usize) < img.width() as usize && y >= 0 && (y as usize) < img.height() as usize {
            img.put_pixel(x as u32, y as u32, color);
        }
        if x == x2 as i32 && y == y2 as i32 { break; }
        let e2 = 2 * err;
        if e2 >= dy { err += dy; x += sx; }
        if e2 <= dx { err += dx; y += sy; }
    }
}

// ── Auth helper ──────────────────────────────────────────────

fn extract_user(headers: &HeaderMap) -> Result<db::User, (StatusCode, Json<ApiResponse>)> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::error("missing or invalid Authorization header")),
            )
        })?;
    db::validate_auth_token(token)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error(&e.to_string())),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::error("invalid or expired token")),
            )
        })
}

fn extract_admin(headers: &HeaderMap) -> Result<db::User, (StatusCode, Json<ApiResponse>)> {
    let user = extract_user(headers)?;
    if user.role != "admin" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiResponse::error("admin access required")),
        ));
    }
    Ok(user)
}

// ── Response types ───────────────────────────────────────────

#[derive(Debug, Serialize)]
struct ApiResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

impl ApiResponse {
    fn ok(msg: impl Into<String>) -> Self {
        Self {
            success: true,
            message: msg.into(),
            data: None,
        }
    }
    fn ok_with_data(msg: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            success: true,
            message: msg.into(),
            data: Some(data),
        }
    }
    fn error(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            message: msg.into(),
            data: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    captcha_id: Option<String>,
    captcha_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChangePasswordRequest {
    old_password: Option<String>,
    new_password: String,
    username: Option<String>,
}

// ── Captcha helpers ──────────────────────────────────────────

fn verify_captcha(state: &AppState, captcha_id: Option<&str>, captcha_code: Option<&str>) -> Result<(), (StatusCode, Json<ApiResponse>)> {
    let id = captcha_id.and_then(|s| if s.is_empty() { None } else { Some(s) });
    let code = captcha_code.and_then(|s| if s.is_empty() { None } else { Some(s) });
    let (id, code) = match (id, code) {
        (Some(id), Some(code)) => (id.to_string(), code.to_uppercase()),
        _ => return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("captcha_id and captcha_code are required")))),
    };
    let mut store = state.captcha_store.lock().unwrap();
    let session = store.get_mut(&id).ok_or_else(|| {
        (StatusCode::BAD_REQUEST, Json(ApiResponse::error("invalid or expired captcha")))
    })?;
    if session.used {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("captcha already used"))));
    }
    if session.created_at.elapsed() > Duration::from_secs(CAPTCHA_EXPIRY_SECS) {
        store.remove(&id);
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("captcha expired"))));
    }
    if session.code != code {
        session.used = true; // prevent brute force retry on same id
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("incorrect captcha"))));
    }
    session.used = true;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct SendMsgRequest {
    text: Option<String>,
}

#[derive(Debug, Serialize)]
struct MessageResponse {
    from_user_id: String,
    text: Option<String>,
    image: bool,
    file: bool,
}

// ── Frontend ─────────────────────────────────────────────────

const FRONTEND_HTML: &str = include_str!("../../webui/index.html");

// ─── Public routes ────────────────────────────────────────────

async fn handle_captcha(
    State(state): State<AppState>,
) -> Json<ApiResponse> {
    let code = generate_captcha_code();
    let id = uuid::Uuid::new_v4().simple().to_string();

    // Generate captcha image on blocking thread pool (CPU-bound)
    let code_clone = code.clone();
    let png = tokio::task::spawn_blocking(move || generate_captcha_image(&code_clone))
        .await
        .unwrap_or_default();

    let b64 = base64::engine::general_purpose::STANDARD.encode(&png);
    let data_url = format!("data:image/png;base64,{b64}");

    let mut store = state.captcha_store.lock().unwrap();
    store.retain(|_, s| s.created_at.elapsed() < Duration::from_secs(CAPTCHA_EXPIRY_SECS));
    store.insert(id.clone(), CaptchaSession {
        code,
        created_at: Instant::now(),
        used: false,
    });

    Json(ApiResponse::ok_with_data("ok", serde_json::json!({
        "captcha_id": id,
        "captcha_image": data_url,
    })))
}

async fn get_frontend() -> Html<&'static str> {
    Html(FRONTEND_HTML)
}

async fn handle_register(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    verify_captcha(&state, req.captcha_id.as_deref(), req.captcha_code.as_deref())?;
    if req.username.trim().is_empty() || req.password.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("username and password are required")),
        ));
    }
    match db::create_user(req.username.trim(), &req.password) {
        Ok(user) => {
            let token = db::create_auth_token(user.id).unwrap_or_default();
            Ok(Json(ApiResponse::ok_with_data(
                "registered successfully",
                serde_json::json!({ "token": token, "username": user.username, "role": user.role }),
            )))
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("UNIQUE") {
                Err((
                    StatusCode::CONFLICT,
                    Json(ApiResponse::error("username already exists")),
                ))
            } else {
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse::error(&msg)),
                ))
            }
        }
    }
}

async fn handle_login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    verify_captcha(&state, req.captcha_id.as_deref(), req.captcha_code.as_deref())?;
    let user = db::verify_user(req.username.trim(), &req.password).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error(&e.to_string())),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::error("invalid username or password")),
        )
    })?;
    let token = db::create_auth_token(user.id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error(&e.to_string())),
        )
    })?;
    Ok(Json(ApiResponse::ok_with_data(
        "login successful",
        serde_json::json!({ "token": token, "username": user.username, "role": user.role }),
    )))
}

async fn handle_change_password(
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    let user = extract_user(&headers)?;
    if req.new_password.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("new password is required"))));
    }
    let old = req.old_password.as_deref().unwrap_or("");
    if db::verify_user(&user.username, old).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(&e.to_string())))
    })?.is_none() {
        return Err((StatusCode::UNAUTHORIZED, Json(ApiResponse::error("old password is incorrect"))));
    }
    db::update_password(&user.username, req.new_password.trim()).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(&e.to_string())))
    })?;
    Ok(Json(ApiResponse::ok("password changed")))
}

async fn handle_admin_change_password(
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    let _admin = extract_admin(&headers)?;
    let target = req.username.as_deref().unwrap_or("");
    if target.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("target username is required"))));
    }
    if req.new_password.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("new password is required"))));
    }
    db::get_user_by_username(target).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(&e.to_string())))
    })?.ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(ApiResponse::error("user not found")))
    })?;
    db::update_password(target, req.new_password.trim()).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(&e.to_string())))
    })?;
    Ok(Json(ApiResponse::ok(format!("password changed for `{target}`"))))
}

// ─── Authenticated routes ─────────────────────────────────────

async fn handle_me(
    headers: HeaderMap,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    let user = extract_user(&headers)?;

    let sessions = db::list_wechat_sessions().ok().unwrap_or_default();
    let bound = sessions.iter().find(|s| {
        s.route_tag.as_deref() == Some(&user.username)
    });

    let data = serde_json::json!({
        "username": user.username,
        "role": user.role,
        "wechat_bound": bound.is_some(),
        "wechat_user_id": bound.as_ref().map(|s| s.user_id.as_str()),
        "webhook_url": bound.as_ref().map(|s| {
            format!("/webhook/{}/send", s.user_id)
        }),
        "webhook_usage": bound.as_ref().map(|s| {
            serde_json::json!({
                "curl": format!("curl -X POST http://<host>:<port>/webhook/{}/send -H 'Content-Type: application/json' -d '{{\"text\":\"hello\"}}'", s.user_id),
                "python": format!("import requests\nr = requests.post(\"http://<host>:<port>/webhook/{}/send\", json={{\"text\":\"hello\"}})\nprint(r.json())", s.user_id),
                "rust": format!("let resp = client.post(format!(\"http://<host>:<port>/webhook/{}/send\", user_id)).json(&serde_json::json!({{\"text\":\"hello\"}})).send().await?;", s.user_id),
            })
        }),
    });
    Ok(Json(ApiResponse::ok_with_data("ok", data)))
}

async fn handle_bind_qrcode(
    headers: HeaderMap,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    let _user = extract_user(&headers)?;

    let client = WeixinApiClient::new("", None);
    let resp = client.fetch_qr_code().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(ApiResponse::error(&e.to_string())),
        )
    })?;

    let qrcode_id = resp.qrcode_id().unwrap_or("").to_string();
    let qrcode_url = resp.qrcode_url().unwrap_or("").to_string();

    Ok(Json(ApiResponse::ok_with_data(
        "qr code fetched",
        serde_json::json!({ "qrcode_id": qrcode_id, "qrcode_url": qrcode_url }),
    )))
}

#[derive(Deserialize)]
struct BindStatusRequest {
    qrcode_id: String,
}

async fn handle_bind_status(
    headers: HeaderMap,
    Json(req): Json<BindStatusRequest>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    let user = extract_user(&headers)?;

    let client = WeixinApiClient::new("", None);
    let resp = client.get_qr_code_status(&req.qrcode_id).await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(ApiResponse::error(&e.to_string())),
        )
    })?;

    match resp.status() {
        "confirmed" => {
            let bot_token = resp.bot_token().unwrap_or("");
            let wechat_user_id = resp.ilink_user_id().unwrap_or("");
            if bot_token.is_empty() || wechat_user_id.is_empty() {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(ApiResponse::error("incomplete bind data from server")),
                ));
            }
            let _ = db::save_context_token(wechat_user_id, bot_token, Some(&user.username), "");
            let _ = db::save_updates_buf(wechat_user_id, "");

            Ok(Json(ApiResponse::ok_with_data(
                "WeChat account bound successfully",
                serde_json::json!({ "wechat_user_id": wechat_user_id }),
            )))
        }
        status => Ok(Json(ApiResponse::ok_with_data(
            "polling",
            serde_json::json!({ "status": status }),
        ))),
    }
}

async fn handle_send_msg(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SendMsgRequest>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    let user = extract_user(&headers)?;

    let sessions = db::list_wechat_sessions().ok().unwrap_or_default();
    let session = sessions.iter().find(|s| {
        s.route_tag.as_deref() == Some(&user.username)
    }).ok_or_else(|| {
        (StatusCode::BAD_REQUEST, Json(ApiResponse::error("no WeChat account bound; scan a QR code first")))
    })?;

    let client = WeixinApiClient::new(&session.bot_token, session.route_tag.clone());
    let uid = session.user_id.clone();
    let text = req.text.unwrap_or_default();

    // Fast path: use cached token directly
    let cached_token = db::load_session(&uid).ok().flatten()
        .and_then(|s| if s.context_token.is_empty() { None } else { Some(s.context_token) });

    if let Some(token) = cached_token {
        match client.send_text_message(&uid, &token, &text).await {
            Ok(_) => {
                let _ = db::save_message(&uid, "send", &text, "text", "");
                return Ok(Json(ApiResponse::ok("message sent")));
            }
            Err(e) if is_invalid_context_token(&e) => {
                // Token stale, fall through to slow path
                eprintln!("cached token invalid, refreshing...");
            }
            Err(e) => return Err((StatusCode::BAD_GATEWAY, Json(ApiResponse::error(&format!("{e:#}"))))),
        }
    }

    // Slow path: poll for fresh token and retry
    let current_buf = state.buf.lock().unwrap().get(&uid).cloned()
        .or_else(|| {
            db::load_session(&uid).ok().flatten().and_then(|s| {
                if s.updates_buf.is_empty() { None } else { Some(s.updates_buf) }
            })
        });

    let session_lock = state.get_poll_lock(&uid);
    let (context_token, new_buf) = poll_context_token(&client, &uid, current_buf.as_deref(), &session_lock).await;
    let token = context_token.unwrap_or_else(|| {
        db::load_session(&uid).ok().flatten()
            .and_then(|s| if s.context_token.is_empty() { None } else { Some(s.context_token) })
            .unwrap_or_default()
    });

    if token.is_empty() {
        return Err((StatusCode::BAD_GATEWAY, Json(ApiResponse::error(
            "no context token; the other user must send a message first"
        ))));
    }

    if let Some(ref b) = new_buf {
        state.buf.lock().unwrap().insert(uid.clone(), b.clone());
        let _ = db::save_updates_buf(&uid, b);
    }
    let _ = db::save_context_token(&uid, client.bot_token(), client.route_tag(), &token);

    client.send_text_message(&uid, &token, &text).await.map_err(|e| {
        (StatusCode::BAD_GATEWAY, Json(ApiResponse::error(&format!("{e:#}"))))
    })?;

    let _ = db::save_message(&uid, "send", &text, "text", "");
    Ok(Json(ApiResponse::ok("message sent")))
}

async fn handle_messages(
    _state: State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    let user = extract_user(&headers)?;

    let sessions = db::list_wechat_sessions().ok().unwrap_or_default();
    let session = sessions.iter().find(|s| {
        s.route_tag.as_deref() == Some(&user.username)
    }).ok_or_else(|| {
        (StatusCode::BAD_REQUEST, Json(ApiResponse::error("no WeChat account bound")))
    })?;

    let page = params.get("page").and_then(|s| s.parse::<i64>().ok()).unwrap_or(1);
    let page_size = params.get("page_size").and_then(|s| s.parse::<i64>().ok()).unwrap_or(15).min(100);

    let (db_messages, total) = db::list_messages_paginated(Some(&session.user_id), page, page_size)
        .unwrap_or_default();

    let messages: Vec<MessageResponse> = db_messages.into_iter()
        .map(|m| {
            let from_user_id = if m.direction == "send" {
                "我".to_string()
            } else {
                serde_json::from_str::<InboundMessage>(&m.raw_json)
                    .ok()
                    .map(|im| im.from_user_id)
                    .unwrap_or_else(|| m.wechat_user_id.clone())
            };

            MessageResponse {
                from_user_id,
                text: if m.msg_type == "text" && !m.content.is_empty() { Some(m.content) } else { None },
                image: m.msg_type == "image",
                file: m.msg_type == "file",
            }
        })
        .collect();

    let total_pages = (total as f64 / page_size as f64).ceil() as i64;
    Ok(Json(ApiResponse::ok_with_data(
        "ok",
        serde_json::json!({ "messages": messages, "page": page, "page_size": page_size, "total": total, "total_pages": total_pages }),
    )))
}

// ─── Webhook routes (no auth, identified by wechat_user_id) ───

/// Shared helper: send a text message to a single WeChat user.
/// Tries cached context token first, falls back to polling.
async fn send_wechat_message(
    state: &AppState,
    client: &WeixinApiClient,
    uid: &str,
    text: &str,
) -> Result<()> {
    // Fast path: use cached token directly
    let cached_token = db::load_session(uid).ok().flatten()
        .and_then(|s| if s.context_token.is_empty() { None } else { Some(s.context_token) });

    if let Some(ref token) = cached_token {
        match client.send_text_message(uid, token, text).await {
            Ok(_) => {
                let _ = db::save_message(uid, "send", text, "text", "");
                return Ok(());
            }
            Err(e) if is_invalid_context_token(&e) => { /* stale, fall through */ }
            Err(e) => return Err(e.into()),
        }
    }

    // Slow path: poll for fresh token
    let current_buf = state.buf.lock().unwrap().get(uid).cloned()
        .or_else(|| db::load_session(uid).ok().flatten().and_then(|s| if s.updates_buf.is_empty() { None } else { Some(s.updates_buf) }));

    let session_lock = state.get_poll_lock(uid);
    let (ctx_token, new_buf) = poll_context_token(client, uid, current_buf.as_deref(), &session_lock).await;
    let token = ctx_token.or_else(|| {
        db::load_session(uid).ok().flatten()
            .and_then(|s| if s.context_token.is_empty() { None } else { Some(s.context_token) })
    }).ok_or_else(|| anyhow::anyhow!("no context token for `{uid}`"))?;

    if let Some(ref b) = new_buf {
        state.buf.lock().unwrap().insert(uid.to_string(), b.clone());
        let _ = db::save_updates_buf(uid, b);
    }
    let _ = db::save_context_token(uid, client.bot_token(), client.route_tag(), &token);
    client.send_text_message(uid, &token, text).await?;
    let _ = db::save_message(uid, "send", text, "text", "");
    Ok(())
}

async fn handle_webhook_send(
    State(state): State<AppState>,
    Path(wechat_user_id): Path<String>,
    Json(req): Json<SendMsgRequest>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    let session = db::load_session(&wechat_user_id)
        .ok()
        .flatten()
        .ok_or_else(|| {
            (StatusCode::NOT_FOUND, Json(ApiResponse::error("unknown wechat user")))
        })?;

    let client = WeixinApiClient::new(&session.bot_token, session.route_tag.clone());
    let text = req.text.unwrap_or_default();
    send_wechat_message(&state, &client, &session.user_id, &text).await.map_err(|e| {
        (StatusCode::BAD_GATEWAY, Json(ApiResponse::error(&format!("{e:#}"))))
    })?;
    Ok(Json(ApiResponse::ok("message sent via webhook")))
}

async fn handle_webhook_messages(
    _state: State<AppState>,
    Path(wechat_user_id): Path<String>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    let session = db::load_session(&wechat_user_id)
        .ok()
        .flatten()
        .ok_or_else(|| {
            (StatusCode::NOT_FOUND, Json(ApiResponse::error("unknown wechat user")))
        })?;

    let db_messages = db::list_messages(Some(&session.user_id))
        .unwrap_or_default();

    let messages: Vec<MessageResponse> = db_messages.into_iter()
        .map(|m| {
            let from_user_id = if m.direction == "send" {
                "我".to_string()
            } else {
                serde_json::from_str::<InboundMessage>(&m.raw_json)
                    .ok()
                    .map(|im| im.from_user_id)
                    .unwrap_or_else(|| m.wechat_user_id.clone())
            };

            MessageResponse {
                from_user_id,
                text: if m.msg_type == "text" && !m.content.is_empty() { Some(m.content) } else { None },
                image: m.msg_type == "image",
                file: m.msg_type == "file",
            }
        })
        .collect();

    Ok(Json(ApiResponse::ok_with_data(
        "ok",
        serde_json::json!({ "messages": messages }),
    )))
}

/// Admin-only webhook to broadcast a message to all bound WeChat users.
async fn handle_webhook_broadcast_send(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SendMsgRequest>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    extract_admin(&headers)?;
    let text = req.text.unwrap_or_default();
    if text.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::error("text is required"))));
    }

    let sessions = db::list_wechat_sessions().map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(&e.to_string())))
    })?;

    // Broadcast concurrently using tokio::spawn
    let state = state.clone();
    let handles: Vec<_> = sessions.into_iter().map(|session| {
        let state = state.clone();
        let text = text.clone();
        tokio::spawn(async move {
            let client = WeixinApiClient::new(&session.bot_token, session.route_tag.clone());
            let uid = session.user_id.clone();
            let result = send_wechat_message(&state, &client, &uid, &text).await;
            serde_json::json!({
                "user_id": uid,
                "success": result.is_ok(),
                "error": result.err().map(|e| format!("{e:#}")),
            })
        })
    }).collect();

    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }

    let success_count = results.iter().filter(|r| r["success"].as_bool().unwrap_or(false)).count();
    Ok(Json(ApiResponse::ok_with_data(
        format!("broadcast sent to {success_count}/{} users", results.len()),
        serde_json::json!({ "results": results }),
    )))
}

// ─── Admin routes ─────────────────────────────────────────────

async fn handle_admin_users(
    headers: HeaderMap,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    let _admin = extract_admin(&headers)?;

    let users = db::list_users().map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(&e.to_string())))
    })?;
    let sessions = db::list_wechat_sessions().ok().unwrap_or_default();

    let users_data: Vec<serde_json::Value> = users.into_iter().map(|u| {
        let bound = sessions.iter().find(|s| s.route_tag.as_deref() == Some(&u.username));
        serde_json::json!({
            "id": u.id,
            "username": u.username,
            "role": u.role,
            "wechat_bound": bound.is_some(),
            "wechat_user_id": bound.as_ref().map(|s| s.user_id.as_str()),
        })
    }).collect();

    Ok(Json(ApiResponse::ok_with_data("ok", serde_json::json!({ "users": users_data }))))
}

async fn handle_admin_messages(
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    let _admin = extract_admin(&headers)?;

    let wechat_user_id = params.get("wechat_user_id").map(|s| s.as_str());
    let page = params.get("page").and_then(|s| s.parse::<i64>().ok()).unwrap_or(1);
    let page_size = params.get("page_size").and_then(|s| s.parse::<i64>().ok()).unwrap_or(15).min(100);

    let (messages, total) = db::list_messages_paginated(wechat_user_id, page, page_size).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(&e.to_string())))
    })?;

    let sessions = db::list_wechat_sessions().ok().unwrap_or_default();

    let msgs: Vec<serde_json::Value> = messages.into_iter().map(|m| {
        let username = sessions.iter()
            .find(|s| s.user_id == m.wechat_user_id)
            .and_then(|s| s.route_tag.as_deref())
            .unwrap_or("");
        serde_json::json!({
            "id": m.id,
            "wechat_user_id": m.wechat_user_id,
            "username": username,
            "direction": m.direction,
            "content": m.content,
            "msg_type": m.msg_type,
            "created_at": m.created_at,
        })
    }).collect();

    let total_pages = (total as f64 / page_size as f64).ceil() as i64;
    Ok(Json(ApiResponse::ok_with_data("ok", serde_json::json!({
        "messages": msgs,
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
    }))))
}

// ─── Shared helpers ───────────────────────────────────────────

/// Poll for updates and return the first valid context_token found,
/// along with the new updates_buf cursor.
async fn poll_context_token(
    client: &WeixinApiClient,
    user_id: &str,
    buf: Option<&str>,
    poll_lock: &tokio::sync::Mutex<()>,
) -> (Option<String>, Option<String>) {
    let _guard = poll_lock.lock().await;
    match client.get_updates(buf).await {
        Ok(resp) => {
            let new_buf = resp.get_updates_buf.clone();
            for msg in resp.messages() {
                if msg.from_user_id == user_id
                    && !msg.context_token.is_empty()
                    && !msg.to_user_id.is_empty()
                {
                    return (Some(msg.context_token.clone()), new_buf);
                }
            }
            (None, new_buf)
        }
        Err(_) => (None, None),
    }
}

fn extract_msg_content(msg: &InboundMessage) -> (String, String) {
    for item in &msg.item_list {
        match item.item_type {
            1 => {
                let text = item.text_item
                    .as_ref()
                    .map(|t| t.text.clone())
                    .or(item.body.clone())
                    .unwrap_or_default();
                return (text, "text".to_string());
            }
            2 => return (String::new(), "image".to_string()),
            4 => return (String::new(), "file".to_string()),
            _ => {}
        }
    }
    (String::new(), "text".to_string())
}

// ─── Server entry point ──────────────────────────────────────

pub async fn run(host: String, port: u16) -> Result<()> {
    let state = AppState::new();
    let bind: SocketAddr = format!("{host}:{port}").parse()?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let app = Router::new()
        .route("/", get(get_frontend))
        .route("/api/captcha", get(handle_captcha))
        .route("/api/register", post(handle_register))
        .route("/api/login", post(handle_login))
        .route("/api/me", get(handle_me))
        .route("/api/bind/qrcode", get(handle_bind_qrcode))
        .route("/api/bind/status", post(handle_bind_status))
        .route("/api/send", post(handle_send_msg))
        .route("/api/messages", get(handle_messages))
        .route("/api/change-password", post(handle_change_password))
        .route("/api/admin/change-password", post(handle_admin_change_password))
        .route(
            "/webhook/{wechat_user_id}/send",
            post(handle_webhook_send),
        )
        .route(
            "/webhook/{wechat_user_id}/messages",
            get(handle_webhook_messages),
        )
        .route(
            "/webhook/broadcast/send",
            post(handle_webhook_broadcast_send),
        )
        .route("/api/admin/users", get(handle_admin_users))
        .route("/api/admin/messages", get(handle_admin_messages))
        .with_state(state.clone());

    // Captcha cleanup task (stops on shutdown signal)
    let mut captcha_shutdown = shutdown_rx.clone();
    let captcha_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let mut store = captcha_state.captcha_store.lock().unwrap();
                    store.retain(|_, s| s.created_at.elapsed() < Duration::from_secs(CAPTCHA_EXPIRY_SECS));
                }
                _ = captcha_shutdown.changed() => break,
            }
        }
    });

    // Background poller: fetches new messages for all sessions concurrently every 3s
    let mut bg_shutdown = shutdown_rx.clone();
    let bg_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let sessions = match db::list_wechat_sessions() {
                        Ok(s) => s,
                        Err(_) => continue,
                    };

                    let handles: Vec<_> = sessions.into_iter().map(|session| {
                        let bg_state = bg_state.clone();
                        let semaphore = bg_state.poll_semaphore.clone();
                        tokio::spawn(async move {
                            let _permit = semaphore.acquire().await.expect("semaphore closed");
                            let uid = session.user_id.clone();
                            let client = WeixinApiClient::new(&session.bot_token, session.route_tag.clone());

                            let current_buf = {
                                let b = bg_state.buf.lock().unwrap();
                                b.get(&uid).cloned()
                            }.or_else(|| {
                                if session.updates_buf.is_empty() { None } else { Some(session.updates_buf.clone()) }
                            });

                            let poll_result = client.get_updates(current_buf.as_deref()).await;
                            if let Ok(resp) = poll_result {
                                if let Some(ref new_buf) = resp.get_updates_buf {
                                    let mut b = bg_state.buf.lock().unwrap();
                                    b.insert(uid.clone(), new_buf.clone());
                                    let _ = db::save_updates_buf(&uid, new_buf);
                                }

                                for msg in resp.messages() {
                                    if !msg.context_token.is_empty() {
                                        let _ = db::save_context_token(&uid, &session.bot_token, session.route_tag.as_deref(), &msg.context_token);
                                    }
                                    let (content, msg_type) = extract_msg_content(msg);
                                    let raw = serde_json::to_string(msg).unwrap_or_default();
                                    let _ = db::save_message(&uid, "receive", &content, &msg_type, &raw);
                                }
                            }
                        })
                    }).collect();

                    for handle in handles {
                        let _ = handle.await;
                    }
                }
                _ = bg_shutdown.changed() => break,
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!("WeChat management server listening on http://{bind}");
    eprintln!("Open http://{bind} in your browser");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::signal::ctrl_c().await.ok();
            eprintln!("\nshutting down gracefully...");
            let _ = shutdown_tx.send(true);
        })
        .await?;

    Ok(())
}
