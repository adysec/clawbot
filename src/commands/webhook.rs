use std::net::SocketAddr;
use std::sync::Mutex;

use anyhow::Result;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::{
    commands::send::{SendContent, SendTarget, resolve_send_content, resolve_send_target},
    db,
    wechat::{
        api::{WeixinApiClient, is_invalid_context_token, is_session_expired},
        media::{OutboundMediaKind, build_media_item, upload_media},
        models::InboundMessage,
    },
};

#[derive(Debug, Clone)]
struct AppState {
    user_id: String,
    client: WeixinApiClient,
    buf: std::sync::Arc<Mutex<String>>,
}

#[derive(Debug, Deserialize)]
struct SendRequest {
    text: Option<String>,
    file: Option<String>,
    caption: Option<String>,
}

#[derive(Debug, Serialize)]
struct ApiResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    messages: Option<Vec<MessageResponse>>,
}

#[derive(Debug, Serialize)]
struct MessageResponse {
    from_user_id: String,
    text: Option<String>,
    image: bool,
    file: bool,
    context_token: String,
}

pub async fn run(
    account: Option<usize>,
    user_id: Option<&str>,
    bot_token: Option<&str>,
    route_tag: Option<&str>,
    bind: SocketAddr,
) -> Result<()> {
    let target = resolve_send_target(account, user_id, bot_token, route_tag)?;

    let (user_id, client) = match &target {
        SendTarget::Saved { user_id, client } => (user_id.clone(), client.clone()),
        SendTarget::Explicit { user_id, client } => (user_id.clone(), client.clone()),
    };

    let saved = db::load_session(&user_id).ok().flatten();
    let updates_buf = saved.as_ref().map(|s| s.updates_buf.clone()).unwrap_or_default();

    if saved.is_some() {
        eprintln!("restored session from database for `{user_id}`");
    } else {
        eprintln!("no saved session for `{user_id}`; the user must send a message first to activate");
        eprintln!("use `GET /webhook/messages` to poll; the first poll will activate the session");
    }

    let state = AppState {
        user_id,
        client,
        buf: std::sync::Arc::new(Mutex::new(updates_buf)),
    };

    let app = Router::new()
        .route("/webhook/send", post(handle_send))
        .route("/webhook/messages", get(handle_messages))
        .route("/health", post(handle_health).get(handle_health))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!("webhook server listening on http://{bind}");
    eprintln!("endpoints:");
    eprintln!("  POST /webhook/send         - send a message");
    eprintln!("  GET  /webhook/messages      - poll new messages");
    eprintln!("  GET|POST /health            - health check");

    axum::serve(listener, app).await?;

    Ok(())
}

async fn handle_health() -> Json<ApiResponse> {
    Json(ApiResponse {
        success: true,
        message: "ok".to_string(),
        messages: None,
    })
}

async fn handle_messages(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    let current_buf = {
        let b = state.buf.lock().unwrap();
        if b.is_empty() { None } else { Some(b.clone()) }
    };

    match state.client.get_updates(current_buf.as_deref()).await {
        Ok(resp) => {
            if let Some(ref new_buf) = resp.get_updates_buf {
                let mut b = state.buf.lock().unwrap();
                *b = new_buf.clone();
                let _ = db::save_updates_buf(&state.user_id, new_buf);
            }

            let mut messages = Vec::new();
            for msg in resp.messages() {
                if !msg.context_token.is_empty() {
                    let _ = db::save_context_token(
                        &state.user_id,
                        state.client.bot_token(),
                        state.client.route_tag(),
                        &msg.context_token,
                    );
                }
                messages.push(message_to_response(msg));
            }

            Ok(Json(ApiResponse {
                success: true,
                message: format!("{} messages", messages.len()),
                messages: Some(messages),
            }))
        }
        Err(err) if is_session_expired(&err) => {
            Err((
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    message: format!("session expired: {err:#}"),
                    messages: None,
                }),
            ))
        }
        Err(err) => {
            Err((
                StatusCode::BAD_GATEWAY,
                Json(ApiResponse {
                    success: false,
                    message: format!("{err:#}"),
                    messages: None,
                }),
            ))
        }
    }
}

fn message_to_response(msg: &InboundMessage) -> MessageResponse {
    let mut text = None;
    let mut image = false;
    let mut file = false;

    for item in &msg.item_list {
        match item.item_type {
            1 => {
                text = Some(
                    item.text_item
                        .as_ref()
                        .map(|t| t.text.clone())
                        .or(item.body.clone())
                        .unwrap_or_default(),
                );
            }
            2 => image = true,
            4 => file = true,
            _ => {}
        }
    }

    MessageResponse {
        from_user_id: msg.from_user_id.clone(),
        text,
        image,
        file,
        context_token: msg.context_token.clone(),
    }
}

async fn handle_send(
    State(state): State<AppState>,
    Json(req): Json<SendRequest>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<ApiResponse>)> {
    let result = send_via_target(&state.user_id, &state.client, &req).await;

    match result {
        Ok(msg) => Ok(Json(ApiResponse {
            success: true,
            message: msg,
            messages: None,
        })),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: format!("{e:#}"),
                messages: None,
            }),
        )),
    }
}

async fn send_via_target(user_id: &str, client: &WeixinApiClient, req: &SendRequest) -> Result<String> {
    let content = resolve_send_content(
        req.text.as_deref(),
        req.file.as_deref().map(std::path::Path::new),
        &mut std::io::empty(),
        false,
    )?;

    match content {
        SendContent::Text(text) => send_text(user_id, client, &text).await,
        SendContent::File(file_path) => send_media(user_id, client, &file_path, req.caption.as_deref()).await,
    }
}

async fn get_context_token_from_db_or_poll(user_id: &str, client: &WeixinApiClient) -> Option<String> {
    // Poll first to get a fresh token
    if let Ok(resp) = client.get_updates(None).await {
        for msg in resp.messages() {
            if msg.from_user_id == user_id
                && !msg.context_token.is_empty()
                && !msg.to_user_id.is_empty()
            {
                let token = msg.context_token.clone();
                if let Some(ref b) = resp.get_updates_buf {
                    let _ = db::save_updates_buf(user_id, b);
                }
                let _ = db::save_context_token(user_id, client.bot_token(), client.route_tag(), &token);
                return Some(token);
            }
        }
    }
    // Fall back to DB cache
    if let Ok(Some(session)) = db::load_session(user_id) {
        if !session.context_token.is_empty() {
            return Some(session.context_token);
        }
    }
    None
}

async fn send_with_token(user_id: &str, client: &WeixinApiClient, text: &str) -> Result<String> {
    // Fast path: use cached token
    let cached = db::load_session(user_id).ok().flatten()
        .and_then(|s| if s.context_token.is_empty() { None } else { Some(s.context_token) });

    if let Some(ref token) = cached {
        match client.send_text_message(user_id, token, text).await {
            Ok(_) => return Ok(format!("sent text message to `{user_id}`")),
            Err(e) if is_invalid_context_token(&e) => { /* stale, retry */ }
            Err(e) => return Err(e.into()),
        }
    }

    // Slow path: poll for fresh token
    let fresh = get_context_token_from_db_or_poll(user_id, client).await;
    let token = fresh.ok_or_else(|| anyhow::anyhow!(
        "no context token for `{user_id}`; the user must send a message first"
    ))?;

    client.send_text_message(user_id, &token, text).await?;
    Ok(format!("sent text message to `{user_id}`"))
}

async fn send_text(user_id: &str, client: &WeixinApiClient, text: &str) -> Result<String> {
    send_with_token(user_id, client, text).await
}

async fn send_media(user_id: &str, client: &WeixinApiClient, file_path: &std::path::Path, caption: Option<&str>) -> Result<String> {
    let file_path = file_path.to_path_buf();

    // Check file existence on blocking thread pool
    let exists = tokio::task::spawn_blocking({
        let fp = file_path.clone();
        move || fp.is_file()
    }).await.unwrap_or(false);
    if !exists {
        anyhow::bail!("file `{}` does not exist", file_path.display());
    }

    let media_kind = tokio::task::spawn_blocking({
        let fp = file_path.clone();
        move || match mime_guess::from_path(&fp).first() {
            Some(mime_type) if mime_type.type_() == mime_guess::mime::IMAGE => OutboundMediaKind::Image,
            _ => OutboundMediaKind::File,
        }
    }).await.unwrap_or(OutboundMediaKind::File);

    // Fast path: try cached token first
    let cached = db::load_session(user_id).ok().flatten()
        .and_then(|s| if s.context_token.is_empty() { None } else { Some(s.context_token) });

    if let Some(ref token) = cached {
        let uploaded = upload_media(client, user_id, &file_path, media_kind).await?;
        let media_item = build_media_item(media_kind, &uploaded);
            match client.send_media_message(user_id, token, caption, media_item).await {
            Ok(_) => {
                let kind_label = match media_kind { OutboundMediaKind::Image => "image", OutboundMediaKind::File => "file" };
                return Ok(format!("sent {kind_label} `{}` to `{user_id}`", file_path.display()));
            }
            Err(e) if is_invalid_context_token(&e) => { /* stale, fall through */ }
            Err(e) => return Err(e.into()),
        }
    }

    // Slow path: poll for fresh token
    let fresh = get_context_token_from_db_or_poll(user_id, client).await
        .ok_or_else(|| anyhow::anyhow!(
            "no context token for `{user_id}`; the user must send a message first"
        ))?;

    let uploaded = upload_media(client, user_id, &file_path, media_kind).await?;
    let media_item = build_media_item(media_kind, &uploaded);
    client.send_media_message(user_id, &fresh, caption, media_item).await?;

    let kind_label = match media_kind {
        OutboundMediaKind::Image => "image",
        OutboundMediaKind::File => "file",
    };
    Ok(format!("sent {kind_label} `{}` to `{user_id}`", file_path.display()))
}
