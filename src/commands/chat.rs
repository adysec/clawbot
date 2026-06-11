use anyhow::{Result, bail};
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc;

use crate::{
    commands::send::{SendTarget, resolve_send_target},
    db,
    wechat::api::is_session_expired,
    wechat::models::InboundMessageItem,
};

pub async fn run(
    account: Option<usize>,
    user_id: Option<&str>,
    bot_token: Option<&str>,
    route_tag: Option<&str>,
) -> Result<()> {
    let target = resolve_send_target(account, user_id, bot_token, route_tag)?;

    let (user_id, client) = match &target {
        SendTarget::Saved { user_id, client } => (user_id.clone(), client.clone()),
        SendTarget::Explicit { user_id, client } => (user_id.clone(), client.clone()),
    };

    let saved = db::load_session(&user_id).ok().flatten();
    let mut context_token: Option<String> = saved
        .as_ref()
        .and_then(|s| if s.context_token.is_empty() { None } else { Some(s.context_token.clone()) });
    let updates_buf: Option<String> = saved
        .as_ref()
        .and_then(|s| if s.updates_buf.is_empty() { None } else { Some(s.updates_buf.clone()) });

    if context_token.is_some() {
        eprintln!("restored session from database");
    } else {
        eprintln!("no saved session found; waiting for {} to send a message to activate the bot...", user_id);
        eprintln!("after activation, the session will be saved and you can restart without re-activation");
    }

    let (stdin_tx, mut stdin_rx) = mpsc::unbounded_channel::<String>();

    tokio::spawn(async move {
        let reader = tokio::io::BufReader::new(tokio::io::stdin());
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if stdin_tx.send(line).is_err() {
                break;
            }
        }
    });

    eprintln!("chatting as `{user_id}`; type your messages and press Enter to send, Ctrl+C to quit");

    let mut consecutive_errors = 0u32;
    let mut buf = updates_buf;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nbye");
                return Ok(());
            }
            line = stdin_rx.recv() => {
                match line {
                    Some(text) => {
                        let text = text.trim().to_string();
                        if text.is_empty() {
                            continue;
                        }
                        match &context_token {
                            Some(token) => {
                                // Retry send with exponential backoff on transient errors
                                let mut send_err = None;
                                for attempt in 0..3 {
                                    if attempt > 0 {
                                        tokio::time::sleep(std::time::Duration::from_millis(100 * (1u64 << attempt))).await;
                                    }
                                    match client.send_text_message(&user_id, token, &text).await {
                                        Ok(_) => {
                                            send_err = None;
                                            break;
                                        }
                                        Err(e) => {
                                            if is_timeout_error(&e) {
                                                send_err = Some(e);
                                                continue;
                                            }
                                            send_err = Some(e);
                                            break;
                                        }
                                    }
                                }
                                if let Some(e) = send_err {
                                    eprintln!("[error] failed to send message: {e:#}");
                                    continue;
                                }
                                println!("[you] {text}");
                            }
                            None => {
                                eprintln!("[system] no context token yet; wait for {} to send a message first", user_id);
                            }
                        }
                    }
                    None => {
                        return Ok(());
                    }
                }
            }
            result = client.get_updates(buf.as_deref()) => {
                match result {
                    Ok(resp) => {
                        consecutive_errors = 0;

                        buf = resp.get_updates_buf.clone();
                        if let Some(ref b) = buf {
                            let _ = db::save_updates_buf(&user_id, b);
                        }

                        for message in resp.messages() {
                            if !message.context_token.is_empty() {
                                context_token = Some(message.context_token.clone());
                                let _ = db::save_context_token(
                                    &user_id,
                                    client.bot_token(),
                                    client.route_tag(),
                                    &message.context_token,
                                );
                                if context_token.is_some() {
                                    eprintln!("[system] session activated – context token saved to DB");
                                }
                            }
                            for item in &message.item_list {
                                print_inbound(&item);
                            }
                        }
                    }
                    Err(err) if is_session_expired(&err) => {
                        bail!("session expired for user `{user_id}`, re-run `wechat-cli login`");
                    }
                    Err(err) if is_timeout_error(&err) => {}
                    Err(err) => {
                        consecutive_errors += 1;
                        eprintln!("chat error ({consecutive_errors}): {err}");
                        if consecutive_errors >= 3 {
                            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                            consecutive_errors = 0;
                        } else {
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        }
                    }
                }
            }
        }
    }
}

fn print_inbound(item: &InboundMessageItem) {
    match item.item_type {
        1 => {
            let text = item
                .text_item
                .as_ref()
                .map(|t| t.text.as_str())
                .or(item.body.as_deref())
                .unwrap_or("[text]");
            println!("[them] {text}");
        }
        2 => {
            println!("[them] [image]");
        }
        4 => {
            println!("[them] [file]");
        }
        t => {
            println!("[them] [unknown type: {t}]");
        }
    }
}

fn is_timeout_error(err: &anyhow::Error) -> bool {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<reqwest::Error>())
        .is_some_and(reqwest::Error::is_timeout)
}
