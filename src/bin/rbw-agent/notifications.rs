use std::sync::Arc;

use futures_util::{SinkExt as _, StreamExt as _};
use tokio::{
    sync::{
        broadcast::{Receiver, Sender},
        oneshot,
    },
    task::JoinHandle,
};

#[derive(Clone, Copy, Debug)]
pub enum Message {
    Disconnected,
    Sync,
    Logout,
}

fn parse_message(message: tokio_tungstenite::tungstenite::Message) -> Option<Message> {
    let tokio_tungstenite::tungstenite::Message::Binary(data) = message else {
        return None;
    };

    // the first few bytes with the 0x80 bit set, plus one byte terminating the length contain the length of the message
    let len_buffer_length = data.iter().position(|&x| (x & 0x80) == 0)? + 1;

    let unpacked_messagepack = rmpv::decode::read_value(&mut &data[len_buffer_length..]).ok()?;

    let unpacked_message = unpacked_messagepack.as_array()?;
    let message_type = unpacked_message.first()?.as_u64()?;
    // invocation
    if message_type != 1 {
        return None;
    }
    let target = unpacked_message.get(3)?.as_str()?;
    if target != "ReceiveMessage" {
        return None;
    }

    let args = unpacked_message.get(4)?.as_array()?;
    let map = args.first()?.as_map()?;
    for (k, v) in map {
        if k.as_str()? == "Type" {
            let ty = v.as_i64()?;
            return match ty {
                11 => Some(Message::Logout),
                _ => Some(Message::Sync),
            };
        }
    }

    None
}

pub struct NotificationsHandler {
    disconnect_tx: Option<oneshot::Sender<()>>,
    read_handle: Option<JoinHandle<()>>,
    broadcast: Arc<Sender<Message>>,
}

impl NotificationsHandler {
    pub fn new() -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(32);

        Self {
            disconnect_tx: None,
            read_handle: None,
            broadcast: Arc::new(tx),
        }
    }

    async fn subscribe_ws(
        &mut self,
        url: String,
    ) -> Result<(oneshot::Sender<()>, JoinHandle<()>), Box<dyn std::error::Error + 'static>> {
        let url = url::Url::parse(url.as_str())?;
        let (mut ws_stream, _response) = tokio_tungstenite::connect_async(url).await?;

        ws_stream
            .send(tokio_tungstenite::tungstenite::Message::Text(
                "{\"protocol\":\"messagepack\",\"version\":1}\x1e".into(),
            ))
            .await?;

        let (disconnect_tx, mut disconnect_rx) = tokio::sync::oneshot::channel::<()>();

        let broadcast = self.broadcast.clone();
        let read_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut disconnect_rx => break,
                    msg = ws_stream.next() => {
                        match msg {
                            Some(Ok(msg)) => {
                                if let Some(parsed) = parse_message(msg) {
                                    let _ = broadcast.send(parsed);
                                }
                            },
                            Some(Err(e)) => {
                                eprintln!("websocket error: {e:?}");
                                break;
                            },
                            None => break,
                        }
                    }
                }
            }

            let _ = ws_stream.close(None).await;
            let _ = broadcast.send(Message::Disconnected);
        });

        Ok((disconnect_tx, read_task))
    }

    pub async fn connect(&mut self, url: String) -> Result<(), Box<dyn std::error::Error>> {
        if self.is_connected() {
            self.disconnect().await?;
        }

        let (disconnect_tx, read_task) = self.subscribe_ws(url).await?;

        self.disconnect_tx = Some(disconnect_tx);
        self.read_handle = Some(read_task);

        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.disconnect_tx.is_some()
            && self.read_handle.is_some()
            && !self.read_handle.as_ref().unwrap().is_finished()
    }

    pub async fn disconnect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(disconnect_tx) = self.disconnect_tx.take() {
            let _ = disconnect_tx.send(());
            self.read_handle.take().unwrap().await?;
        }

        self.disconnect_tx = None;
        self.read_handle = None;

        Ok(())
    }

    pub fn get_channel(&self) -> Receiver<Message> {
        self.broadcast.subscribe()
    }
}
