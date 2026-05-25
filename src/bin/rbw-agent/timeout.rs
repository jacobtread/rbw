use futures_util::StreamExt as _;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio_stream::wrappers::UnboundedReceiverStream;

#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone)]
enum Streams {
    Requests,
    Timer,
}

#[derive(Debug)]
enum Action {
    Set(std::time::Duration),
    Clear,
}

pub struct Timeout {
    req_w: UnboundedSender<Action>,
}

impl Timeout {
    pub fn new() -> (Self, UnboundedReceiver<()>) {
        let (req_w, req_r) = unbounded_channel();
        let (timer_w, timer_r) = unbounded_channel();
        tokio::spawn(async move {
            enum Event {
                Request(Action),
                Timer,
            }
            let mut stream = tokio_stream::StreamMap::new();
            stream.insert(
                Streams::Requests,
                UnboundedReceiverStream::new(req_r)
                    .map(Event::Request)
                    .boxed(),
            );
            while let Some(event) = stream.next().await {
                match event {
                    (_, Event::Request(Action::Set(dur))) => {
                        stream.insert(
                            Streams::Timer,
                            futures_util::stream::once(tokio::time::sleep(dur))
                                .map(|()| Event::Timer)
                                .boxed(),
                        );
                    }
                    (_, Event::Request(Action::Clear)) => {
                        stream.remove(&Streams::Timer);
                    }
                    (_, Event::Timer) => {
                        timer_w.send(()).unwrap();
                    }
                }
            }
        });
        (Self { req_w }, timer_r)
    }

    pub fn set(&self, dur: std::time::Duration) {
        self.req_w.send(Action::Set(dur)).unwrap();
    }

    pub fn clear(&self) {
        self.req_w.send(Action::Clear).unwrap();
    }
}
