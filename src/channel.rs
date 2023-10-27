#[derive(Clone)]
pub struct Sender<T> {
    inner: InnerSender<T>,
}
#[derive(Clone)]
pub enum InnerSender<T> {
    SyncSender(std::sync::mpsc::SyncSender<T>),
    Sender(std::sync::mpsc::Sender<T>)
}

pub struct Receiver<T> {
    inner: std::sync::mpsc::Receiver<T>,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct SendError<T>(pub T);

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct RecvError;

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum TryRecvError {
    /// This **channel** is currently empty, but the **Sender**(s) have not yet
    /// disconnected, so data may yet become available.
    Empty,

    /// The **channel**'s sending half has become disconnected, and there will
    /// never be any more data received on it.
    Disconnected,
}
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum RecvTimeoutError {
    /// This **channel** is currently empty, but the **Sender**(s) have not yet
    /// disconnected, so data may yet become available.
    Timeout,
    /// The **channel**'s sending half has become disconnected, and there will
    /// never be any more data received on it.
    Disconnected,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum TrySendError<T> {
    Full(T),
    Disconnected(T)
}



impl<T> Sender<T> {
    fn new_sync(sender : std::sync::mpsc::SyncSender<T>) -> Self {
        Self {
            inner : InnerSender::SyncSender(sender)
        }
    }
    fn new(sender : std::sync::mpsc::Sender<T>) -> Self {
        Self {
            inner : InnerSender::Sender(sender)
        }
    }

    pub fn send(&self, msg : T) -> Result<(), SendError<T>> {
        let res = match &self.inner {
            InnerSender::SyncSender(s) => s.send(msg),
            InnerSender::Sender(s) => s.send(msg),
        };
        match res {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into())
        }
    }

    pub fn try_send(&self, msg : T) -> Result<(), TrySendError<T>> {
        match &self.inner {
            InnerSender::SyncSender(s) => match s.try_send(msg) {
                Ok(_) => Ok(()),
                Err(e) => Err(e.into())
            },
            InnerSender::Sender(s) => match s.send(msg) {
                Ok(_) => Ok(()),
                Err(e) => Err(e.into())
            },
        }
    }
}

impl<T> Receiver<T> {
    fn new(receiver : std::sync::mpsc::Receiver<T>) -> Self {
        Self {
            inner : receiver
        }
    }
    pub fn recv(&self) -> Result<T, RecvError> {
        match self.inner.recv() {
            Ok(v) => Ok(v),
            Err(e) => Err(e.into())
        }
    }
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        match self.inner.try_recv() {
            Ok(v) => Ok(v),
            Err(e) => Err(e.into())
        }
    }
    pub fn recv_timeout(&self, duration : std::time::Duration) -> Result<T, RecvTimeoutError> {
        match self.inner.recv_timeout(duration) {
            Ok(v) => Ok(v),
            Err(e) => Err(e.into())
        }
    }
}

pub fn sync_channel<T>(bound : usize) -> (Sender<T>, Receiver<T>) {
    let (sender, receiver) = std::sync::mpsc::sync_channel(bound);
    (Sender::new_sync(sender), Receiver::new(receiver))
}

pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let (sender, receiver) = std::sync::mpsc::channel();
    (Sender::new(sender), Receiver::new(receiver))
}


impl<T> From<std::sync::mpsc::TrySendError<T>> for TrySendError<T> {
    fn from(value: std::sync::mpsc::TrySendError<T>) -> Self {
        match value {
            std::sync::mpsc::TrySendError::Full(v) => TrySendError::Full(v),
            std::sync::mpsc::TrySendError::Disconnected(v) => TrySendError::Disconnected(v),
        }
    }
}
impl<T> From<std::sync::mpsc::SendError<T>> for TrySendError<T> {
    fn from(value: std::sync::mpsc::SendError<T>) -> Self {
        TrySendError::Disconnected(value.0)
    }
}

impl<T> From<std::sync::mpsc::SendError<T>> for SendError<T> {
    fn from(value: std::sync::mpsc::SendError<T>) -> Self {
        SendError(value.0)
    }
}

impl From<std::sync::mpsc::RecvError> for RecvError {
    fn from(_value: std::sync::mpsc::RecvError) -> Self {
        RecvError
    }
}

impl From<std::sync::mpsc::TryRecvError> for TryRecvError {
    fn from(value: std::sync::mpsc::TryRecvError) -> Self {
        match value {
            std::sync::mpsc::TryRecvError::Disconnected => TryRecvError::Disconnected,
            std::sync::mpsc::TryRecvError::Empty => TryRecvError::Empty
        }
    }
}
impl From<std::sync::mpsc::RecvTimeoutError> for RecvTimeoutError {
    fn from(value: std::sync::mpsc::RecvTimeoutError) -> Self {
        match value {
            std::sync::mpsc::RecvTimeoutError::Disconnected => RecvTimeoutError::Disconnected,
            std::sync::mpsc::RecvTimeoutError::Timeout => RecvTimeoutError::Timeout
        }
    }
}