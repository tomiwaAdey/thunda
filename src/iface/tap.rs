use actix::prelude::*;
use std::sync::{Arc, Mutex};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::io::{self, Error};
use std::os::unix::io::AsRawFd;
use tokio::fs::OpenOptions as TokioOpenOptions;
use futures::Future;
use std::pin::Pin;

struct OpenOptions {
    read: bool,
    write: bool,
}

impl OpenOptions {
    fn new() -> Self {
        Self { read: true, write: true }
    }

    #[allow(unsafe_code)]
    async fn open(&self) -> io::Result<File> {
        let path = "/dev/net/tun";
        let file = TokioOpenOptions::new()
            .read(self.read)
            .write(self.write)
            .open(path)
            .await?;
        Ok(file)
    }
}

pub trait DeviceOpener {
    fn open(&self) -> Pin<Box<dyn Future<Output = io::Result<File>> + Send>>;
}

struct Device;

impl DeviceOpener for Device {
    #[allow(unsafe_code)]
    fn open(&self) -> Pin<Box<dyn Future<Output = io::Result<File>> + Send>> {
        Box::pin(async move {
            match OpenOptions::new().open().await {
                Ok(file) => {
                    // Set non-blocking mode
                    let fd = file.as_raw_fd();
                    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
                    if result == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(file)
                },
                Err(e) => Err(e),
            }
        })
    }
}

// Tap actor for handling TAP device operations
pub struct Tap {
    device: Arc<Mutex<Option<File>>>
}

impl Actor for Tap {
    type Context = Context<Self>;
}

impl Tap {
    fn new() -> Self {
        Self {
            device: Arc::new(Mutex::new(None)),
         }
    }
}

// Message for opening the TAP device
// Takes the opener as an arg
pub struct OpenTap {
    pub opener: Box<dyn DeviceOpener + Send>,
}


impl Message for OpenTap {
    type Result = Result<(), Error>;
}

impl Handler<OpenTap> for Tap {
    type Result = ResponseFuture<Result<(), io::Error>>;

    fn handle(&mut self, msg: OpenTap, ctx: &mut Context<Self>) -> Self::Result {
        let device_future = msg.opener.open();
        let addr: Addr<Tap> = ctx.address(); // Get actor's address
        Box::pin(async move {
            match device_future.await {
                Ok(file) => {
                    addr.do_send(UpdateDevice { device: file });
                    Ok(())
                },
                Err(e) => Err(e),
            }
        })
    }
}


pub struct UpdateDevice {
    device: File,
}

impl Message for UpdateDevice {
    type Result = Result<(), io::Error>;
}

impl Handler<UpdateDevice> for Tap {
    type Result = Result<(), io::Error>;

    fn handle(&mut self, msg: UpdateDevice, _: &mut Context<Self>) -> Self::Result {
        let mut device = self.device.lock().map_err(|_| io::Error::new(io::ErrorKind::Other, "Mutex lock poisoned"))?;
        *device = Some(msg.device);
        Ok(())
    }
}

// Message to request a write operation to the TAP device
pub struct WriteMessage {
    pub data: Vec<u8>,
}

impl Message for WriteMessage {
    type Result = Result<(), std::io::Error>;
}

impl Handler<WriteMessage> for Tap {
    type Result = ResponseFuture<Result<(), io::Error>>;

    fn handle(&mut self, msg: WriteMessage, _: &mut Context<Self>) -> Self::Result {
        let device = self.device.clone();

        Box::pin(async move {
            let device_lock = device.lock().map_err(|_| io::Error::new(io::ErrorKind::Other, "Mutex lock poisoned"));
            match device_lock {
                Ok(mut device) => {
                    if let Some(file) = device.as_mut() {
                        file.write_all(&msg.data).await.map_err(|e| e.into())
                    } else {
                        Err(io::Error::new(io::ErrorKind::NotFound, "Device not found"))
                    }
                },
                Err(e) => Err(e),
            }
        })
    }
}



// Message to request reading from the TAP device
pub struct ReadMessage;

impl Message for ReadMessage {
    type Result = Result<Vec<u8>, std::io::Error>;
}


impl Handler<ReadMessage> for Tap {
    type Result = ResponseFuture<Result<Vec<u8>, io::Error>>;

    fn handle(&mut self, _: ReadMessage, _: &mut Context<Self>) -> Self::Result {
        let device = self.device.clone();

        Box::pin(async move {
            let device_lock = device.lock().map_err(|_| io::Error::new(io::ErrorKind::Other, "Mutex lock poisoned"));
            match device_lock {
                Ok(mut device) => {
                    if let Some(file) = device.as_mut() {
                        let mut buf = vec![0u8; 4096];
                        let n = file.read(&mut buf).await?;
                        buf.truncate(n);
                        Ok(buf)
                    } else {
                        Err(io::Error::new(io::ErrorKind::NotFound, "Device not found"))
                    }
                },
                Err(e) => Err(e),
            }
        })
    }
}


struct MockDevice;
impl DeviceOpener for MockDevice {
    fn open(&self) -> Pin<Box<dyn Future<Output = io::Result<File>> + Send>> {
        Box::pin(async {
            // Simulate successful device opening
            Ok(File::from_std(std::fs::File::open("/dev/null").unwrap()))
        })
    }
}

struct MockFailingDevice;
impl DeviceOpener for MockFailingDevice {
    fn open(&self) -> Pin<Box<dyn Future<Output = io::Result<File>> + Send>> {
        Box::pin(async {
            // Simulate an I/O error using io::Error
            Err(io::Error::new(io::ErrorKind::Other, "Mocked device open failure"))
        })
    }
}

#[actix_rt::test]
async fn test_open() {
    let mock_device_opener = MockDevice {};
    let tap_actor = Tap::new().start();
    let open_result = tap_actor.send(OpenTap { opener: Box::new(mock_device_opener) }).await;
    assert!(open_result.is_ok(), "The OpenTap message should be handled without errors");
}

#[actix_rt::test]
async fn test_open_failure() {
    let tap_actor = Tap::new().start();
    let failing_device_opener = MockFailingDevice {};

    let result = tap_actor.send(OpenTap { opener: Box::new(failing_device_opener) }).await;

    assert!(result.unwrap().is_err(), "Opening the TAP device should fail under simulated error conditions");
}

#[actix_rt::test]
async fn test_write() {
    let tap_actor = Tap::new().start();
    let frame_data = vec![0xde, 0xad, 0xbe, 0xef]; // Example Ethernet frame data
    let write_result = tap_actor.send(WriteMessage { data: frame_data }).await;
    assert!(write_result.is_ok(), "The WriteMessage should be processed without errors");
}


#[actix_rt::test]
async fn test_read() {
    let tap_actor = Tap::new().start();
    let read_result = tap_actor.send(ReadMessage).await;
    assert!(read_result.is_ok(), "The ReadMessage should be processed without errors");
}

#[actix_rt::test]
async fn test_read_with_no_device() {
    let tap_actor = Tap::new().start();

    let result = tap_actor.send(ReadMessage).await;

    assert!(result.unwrap().is_err(), "Read operation should fail when no device is open");
}

#[actix_rt::test]
async fn test_write_with_no_device() {
    let tap_actor = Tap::new().start();
    let data_to_write = vec![0xde, 0xad, 0xbe, 0xef];

    let result = tap_actor.send(WriteMessage { data: data_to_write }).await;

    assert!(result.unwrap().is_err(), "Write operation should fail when no device is open");
}
