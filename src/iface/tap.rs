use actix::prelude::*;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::io::{self, Error};
use std::os::unix::io::AsRawFd;
use tokio::fs::OpenOptions as TokioOpenOptions;

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

        // Set non-blocking mode
        let fd = file.as_raw_fd();
        let result = unsafe {
            libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK)
        };
        if result == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok(file)
    }
}

// Tap actor for handling TAP device operations
pub struct Tap {
    device: Option<File>,
}

impl Actor for Tap {
    type Context = Context<Self>;
}

impl Tap {
    pub fn new() -> Self {
        Self { device: None }
    }

    // Read data from the TAP interface asynchronously
    async fn read_data(&mut self) -> io::Result<Vec<u8>> {
        if let Some(file) = &mut self.device {
            let mut buf = vec![0u8; 4096]; // Adjust buffer size as needed
            let n = file.read(&mut buf).await?;
            buf.truncate(n);
            Ok(buf)
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "TAP device not opened"))
        }
    }

    // Write data to the TAP interface asynchronously
    async fn write_data(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(file) = &mut self.device {
            file.write_all(data).await?;
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "TAP device not opened"))
        }
    }
}

// OpenTap message for opening the TAP device
pub struct OpenTap;

impl Message for OpenTap {
    type Result = Result<(), Error>;
}

pub struct UpdateDevice {
    device: File,
}

impl Message for UpdateDevice {
    type Result = ();
}

impl Handler<UpdateDevice> for Tap {
    type Result = ();

    fn handle(&mut self, msg: UpdateDevice, _: &mut Context<Self>) {
        self.device = Some(msg.device);
    }
}

impl Handler<OpenTap> for Tap {
    type Result = ResponseFuture<Result<(), Error>>;

    #[allow(unsafe_code)]
    fn handle(&mut self, _: OpenTap, ctx: &mut Context<Self>) -> Self::Result {
        let addr = ctx.address(); // Get actor's address

        Box::pin(async move {
            match OpenOptions::new().open().await {
                Ok(file) => {
                    let fd = file.as_raw_fd();
                    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
                    if result == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    // Send a message to the actor to update its state
                    addr.do_send(UpdateDevice { device: file });
                    Ok(())
                },
                Err(e) => Err(e),
            }
        })
    }
}
