use std::{convert::TryFrom as _, ffi::OsString, process::Stdio};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt as _},
    process::{Child, ChildStdout, Command},
};

use crate::{
    error::{Error, Result},
    locked::LockedVec,
};

struct Pinentry {
    child: Child,
    stdout: ChildStdout,
}

impl Pinentry {
    async fn read_line(&mut self) -> Result<LockedVec> {
        let mut v = LockedVec::new();

        loop {
            let b = self.stdout.read_u8().await?;

            if b == b'\n' {
                break;
            }

            // NOTE: This panics if the line is > 4096 bytes
            v.push(b);
        }

        Ok(v)
    }

    async fn spawn(
        binary: &str,
        environment: &crate::protocol::Environment,
        grab: bool,
    ) -> Result<Self> {
        let mut cmd = Command::new(binary);

        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());

        let mut args = vec!["--timeout".into(), "0".into()];

        if let Some(tty) = environment.tty() {
            args.extend(["--ttyname".into(), tty.into()]);
        }

        let env_vars = environment.env_vars();

        // Not all pinentry appear to respect the --display flag, so we also keep the environment
        // variable.
        if let Some(display) = env_vars.get(OsString::from("DISPLAY").as_os_str()) {
            args.extend(["--display".into(), display.clone()]);
        }

        if !grab {
            args.push("--no-global-grab".into());
        }

        cmd.args(args);

        for env_var in &*crate::protocol::ENVIRONMENT_VARIABLES_OS {
            if let Some(val) = env_vars.get(env_var) {
                cmd.env(env_var, val);
            } else {
                cmd.env_remove(env_var);
            }
        }

        cmd.envs(env_vars);

        let mut child = cmd.spawn().map_err(|source| Error::Spawn { source })?;
        // unwrap is safe because we specified stdin as piped in the command opts
        // above

        let Some(stdout) = child.stdout.take() else {
            return Err(Error::PinentryReadOutput {
                source: std::io::Error::other("stdout unavailable"),
            });
        };

        let mut p = Self { child, stdout };
        let line = p.read_line().await?;

        if line.as_str()?.starts_with("OK") {
            Ok(p)
        } else {
            Err(Error::PinentryErrorMessage {
                error: line.as_str()?.to_string(),
            })
        }
    }

    async fn command(&mut self, command: &str) -> Result<LockedVec> {
        let Some(stdin) = &mut self.child.stdin else {
            return Err(Error::WriteStdin {
                source: std::io::Error::other("stdin unavailable"),
            });
        };

        stdin
            .write_all(&format!("{command}\n").as_bytes())
            .await
            .map_err(|source| Error::WriteStdin { source })?;

        loop {
            let mut line = self.read_line().await?;

            let line_str = line.as_str()?;

            if line_str.starts_with("OK") {
                return Ok(line);
            } else if line_str.starts_with("ERR ") {
                let err = &line_str[4..];
                let mut split = err.splitn(2, ' ');
                let code = split.next();
                match code {
                    Some("83886179") => {
                        return Err(Error::PinentryCancelled);
                    }
                    _ => {
                        return Err(Error::PinentryErrorMessage {
                            error: err.to_string(),
                        });
                    }
                }
            } else if line_str.starts_with("S ") {
                continue;
            } else if line_str.starts_with("D ") {
                match self.read_line().await?.as_str()? {
                    "OK" => {
                        let len = line.len();
                        let len = percent_decode(&mut line[..len]);

                        return Ok(LockedVec::from_slice(&line[2..len]));
                    }
                    line => {
                        return Err(Error::PinentryErrorMessage {
                            error: line.to_string(),
                        });
                    }
                }
            } else {
                return Err(Error::PinentryErrorMessage {
                    error: line.as_str()?.to_string(),
                });
            }
        }
    }

    async fn wait(&mut self) -> Result<()> {
        self.child
            .wait()
            .await
            .map_err(|source| Error::PinentryWait { source })?;

        Ok(())
    }
}

pub async fn getpin(
    pinentry: &str,
    prompt: &str,
    desc: &str,
    err: Option<&str>,
    environment: &crate::protocol::Environment,
    grab: bool,
) -> Result<crate::locked::Password> {
    let mut pinentry = Pinentry::spawn(pinentry, environment, grab).await?;

    pinentry.command("SETTITLE rbw").await?;
    pinentry.command(&format!("SETPROMPT {prompt}")).await?;
    pinentry.command(&format!("SETDESC {desc}")).await?;

    if let Some(err) = err {
        pinentry.command(&format!("SETERROR {err}")).await?;
    }

    let buf = pinentry.command("GETPIN").await?;

    pinentry.wait().await?;

    Ok(crate::locked::Password::new(buf))
}

pub async fn confirm(
    pinentry: &str,
    desc: &str,
    environment: &crate::protocol::Environment,
    grab: bool,
) -> Result<bool> {
    let mut pinentry = Pinentry::spawn(pinentry, environment, grab).await?;

    pinentry.command("SETTITLE rbw").await?;
    pinentry.command(&format!("SETDESC {desc}")).await?;

    pinentry.command("CONFIRM").await?;

    pinentry.wait().await?;

    Ok(true)
}

// not using the percent-encoding crate because it doesn't provide a way to do
// this in-place, and we want the password to always live within the locked
// vec. should really move something like this into the percent-encoding crate
// at some point.
fn percent_decode(buf: &mut [u8]) -> usize {
    let mut read_idx = 0;
    let mut write_idx = 0;
    let len = buf.len();

    while read_idx < len {
        let mut c = buf[read_idx];

        if c == b'%' && read_idx + 2 < len {
            if let Some(h) = char::from(buf[read_idx + 1]).to_digit(16) {
                if let Some(l) = char::from(buf[read_idx + 2]).to_digit(16) {
                    // h and l were parsed from a single hex digit, so they
                    // must be in the range 0-15, so these unwraps are safe
                    c = u8::try_from(h).unwrap() * 0x10 + u8::try_from(l).unwrap();
                    read_idx += 2;
                }
            }
        }

        buf[write_idx] = c;
        read_idx += 1;
        write_idx += 1;
    }

    write_idx
}
