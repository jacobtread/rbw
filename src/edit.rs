use crate::prelude::*;

use std::{
    ffi::{OsStr, OsString},
    io::{IsTerminal as _, Read as _, Write as _},
    path::PathBuf,
};

fn get_editor() -> (&'static str, OsString) {
    let mut var = "VISUAL";
    let editor = std::env::var_os(var).unwrap_or_else(|| {
        var = "EDITOR";
        std::env::var_os(var).unwrap_or_else(|| "/usr/bin/vim".into())
    });

    (var, editor)
}

fn get_editor_cmd_args(
    editor: &OsString,
    file: &PathBuf,
    var: &str,
) -> Result<(PathBuf, Vec<OsString>)> {
    if contains_shell_metacharacters(&editor) {
        let mut cmdline = OsString::new();
        cmdline.extend([editor.as_ref(), OsStr::new(" "), file.as_os_str()]);

        let editor_args = vec![OsString::from("-c"), cmdline];

        Ok((PathBuf::from("/bin/sh"), editor_args))
    } else {
        let editor = PathBuf::from(editor);
        let mut editor_args = vec![];

        #[allow(clippy::single_match_else)] // more to come
        match editor.file_name() {
            Some(editor) => match editor.to_str() {
                Some("vim" | "nvim") => {
                    // disable swap files and viminfo for password entry
                    editor_args.push(OsString::from("-ni"));
                    editor_args.push(OsString::from("NONE"));
                }
                _ => {
                    // other editor support welcomed
                }
            },
            None => {
                return Err(Error::InvalidEditor {
                    var: var.to_string(),
                    editor: editor.as_os_str().to_os_string(),
                })
            }
        }

        editor_args.push(file.clone().into_os_string());

        Ok((editor, editor_args))
    }
}

pub fn edit(contents: &str, help: &str) -> Result<String> {
    if !std::io::stdin().is_terminal() {
        // directly read from piped content
        return match std::io::read_to_string(std::io::stdin()) {
            Err(e) => Err(Error::FailedToReadFromStdin { err: e }),
            Ok(res) => Ok(res),
        };
    }

    let dir = tempfile::tempdir()?;
    let file = dir.path().join("rbw");
    let mut fh = std::fs::File::create(&file)?;

    fh.write_all(contents.as_bytes())?;
    fh.write_all(help.as_bytes())?;

    drop(fh);

    let (var, editor) = get_editor();

    let (cmd, args) = get_editor_cmd_args(&editor, &file, var)?;

    let res = std::process::Command::new(&cmd).args(&args).status();
    match res {
        Ok(res) => {
            if !res.success() {
                return Err(Error::FailedToRunEditor {
                    editor: cmd.to_owned(),
                    args,
                    res,
                });
            }
        }
        Err(err) => {
            return Err(Error::FailedToFindEditor {
                editor: cmd.to_owned(),
                err,
            })
        }
    }

    let mut fh = std::fs::File::open(&file)?;
    let mut contents = String::new();

    fh.read_to_string(&mut contents)?;

    drop(fh);

    Ok(contents)
}

fn contains_shell_metacharacters(cmd: &OsStr) -> bool {
    cmd.to_str()
        .is_some_and(|s| s.contains(&[' ', '$', '\'', '"'][..]))
}
