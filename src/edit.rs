use crate::prelude::*;

use std::{
    ffi::{OsStr, OsString},
    io::{IsTerminal as _, Read as _, Write as _},
    path::{Path, PathBuf},
};

fn contains_shell_metacharacters(cmd: &OsStr) -> bool {
    cmd.to_str()
        .is_some_and(|s| s.contains(&[' ', '$', '\'', '"']))
}

fn get_editor_metachars(editor: &OsStr, file: &Path) -> (PathBuf, Vec<OsString>) {
    (
        PathBuf::from("/bin/sh"),
        vec![
            "-c".into(),
            [editor, OsStr::new(" "), file.as_os_str()]
                .into_iter()
                .collect::<OsString>(),
        ],
    )
}

fn get_editor_cmd_args(editor: &Path, file: &Path) -> Option<(PathBuf, Vec<OsString>)> {
    match editor.file_name()?.to_str() {
        // disable swap files and viminfo for password entry
        Some("vim" | "nvim") => Some((
            editor.to_owned(),
            vec!["-ni".into(), "NONE".into(), file.into()],
        )),
        // other editor support welcomed
        _ => Some((editor.to_owned(), vec![file.into()])),
    }
}

fn get_editor(file: &Path) -> Result<(PathBuf, Vec<OsString>)> {
    let mut var = "VISUAL";

    let editor = std::env::var_os(var).unwrap_or_else(|| {
        var = "EDITOR";
        std::env::var_os(var).unwrap_or_else(|| "/usr/bin/vim".into())
    });

    if contains_shell_metacharacters(&editor) {
        Ok(get_editor_metachars(&editor, file))
    } else {
        Ok(
            get_editor_cmd_args(Path::new(&editor), file).ok_or(Error::InvalidEditor {
                var: var.to_string(),
                editor,
            })?,
        )
    }
}

/// Small helper to avoid heap allocation of std::fs::write(.., [str1, str2].join(""))
fn write_strs(path: &Path, pieces: &[&str]) -> Result<()> {
    let mut f = std::fs::File::create(path)?;
    for piece in pieces {
        f.write_all(piece.as_bytes())?;
    }
    Ok(())
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

    write_strs(&file, &[contents, help])?;

    let (cmd, args) = get_editor(&file)?;

    let res = std::process::Command::new(&cmd).args(&args).status();
    match res {
        Ok(res) => {
            if !res.success() {
                return Err(Error::FailedToRunEditor {
                    editor: cmd,
                    args,
                    res,
                });
            }
        }
        Err(err) => return Err(Error::FailedToFindEditor { editor: cmd, err }),
    }

    // TODO: This should be zeroized as it contains sensible stuff
    Ok(std::fs::read_to_string(&file)?)
}
