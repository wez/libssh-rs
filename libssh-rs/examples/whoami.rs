use libssh_rs::*;

fn verify_known_hosts(sess: &Session) -> SshResult<()> {
    let key = sess
        .get_server_public_key()?
        .get_public_key_hash_hexa(PublicKeyHashType::Sha256)?;

    match sess.is_known_server()? {
        KnownHosts::Ok => Ok(()),
        KnownHosts::NotFound | KnownHosts::Unknown => {
            eprintln!("The server is not a known host. Do you trust the host key?");
            eprintln!("Public key hash: {}", key);

            let input = prompt_stdin("Enter yes to trust the key: ")?;
            if input == "yes" {
                sess.update_known_hosts_file()
            } else {
                Err(Error::Fatal("untrusted server".to_string()))
            }
        }
        KnownHosts::Changed => {
            eprintln!("The key for the server has changed. It is now:");
            eprintln!("{}", key);
            Err(Error::Fatal("host key changed".to_string()))
        }
        KnownHosts::Other => {
            eprintln!("The host key for this server was not found, but another");
            eprintln!("type of key exists. An attacker might change the default");
            eprintln!("server key to confuse your client into thinking the key");
            eprintln!("does not exist");
            Err(Error::Fatal("host key has wrong type".to_string()))
        }
    }
}

fn prompt(prompt: &str, echo: bool) -> SshResult<String> {
    get_password(prompt, None, echo, false)
        .ok_or_else(|| Error::Fatal("reading password".to_string()))
}

fn prompt_stdin(prompt: &str) -> SshResult<String> {
    eprintln!("{}", prompt);
    let mut input = String::new();
    let _ = std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| Error::Fatal(format!("reading stdin: {:#}", e)))?;
    Ok(input.trim().to_string())
}

fn authenticate(sess: &Session, user_name: Option<&str>) -> SshResult<()> {
    match dbg!(sess.userauth_none(user_name)?) {
        AuthStatus::Success => return Ok(()),
        _ => {}
    }

    loop {
        let auth_methods = sess.userauth_list(user_name)?;
        eprintln!("{:?}", auth_methods);

        if auth_methods.contains(AuthMethods::PUBLIC_KEY) {
            match dbg!(sess.userauth_public_key_auto(None, None)?) {
                AuthStatus::Success => return Ok(()),
                _ => {}
            }
        }

        if auth_methods.contains(AuthMethods::INTERACTIVE) {
            loop {
                match dbg!(sess.userauth_keyboard_interactive(None, None)?) {
                    AuthStatus::Success => return Ok(()),
                    AuthStatus::Info => {
                        let info = sess.userauth_keyboard_interactive_info()?;
                        eprintln!("{:?}", info);
                        if !info.instruction.is_empty() {
                            eprintln!("{}", info.instruction);
                        }
                        let mut answers = vec![];
                        for p in &info.prompts {
                            answers.push(prompt(&p.prompt, p.echo)?);
                        }
                        sess.userauth_keyboard_interactive_set_answers(&answers)?;

                        continue;
                    }
                    AuthStatus::Denied => {
                        break;
                    }
                    status => {
                        return Err(Error::Fatal(format!(
                            "interactive auth status: {:?}",
                            status
                        )))
                    }
                }
            }
        }

        if auth_methods.contains(AuthMethods::PASSWORD) {
            let pw = prompt("Password: ", false)?;

            match sess.userauth_password(user_name, Some(&pw))? {
                AuthStatus::Success => return Ok(()),
                status => return Err(Error::Fatal(format!("password auth status: {:?}", status))),
            }
        }

        return Err(Error::Fatal("unhandled auth case".to_string()));
    }
}

fn main() -> SshResult<()> {
    let sess = Session::new();
    sess.set_option(SshOption::Hostname("localhost".to_string()))?;
    // sess.set_option(SshOption::LogLevel(LogLevel::Packet))?;
    sess.options_parse_config(None)?;
    sess.connect()?;
    eprintln!(
        "using {} as user name for authentication",
        sess.get_user_name()?
    );
    verify_known_hosts(&sess)?;

    authenticate(&sess, None)?;

    eprintln!("OK!");

    Ok(())
}
