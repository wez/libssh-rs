use std::path::PathBuf;

fn main() {
    if std::env::var_os("CARGO_FEATURE_VENDORED").is_some() {
        let mut cfg = cc::Build::new();
        cfg.define("LIBSSH_STATIC", None);
        cfg.define("_GNU_SOURCE", None);
        cfg.include("vendored/include");

        let dst = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
        let include = dst.join("include");
        std::fs::create_dir_all(&include).unwrap();
        cfg.include(&include);
        println!("cargo:include={}", include.display());
        println!("cargo:root={}", dst.display());

        let target = std::env::var("TARGET").unwrap();
        cfg.define("GLOBAL_CLIENT_CONFIG", Some("\"/etc/ssh/ssh_config\""));
        cfg.define("HAVE_GETADDRINFO", Some("1"));
        cfg.define("HAVE_LIBCRYPTO", Some("1"));
        cfg.define("HAVE_OPENSSL_AES_H", Some("1"));
        cfg.define("HAVE_OPENSSL_BLOWFISH_H", Some("1"));
        cfg.define("HAVE_OPENSSL_DES_H", Some("1"));
        cfg.define("HAVE_OPENSSL_ECC", Some("1"));
        cfg.define("HAVE_OPENSSL_ECDH_H", Some("1"));
        cfg.define("HAVE_OPENSSL_ECDSA_H", Some("1"));
        cfg.define("HAVE_OPENSSL_EC_H", Some("1"));
        cfg.define("HAVE_OPENSSL_EVP_CHACHA20", Some("1"));
        cfg.define("HAVE_OPENSSL_EVP_DIGESTSIGN", Some("1"));
        cfg.define("HAVE_OPENSSL_EVP_DIGESTVERIFY", Some("1"));
        cfg.define("HAVE_OPENSSL_EVP_KDF_CTX_NEW_ID", Some("1"));
        cfg.define("HAVE_OPENSSL_FIPS_MODE", Some("1"));
        cfg.define("HAVE_OPENSSL_IA32CAP_LOC", Some("1"));
        cfg.define("HAVE_STDINT_H", Some("1"));
        cfg.define("HAVE_SYS_TIME_H", Some("1"));
        cfg.define("WITH_ZLIB", Some("1"));

        if target.contains("windows") {
            cfg.define("HAVE_IO_H", Some("1"));
            cfg.define("HAVE_MEMSET_S", Some("1"));
            cfg.define("HAVE_SECURE_ZERO_MEMORY", Some("1"));
            cfg.define("HAVE__SNPRINTF", Some("1"));
            cfg.define("HAVE__SNPRINTF_S", Some("1"));
            cfg.define("HAVE__STRTOUI64", Some("1"));
            cfg.define("HAVE__VSNPRINTF", Some("1"));
            cfg.define("HAVE__VSNPRINTF_S", Some("1"));
            cfg.define("HAVE_ISBLANK", Some("1"));
        } else {
            cfg.define("HAVE_ARPA_INET_H", Some("1"));
            cfg.define("HAVE_CLOCK_GETTIME", Some("1"));
            cfg.define("HAVE_PTHREAD_H", Some("1"));
            cfg.define("HAVE_SELECT", Some("1"));
            cfg.define("HAVE_SNPRINTF", Some("1"));
            cfg.define("HAVE_STRTOULL", Some("1"));
            cfg.define("HAVE_TERMIOS_H", Some("1"));
            cfg.define("HAVE_UNISTD_H", Some("1"));
            cfg.define("HAVE_VSNPRINTF", Some("1"));

            if !target.contains("darwin") {
                cfg.define("HAVE_POLL", Some("1"));
            }
        }
        if target.contains("linux") {
            cfg.define("HAVE_STRNDUP", Some("1"));
        }

        let compiler = cfg.get_compiler();
        if compiler.is_like_gnu() {
            cfg.define("HAVE_COMPILER__FUNCTION__", Some("1"));
            cfg.define("HAVE_COMPILER__FUNC__", Some("1"));
            cfg.define("HAVE_GCC_THREAD_LOCAL_STORAGE", Some("1"));
        }

        if compiler.is_like_msvc() {
            cfg.define("HAVE_COMPILER__FUNC__", Some("1"));
            cfg.define("HAVE_MSC_THREAD_LOCAL_STORAGE", Some("1"));
        }

        std::fs::write(include.join("config.h"), "// nothing").unwrap();

        let version = std::fs::read_to_string("vendored/include/libssh/libssh_version.h.cmake")
            .unwrap()
            .replace("@libssh_VERSION_MAJOR@", "0")
            .replace("@libssh_VERSION_MINOR@", "8")
            .replace("@libssh_VERSION_PATCH@", "90");

        std::fs::create_dir_all(include.join("libssh")).unwrap();
        std::fs::write(include.join("libssh/libssh_version.h"), version).unwrap();

        println!("cargo:rerun-if-env-changed=DEP_Z_INCLUDE");
        if let Some(path) = std::env::var_os("DEP_Z_INCLUDE") {
            cfg.include(path);
        }

        println!("cargo:rerun-if-env-changed=DEP_OPENSSL_INCLUDE");
        if let Some(path) = std::env::var_os("DEP_OPENSSL_INCLUDE") {
            if let Some(path) = std::env::split_paths(&path).next() {
                if let Some(path) = path.to_str() {
                    if path.len() > 0 {
                        cfg.include(path);
                    }
                }
            }
        }

        /*
        for (k, v) in std::env::vars() {
            if k.starts_with("CARGO") || k.starts_with("DEP") {
                println!("{}={}", k, v);
            }
        }
        */

        cfg.warnings(false);
        for f in &[
            "agent.c",
            "auth.c",
            "base64.c",
            "bignum.c",
            "buffer.c",
            "callbacks.c",
            "channels.c",
            "client.c",
            "config.c",
            "connect.c",
            "connector.c",
            "crypto_common.c",
            "curve25519.c",
            "dh.c",
            "dh_crypto.c",
            "ecdh.c",
            "error.c",
            "getpass.c",
            "init.c",
            "kdf.c",
            "kex.c",
            "known_hosts.c",
            "knownhosts.c",
            "legacy.c",
            "log.c",
            "match.c",
            "messages.c",
            "misc.c",
            "options.c",
            "packet.c",
            "packet_cb.c",
            "packet_crypt.c",
            "pcap.c",
            "pki.c",
            "pki_container_openssh.c",
            "poll.c",
            "session.c",
            "scp.c",
            "socket.c",
            "string.c",
            "threads.c",
            "wrapper.c",
            "external/bcrypt_pbkdf.c",
            "external/blowfish.c",
            "config_parser.c",
            "token.c",
            "pki_ed25519_common.c",
            "threads/noop.c",
        ] {
            cfg.file(&format!("vendored/src/{}", f));
        }

        if cfg!(unix) {
            cfg.file("vendored/src/threads/pthread.c");
        }
        if cfg!(windows) {
            cfg.file("vendored/src/threads/winlocks.c");
        }
        cfg.compile("libssh");

        if target.contains("windows") {
            println!("cargo:rustc-link-lib=bcrypt");
            println!("cargo:rustc-link-lib=crypt32");
            println!("cargo:rustc-link-lib=user32");
            println!("cargo:rustc-link-lib=ntdll");
        }

        println!("cargo:rustc-link-lib=ssl");
        println!("cargo:rustc-link-lib=crypto");
        println!("cargo:rustc-link-lib=z");
    } else {
        pkg_config::Config::new()
            .atleast_version("0.8")
            .probe("libssh")
            .expect("dynamically linked libssh >= 0.8 is required");
    }
}
