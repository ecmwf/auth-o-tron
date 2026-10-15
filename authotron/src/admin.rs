// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! `authotron admin`: operator commands that reach the server's store through its own
//! configuration file and open no listener, for example inside a server pod with
//! `kubectl exec deploy/authotron -- authotron admin logins list --realm idp`.

use crate::{
    browser::BrowserLoginState,
    config::{ConfigV2, LoggingConfig, ui::BrowserBackendConfig},
    metrics::Metrics,
    oauth::{
        admin::{AdminError, LeftReason, LoginFilter, MAX_CONSECUTIVE_UPSTREAM_FAILURES},
        audit::{self, family_ref},
        refresh::FamilySummary,
        runtime::OAuthRuntime,
    },
    utils::logger,
};
use chrono::{DateTime, SecondsFormat};
use std::{collections::BTreeSet, io::Write, sync::Arc};

pub const USAGE: &str = "\
usage: authotron admin logins list   --realm <realm> [--username <name>] [--client <id>] [--limit <n>]
       authotron admin logins revoke --realm <realm> (--username <name> | --all-users)
                                     [--client <id>] [--dry-run]";

/// Logins `list` shows unless `--limit` says otherwise, and the most it accepts.
const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 10_000;

/// How a command that did not fail ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finished {
    Done,
    /// The logins were revoked, but some of their upstream grants may still be live at
    /// the provider; the report names them.
    UpstreamLeft,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help,
    /// Shows at most `limit` of the selected logins, newest first.
    List {
        filter: LoginFilter,
        limit: usize,
    },
    /// Revokes the selected logins, or only shows them with `dry_run`.
    Revoke {
        filter: LoginFilter,
        dry_run: bool,
    },
}

/// Parses the arguments after `authotron admin`. A value follows its flag or is joined to
/// it with `=`; a separate value cannot start with `--`, so a forgotten value is not
/// mistaken for the next flag.
/// Valid: `logins list --realm idp`, `logins list --realm=idp --client cli --limit 20`,
/// `logins revoke --realm idp --username alice --dry-run`,
/// `logins revoke --realm idp --all-users --client cli`, `--help`.
/// Invalid: `logins list` (no realm), `logins revoke --realm idp` (neither a username nor
/// `--all-users`), `--username alice --all-users` together, `--realm --username alice`,
/// a flag given twice, an empty value, `--limit 0`, `--dry-run` with `list`, `--limit`
/// with `revoke`, or any other argument.
pub fn parse(args: &[String]) -> Result<Command, String> {
    if let [only] = args
        && ["--help", "-h", "help"].contains(&only.as_str())
    {
        return Ok(Command::Help);
    }
    let [scope, action, flags @ ..] = args else {
        return Err("expected `logins list` or `logins revoke`".into());
    };
    if scope != "logins" || !["list", "revoke"].contains(&action.as_str()) {
        return Err("expected `logins list` or `logins revoke`".into());
    }
    let (mut realm, mut username, mut client, mut limit) = (None, None, None, None);
    let mut switches = BTreeSet::new();
    let mut rest = flags.iter();
    while let Some(arg) = rest.next() {
        let (name, joined) = match arg.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (arg.as_str(), None),
        };
        let slot = match name {
            "--realm" => &mut realm,
            "--username" => &mut username,
            "--client" => &mut client,
            "--limit" => &mut limit,
            "--all-users" | "--dry-run" if joined.is_none() => {
                if !switches.insert(name) {
                    return Err(format!("{name} is given twice"));
                }
                continue;
            }
            _ => return Err(format!("unknown argument `{arg}`")),
        };
        let value = match joined {
            Some(value) => value,
            None => rest
                .next()
                .filter(|value| !value.starts_with("--"))
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))?,
        };
        if value.is_empty() {
            return Err(format!("{name} needs a value"));
        }
        if slot.replace(value).is_some() {
            return Err(format!("{name} is given twice"));
        }
    }
    let filter = LoginFilter {
        realm: realm.ok_or("--realm is required")?,
        username,
        client,
    };
    if action == "list" {
        if !switches.is_empty() {
            return Err("--all-users and --dry-run apply to `revoke` only".into());
        }
        let limit = match limit {
            Some(limit) => limit
                .parse()
                .ok()
                .filter(|limit| (1..=MAX_LIMIT).contains(limit))
                .ok_or(format!("--limit must be a number from 1 to {MAX_LIMIT}"))?,
            None => DEFAULT_LIMIT,
        };
        return Ok(Command::List { filter, limit });
    }
    if limit.is_some() {
        return Err("--limit applies to `list` only".into());
    }
    match (filter.username.is_some(), switches.contains("--all-users")) {
        (true, true) => Err("give either --username or --all-users".into()),
        (false, false) => Err("revoking every user of a realm needs --all-users".into()),
        _ => Ok(Command::Revoke {
            filter,
            dry_run: switches.contains("--dry-run"),
        }),
    }
}

fn message(error: AdminError) -> String {
    match error {
        AdminError::NoLogins => {
            "no client has refresh tokens enabled, so there are no logins".into()
        }
        AdminError::PerProcess => PER_PROCESS.into(),
        AdminError::Unavailable => "the Valkey store did not answer".into(),
    }
}

const PER_PROCESS: &str = "the memory browser-session backend keeps refresh-token families \
inside each server process, out of reach of this command; restarting the server ends them all";

/// Starts the authorization-server runtime the configuration describes, without its
/// listeners. The memory backend is refused first: its families are not in this process.
async fn runtime(config: &ConfigV2) -> Result<Arc<OAuthRuntime>, String> {
    let session = config.ui.browser_session.as_ref();
    if config.oauth.enabled
        && session.is_some_and(|session| matches!(session.backend, BrowserBackendConfig::Memory {}))
    {
        return Err(PER_PROCESS.into());
    }
    match OAuthRuntime::initialize(config).await {
        Ok(Some(runtime)) => Ok(runtime),
        Ok(None) => Err("OAuth is not enabled, so there are no logins".into()),
        Err(error) => Err(format!("cannot start the OAuth runtime: {error}")),
    }
}

/// Logs to standard error in the configured format and level, but the events of ended
/// families and upstream revocations at least at INFO: a revocation is always logged.
pub fn init_logging(logging: &LoggingConfig) {
    logger::init_logging_to_stderr(logging, &audit::TARGETS);
}

/// Runs `command` against the store of `config`, writing its report to `out`: the
/// selected logins, then for `revoke` what it did. Audit events go to the log
/// ([`init_logging`]).
pub async fn run(
    config: &ConfigV2,
    command: &Command,
    out: &mut impl Write,
) -> Result<Finished, String> {
    let write = |error: std::io::Error| format!("cannot write the report: {error}");
    let filter = match command {
        Command::Help => {
            writeln!(out, "{USAGE}").map_err(write)?;
            return Ok(Finished::Done);
        }
        Command::List { filter, .. } | Command::Revoke { filter, .. } => filter,
    };
    let runtime = runtime(config).await?;
    let found = runtime.find_logins(filter).await.map_err(message)?;
    match command {
        Command::List { limit, .. } => {
            table(out, &found[..found.len().min(*limit)]).map_err(write)?;
            if found.len() > *limit {
                writeln!(out, "showing {limit} of {} logins", found.len()).map_err(write)?;
            } else {
                writeln!(out, "{} logins", found.len()).map_err(write)?;
            }
        }
        Command::Revoke { dry_run: true, .. } => {
            table(out, &found).map_err(write)?;
            writeln!(out, "dry run: would revoke {} logins", found.len()).map_err(write)?;
        }
        _ => {
            table(out, &found).map_err(write)?;
            let browser = BrowserLoginState::new(config)
                .map_err(|error| format!("invalid browser sign-in configuration: {error}"))?;
            let revoked = runtime
                .revoke_found(&found, &browser, &Metrics::new())
                .await
                .map_err(message)?;
            writeln!(
                out,
                "revoked {} logins; upstream grants: {} revoked at the provider, {} not \
                 supported there, {} failed, {} skipped",
                revoked.families,
                revoked.upstream_sent,
                revoked.upstream_unsupported,
                revoked.upstream_failed,
                revoked.upstream_skipped
            )
            .map_err(write)?;
            for left in &revoked.upstream_left {
                let reason = match left.reason {
                    LeftReason::Failed => "failed".into(),
                    LeftReason::NotAttempted => format!(
                        "not attempted after {MAX_CONSECUTIVE_UPSTREAM_FAILURES} failures in a row at its provider"
                    ),
                    LeftReason::Skipped => "skipped".into(),
                };
                let username = printable(&left.username);
                writeln!(
                    out,
                    "upstream grant left: {} {username} ({reason})",
                    left.family
                )
                .map_err(write)?;
            }
            if revoked.interrupted {
                return Err("the store failed during the revocation; run the command again".into());
            }
            if !revoked.upstream_left.is_empty() {
                return Ok(Finished::UpstreamLeft);
            }
        }
    }
    Ok(Finished::Done)
}

/// Text with control characters and invisible or reordering format characters escaped,
/// so a stored name can neither steer the terminal nor pass for another name.
/// Escaped: `\u{1b}`, `\u{202e}` (right-to-left override), `\u{200b}` (zero-width
/// space), `\u{2028}` (line separator). Kept: `é`, `ß`, `名`.
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() || hidden_format(c) {
                c.escape_default().to_string()
            } else {
                c.into()
            }
        })
        .collect()
}

/// The soft hyphen, the bidirectional controls and marks, the zero-width and invisible
/// format characters, the line and paragraph separators, the byte-order mark, and
/// characters that render as nothing: the combining grapheme joiner, the Hangul fillers,
/// variation selectors, tags and musical-symbol format characters.
fn hidden_format(c: char) -> bool {
    matches!(
        c,
        '\u{ad}'
            | '\u{34f}'
            | '\u{61c}'
            | '\u{115f}'..='\u{1160}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e007f}'
    )
}

/// `ms` as `2026-10-15T13:12:42Z`.
fn time(ms: u64) -> String {
    i64::try_from(ms)
        .ok()
        .and_then(DateTime::from_timestamp_millis)
        .map_or("unknown".into(), |at| {
            at.to_rfc3339_opts(SecondsFormat::Secs, true)
        })
}

/// One row per login, in columns as wide as their widest value; never a token, family
/// id or sealed grant.
fn table(out: &mut impl Write, logins: &[FamilySummary]) -> std::io::Result<()> {
    let header = [
        "CLIENT",
        "METHOD",
        "REALM",
        "USERNAME",
        "CREATED",
        "LAST_USED",
        "IDLE_EXPIRY",
        "ABSOLUTE_EXPIRY",
        "REFERENCE",
    ]
    .map(String::from);
    let rows: Vec<[String; 9]> = std::iter::once(header)
        .chain(logins.iter().map(|login| {
            [
                printable(&login.grant.client_id),
                printable(&login.grant.method),
                printable(&login.grant.realm),
                printable(&login.grant.username),
                time(login.created_at_ms),
                time(login.last_used_at_ms),
                time(login.idle_expires_at_ms),
                time(login.absolute_expires_at_ms),
                family_ref(&login.family_id),
            ]
        }))
        .collect();
    let widths: Vec<usize> = (0..9)
        .map(|column| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    for row in &rows {
        let cells: Vec<String> = row
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect();
        writeln!(out, "{}", cells.join("  ").trim_end())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(line: &str) -> Vec<String> {
        line.split_whitespace().map(String::from).collect()
    }
    fn filter(realm: &str, username: Option<&str>, client: Option<&str>) -> LoginFilter {
        LoginFilter {
            realm: realm.into(),
            username: username.map(Into::into),
            client: client.map(Into::into),
        }
    }

    #[test]
    fn arguments_select_logins_and_revoking_a_whole_realm_must_be_explicit() {
        let valid = [
            ("--help", Command::Help),
            (
                "logins list --realm idp",
                Command::List {
                    filter: filter("idp", None, None),
                    limit: DEFAULT_LIMIT,
                },
            ),
            (
                "logins list --realm=idp --client cli --limit 20",
                Command::List {
                    filter: filter("idp", None, Some("cli")),
                    limit: 20,
                },
            ),
            (
                "logins revoke --realm idp --username alice --dry-run",
                Command::Revoke {
                    filter: filter("idp", Some("alice"), None),
                    dry_run: true,
                },
            ),
            (
                "logins revoke --all-users --client cli --realm idp",
                Command::Revoke {
                    filter: filter("idp", None, Some("cli")),
                    dry_run: false,
                },
            ),
            (
                "logins revoke --realm idp --username=--odd",
                Command::Revoke {
                    filter: filter("idp", Some("--odd"), None),
                    dry_run: false,
                },
            ),
        ];
        for (line, expected) in valid {
            assert_eq!(parse(&args(line)), Ok(expected), "{line}");
        }
        for line in [
            "",
            "logins",
            "logins show --realm idp",
            "tokens list --realm idp",
            "logins list",
            "logins list --username alice",
            "logins revoke --realm idp",
            "logins revoke --realm idp --client cli",
            "logins revoke --realm idp --username alice --all-users",
            "logins list --realm --username alice",
            "logins list --realm",
            "logins list --realm=",
            "logins list --realm idp --realm other",
            "logins revoke --realm idp --all-users --all-users",
            "logins list --realm idp --limit 0",
            "logins list --realm idp --limit 10001",
            "logins list --realm idp --limit many",
            "logins list --realm idp --dry-run",
            "logins list --realm idp --all-users",
            "logins revoke --realm idp --all-users --limit 5",
            "logins revoke --realm idp --all-users --dry-run=yes",
            "logins list --realm idp extra",
            "logins list --realm idp -r idp",
            "--help logins",
        ] {
            assert!(parse(&args(line)).is_err(), "{line}");
        }
    }

    #[test]
    fn rows_escape_control_characters_and_show_only_references() {
        let login = FamilySummary {
            family_id: "family-id-never-shown".into(),
            grant: crate::oauth::refresh::RefreshGrant {
                client_id: "cli".into(),
                resource: "https://mcp.example.org/mcp".into(),
                scopes: vec!["read".into()],
                username: "ali\u{1b}[31mce".into(),
                realm: "idp".into(),
                provider_roles: vec![],
                method: "sso".into(),
                upstream_coupled: false,
            },
            created_at_ms: 1_760_000_000_000,
            last_used_at_ms: 1_760_000_060_000,
            idle_expires_at_ms: 1_760_000_660_000,
            absolute_expires_at_ms: 1_760_003_600_000,
        };
        let mut out = Vec::new();
        table(&mut out, &[login]).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert!(lines[0].starts_with("CLIENT  METHOD  REALM  USERNAME"));
        assert!(lines[1].starts_with("cli     sso     idp    ali\\u{1b}[31mce"));
        assert!(lines[1].contains("2025-10-09T08:53:20Z  2025-10-09T08:54:20Z"));
        assert!(lines[1].ends_with(&family_ref("family-id-never-shown")));
        assert!(!text.contains("family-id-never-shown"));
        assert!(!text.contains('\u{1b}'));
        let shown = printable("\u{202e}eci\u{200b}la\u{2066}\u{2028}\u{feff}\u{ad}Zoë 名");
        assert_eq!(
            shown,
            "\\u{202e}eci\\u{200b}la\\u{2066}\\u{2028}\\u{feff}\\u{ad}Zoë 名"
        );
        for invisible in [
            '\u{34f}',
            '\u{115f}',
            '\u{1160}',
            '\u{3164}',
            '\u{ffa0}',
            '\u{fe00}',
            '\u{fe0f}',
            '\u{e0000}',
            '\u{e0041}',
            '\u{e007f}',
            '\u{1d173}',
            '\u{1d17a}',
        ] {
            let shown = printable(&format!("a{invisible}b"));
            assert_eq!(shown, format!("a{}b", invisible.escape_default()));
        }
        // Their neighbours stay as they are.
        for visible in ['\u{1161}', '\u{3165}', '\u{ffa1}', '\u{fe10}', '\u{1d17b}'] {
            assert_eq!(printable(&visible.to_string()), visible.to_string());
        }
    }

    #[tokio::test]
    async fn the_memory_backend_and_a_server_without_oauth_have_no_logins_to_reach() {
        let config = |oauth: bool| -> ConfigV2 {
            serde_json::from_value(serde_json::json!({
                "store": {"enabled": false}, "services": [], "augmenters": [],
                "providers": [{"type": "plain", "name": "basic", "realm": "local", "users": [], "browser": {"id": "password", "label": "Password"}}],
                "server": {"port": 0}, "jwt": {"iss": "fixture", "exp": 300, "secret": "fixture-only"},
                "logging": {"level": "warn", "format": "console"},
                "ui": {"enabled": true, "browser_session": {"public_origin": "https://login.example.org", "backend": {"type": "memory"}}},
                "oauth": {"enabled": oauth}
            }))
            .unwrap()
        };
        let list = parse(&args("logins list --realm local")).unwrap();
        let mut out = Vec::new();
        let error = run(&config(false), &list, &mut out).await.unwrap_err();
        assert!(error.contains("OAuth is not enabled"), "{error}");
        let error = run(&config(true), &list, &mut out).await.unwrap_err();
        assert!(error.contains("inside each server process"), "{error}");
        // An invalid OAuth configuration is reported before any store is reached.
        let mut invalid = config(true);
        invalid.ui.browser_session.as_mut().unwrap().backend =
            serde_json::from_value(serde_json::json!({"type": "valkey",
                "url": "redis://127.0.0.1:9/0", "key_prefix": "authotron", "password": "unused"}))
            .unwrap();
        let error = run(&invalid, &list, &mut out).await.unwrap_err();
        assert!(
            error.starts_with("cannot start the OAuth runtime: "),
            "{error}"
        );
        assert!(out.is_empty());
        run(&config(false), &Command::Help, &mut out).await.unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .starts_with("usage: authotron admin logins list")
        );
    }
}
