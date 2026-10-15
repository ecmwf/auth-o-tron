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

use crate::oauth::admin::LoginFilter;
use std::collections::BTreeSet;

pub const USAGE: &str = "\
usage: authotron admin logins list   --realm <realm> [--username <name>] [--client <id>] [--limit <n>]
       authotron admin logins revoke --realm <realm> (--username <name> | --all-users)
                                     [--client <id>] [--dry-run]";

/// Logins `list` shows unless `--limit` says otherwise, and the most it accepts.
const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 10_000;

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
}
