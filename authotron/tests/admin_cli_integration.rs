// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! `authotron admin` as an operator runs it, without a configuration file.

use std::process::{Command, Output};

fn admin(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_authotron"))
        .arg("admin")
        .args(args)
        .env("AOT_CONFIG_PATH", "/nonexistent/authotron/config.yaml")
        .output()
        .expect("the authotron binary runs")
}

#[test]
fn help_and_invalid_arguments_are_answered_without_a_configuration() {
    for flag in ["--help", "-h", "help"] {
        let output = admin(&[flag]);
        assert_eq!(output.status.code(), Some(0), "{flag}");
        let usage = String::from_utf8(output.stdout).unwrap();
        assert!(
            usage.starts_with("usage: authotron admin logins list"),
            "{usage}"
        );
        assert!(output.stderr.is_empty(), "{flag}");
    }
    let output = admin(&["logins", "list"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(
        error.starts_with("authotron admin: --realm is required\nusage:"),
        "{error}"
    );
}
