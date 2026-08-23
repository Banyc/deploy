//! Jinja-style (`{{ name }}`) templating for the elected deployment
//! variables.
//!
//! # Elected variables
//!
//! The renderer understands exactly this fixed set of variables:
//!
//! | variable      | meaning                                                       | render sites |
//! |---------------|---------------------------------------------------------------|--------------|
//! | `deploy_dir`  | absolute on-server deployment directory of the slot           | activation, verification |
//! | `variant`     | the release variant being materialized / activated            | mapping, activation, verification |
//! | `application` | `application` from `deploy.toml`                              | activation, verification |
//! | `release`     | the active release name (`release:` in `deploy.toml`)         | activation, verification |
//! | `target`      | the target being pushed                                       | activation, verification |
//! | `server`      | the server ID of the slot                                     | activation, verification |
//!
//! Sites that cannot fill a variable leave it unset, and referencing it at
//! that site fails loudly (see below). Materialization is the constrained
//! case: trees are content-addressed and shared across slots, so mapping
//! paths may only use `variant` — never per-slot values such as `deploy_dir`
//! (two slots with different `deploy_dir`s must still produce the same tree
//! digest).
//!
//! # Security posture
//!
//! Only `{{ name }}` for exactly the elected names above is recognized — no
//! expressions, no filters, no control flow, no function calls. Unknown
//! variables, malformed templates (unterminated `{{`, empty `{{ }}`), and
//! names that are not available at the render site all fail loudly with
//! `Error::Template`. Literal text without `{{ ... }}` passes through
//! unchanged, and rendered output is substituted only into mapping paths,
//! unit-file content, and per-element argv BEFORE the command vector is
//! handed to the transport — command boundaries are preserved (exec never
//! runs a shell).
//!
//! Render sites:
//! * [`crate::mapper::materialize_variant`] renders each mapping `from` path
//!   (the `to` path is not templated) with `TemplateVars::mapping`.
//! * [`crate::adapter::systemd::run_activation`] renders each unit artifact's
//!   content with the slot context before installing it.
//! * [`crate::adapter::verify::run_verification`] renders every argv element
//!   with the slot context before exec.

use crate::error::{Error, Result};
use std::path::Path;

/// The full elected variable set, in documentation order.
pub const ELECTED_VARIABLES: [&str; 6] = [
    "deploy_dir",
    "variant",
    "application",
    "release",
    "target",
    "server",
];

/// The context for one [`render`] call.
///
/// Every field is `Option` because a render site can only fill the variables
/// it actually knows: materialization (`TemplateVars::mapping`) knows only the
/// variant, while activation/verification (`TemplateVars::slot`) knows the
/// full slot context. A template that references a `None` field fails loudly
/// instead of silently rendering an empty string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateVars {
    deploy_dir: Option<String>,
    variant: Option<String>,
    application: Option<String>,
    release: Option<String>,
    target: Option<String>,
    server: Option<String>,
}

impl TemplateVars {
    /// Context for mapping materialization: only per-variant values are
    /// available. Trees are content-addressed and shared across slots, so
    /// slot-level variables (`deploy_dir`, `server`, `target`) must never be
    /// rendered into a tree; a mapping that references them fails loudly.
    pub fn mapping(variant: &str) -> TemplateVars {
        TemplateVars {
            deploy_dir: None,
            variant: Some(variant.to_string()),
            application: None,
            release: None,
            target: None,
            server: None,
        }
    }

    /// Full slot context available at activation/verification time.
    pub fn slot(
        deploy_dir: &Path,
        variant: &str,
        application: &str,
        release: &str,
        target: &str,
        server: &str,
    ) -> TemplateVars {
        TemplateVars {
            deploy_dir: Some(deploy_dir.to_string_lossy().into_owned()),
            variant: Some(variant.to_string()),
            application: Some(application.to_string()),
            release: Some(release.to_string()),
            target: Some(target.to_string()),
            server: Some(server.to_string()),
        }
    }

    /// Same context with a different `variant`. Compensation re-runs the
    /// PRIOR generation's contract, whose variant can differ from the desired
    /// one; everything else (deploy_dir, application, ...) is unchanged.
    pub fn with_variant(&self, variant: &str) -> TemplateVars {
        let mut out = self.clone();
        out.variant = Some(variant.to_string());
        out
    }

    /// Resolve one variable name. `None` = the name is not elected at all;
    /// `Some(None)` = elected but not available in this context.
    fn lookup(&self, name: &str) -> Option<Option<&str>> {
        let value = match name {
            "deploy_dir" => self.deploy_dir.as_deref(),
            "variant" => self.variant.as_deref(),
            "application" => self.application.as_deref(),
            "release" => self.release.as_deref(),
            "target" => self.target.as_deref(),
            "server" => self.server.as_deref(),
            _ => return None,
        };
        Some(value)
    }
}

/// Render `template`, substituting every `{{ name }}` for an elected variable
/// in `vars`.
///
/// * unknown variable names → `Err` (no silent passthrough);
/// * an elected variable that this context does not provide → `Err`;
/// * unterminated `{{` or an empty `{{ }}` → `Err`;
/// * literal text without templates → returned unchanged.
pub fn render_template(template: &str, vars: &TemplateVars) -> Result<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(close) = after.find("}}") else {
            return Err(Error::template(format!(
                "malformed template: unterminated '{{{{' in {template:?}"
            )));
        };
        let name = after[..close].trim();
        if name.is_empty() {
            return Err(Error::template(format!(
                "malformed template: empty '{{{{ }}}}' variable in {template:?}"
            )));
        }
        match vars.lookup(name) {
            None => {
                return Err(Error::template(format!(
                    "unknown template variable '{name}' in {template:?} \
                     (supported variables: {})",
                    ELECTED_VARIABLES.join(", ")
                )));
            }
            Some(None) => {
                return Err(Error::template(format!(
                    "template variable '{name}' is not available in this \
                     context (render site) while rendering {template:?}"
                )));
            }
            Some(Some(value)) => out.push_str(value),
        }
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Render every element of a command vector (e.g. verification `argv`).
/// Elements without templates are unchanged; malformed or unknown variables
/// fail loudly before the command is executed.
pub fn render_argv(argv: &[String], vars: &TemplateVars) -> Result<Vec<String>> {
    argv.iter().map(|a| render_template(a, vars)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot_vars() -> TemplateVars {
        TemplateVars::slot(
            Path::new("/srv/deploy/example"),
            "standard",
            "example",
            "v1",
            "production",
            "server-01",
        )
    }

    #[test]
    fn known_variables_render() {
        let v = slot_vars();
        assert_eq!(
            render_template("{{ deploy_dir }}/current/app/server", &v,).unwrap(),
            "/srv/deploy/example/current/app/server"
        );
        assert_eq!(
            render_template(
                "deployment/variants/{{ variant }}/",
                &TemplateVars::mapping("standard"),
            )
            .unwrap(),
            "deployment/variants/standard/"
        );
        // No whitespace inside the braces is required.
        assert_eq!(
            render_template("{{variant}} {{ deploy_dir }}", &v).unwrap(),
            "standard /srv/deploy/example"
        );
        // Every elected variable renders from the slot context.
        let all = render_template(
            "{{ deploy_dir }}|{{ variant }}|{{ application }}|{{ release }}|{{ target }}|{{ server }}",
            &v,
        )
        .unwrap();
        assert_eq!(
            all,
            "/srv/deploy/example|standard|example|v1|production|server-01"
        );
    }

    #[test]
    fn unknown_variable_fails() {
        let v = slot_vars();
        let err = render_template("a {{ nope }} b", &v).unwrap_err();
        assert!(err.to_string().contains("unknown template variable 'nope'"));
        // Expressions/filters/control flow are not variable names.
        for bad in ["{{ variant|upper }}", "{{ 1 + 1 }}", "{{ 'x' }}"] {
            assert!(
                render_template(bad, &v).is_err(),
                "expression {bad} must be rejected"
            );
        }
    }

    #[test]
    fn unavailable_variable_fails_at_its_render_site() {
        // A mapping context knows only `variant`: referencing deploy_dir there
        // must fail loudly rather than render an empty path component.
        let m = TemplateVars::mapping("standard");
        let err = render_template("artifacts/{{ deploy_dir }}", &m).unwrap_err();
        assert!(
            err.to_string()
                .contains("variable 'deploy_dir' is not available in this context")
        );
    }

    #[test]
    fn malformed_template_fails() {
        let v = slot_vars();
        assert!(render_template("{{ variant", &v).is_err(), "unterminated");
        assert!(render_template("{{ }}", &v).is_err(), "empty variable");
        assert!(render_template("a {{ }} b", &v).is_err(), "empty in text");
        assert!(
            render_template("{{{ variant }}}", &v).is_err(),
            "triple brace"
        );
    }

    #[test]
    fn literal_text_passes_through() {
        let v = slot_vars();
        assert_eq!(
            render_template("no templates here", &v).unwrap(),
            "no templates here"
        );
        assert_eq!(render_template("", &v).unwrap(), "");
        // Stray braces that never open a template are literal text.
        assert_eq!(
            render_template("printf \"%s\" \"$x\"", &v).unwrap(),
            "printf \"%s\" \"$x\""
        );
    }

    #[test]
    fn argv_renders_elementwise() {
        let v = slot_vars();
        let argv = render_argv(
            &[
                "{{ deploy_dir }}/bin/probe".to_string(),
                "{{ variant }}".to_string(),
                "--flag".to_string(),
            ],
            &v,
        )
        .unwrap();
        assert_eq!(
            argv,
            vec![
                "/srv/deploy/example/bin/probe".to_string(),
                "standard".to_string(),
                "--flag".to_string(),
            ]
        );
        // An unknown element fails the whole vector (fail closed).
        assert!(render_argv(&["{{ bogus }}".to_string()], &v).is_err());
    }

    #[test]
    fn with_variant_replaces_only_the_variant() {
        let v = TemplateVars::slot(Path::new("/srv/a"), "standard", "app", "v2", "prod", "s1");
        let prior = v.with_variant("old");
        assert_eq!(
            render_template("{{ variant }}|{{ deploy_dir }}|{{ release }}", &prior).unwrap(),
            "old|/srv/a|v2"
        );
    }
}
