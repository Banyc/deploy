//! Jinja-style (`{{ name }}`) templating for the elected deployment
//! variables.
//!
//! # Elected variables
//!
//! The renderer understands exactly this fixed set of variables:
//!
//! | variable        | meaning                                                              |
//! |-----------------|----------------------------------------------------------------------|
//! | `deploy_dir`    | absolute on-server deployment directory of the slot                  |
//! | `variant`       | the release variant being materialized / activated                   |
//! | `application`   | `application` from `deploy.toml`                                     |
//! | `release`       | the active release name (`release:` in `deploy.toml`)                |
//! | `target`        | the target being pushed                                              |
//! | `server`        | the server ID of the slot (`[[servers]].id`)                         |
//! | `user`          | the server's deployment account (`[[servers]].user`)                 |
//! | `address`       | the server's address (`[[servers]].address`)                         |
//! | `port`          | the server's SSH port (`[[servers]].port`)                           |
//! | `slot`          | the placement-slot ID of the slot (`[[slots]].id`)                   |
//! | `deployment_id` | the deployment ID being activated (per-server activation/verification only) |
//! | `generation`    | the generation being activated (per-server activation/verification only)    |
//! | `tree`          | the tree digest being activated (per-server activation/verification only)   |
//!
//! # Availability matrix
//!
//! Sites that cannot fill a variable leave it unset, and referencing it at
//! that site fails loudly (see below).
//!
//! | context                                             | available variables                                        |
//! |-----------------------------------------------------|------------------------------------------------------------|
//! | `TemplateVars::mapping` (materialization)           | `variant`, `application`, `release`                        |
//! | `TemplateVars::slot` (base activation/verification) | `deploy_dir`, `variant`, `application`, `release`, `target`, `server` |
//! | slot + [`TemplateVars::with_server`]                | ... + `user`, `address`, `port`                            |
//! | slot + [`TemplateVars::with_slot_id`]               | ... + `slot`                                               |
//! | slot + [`TemplateVars::with_deployment`]            | ... + `deployment_id`, `generation`, `tree`                |
//!
//! Materialization is the constrained case: trees are content-addressed and
//! shared across slots, so mapping paths may only use per-variant values
//! (`variant`, `application`, `release`) — never per-slot or per-server
//! values such as `deploy_dir`, `user`, or `address` (two slots with
//! different `deploy_dir`s must still produce the same tree digest).
//!
//! The three deployment-scoped variables (`deployment_id`, `generation`,
//! `tree`) are only filled by the engine's per-server activation/verification
//! path (and compensation); sites that do not know them (e.g. the
//! reconciliation loop) leave them unset, so a unit/argv referencing them
//! there fails loudly rather than rendering a stale value.
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
pub const ELECTED_VARIABLES: [&str; 13] = [
    "deploy_dir",
    "variant",
    "application",
    "release",
    "target",
    "server",
    "user",
    "address",
    "port",
    "slot",
    "deployment_id",
    "generation",
    "tree",
];

/// The context for one [`render`] call.
///
/// Every field is `Option` because a render site can only fill the variables
/// it actually knows: materialization ([`TemplateVars::mapping`]) knows only
/// `variant`/`application`/`release`, while activation/verification
/// ([`TemplateVars::slot`] plus the `with_*` builders) knows the full slot
/// context. A template that references a `None` field fails loudly instead of
/// silently rendering an empty string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateVars {
    deploy_dir: Option<String>,
    variant: Option<String>,
    application: Option<String>,
    release: Option<String>,
    target: Option<String>,
    server: Option<String>,
    user: Option<String>,
    address: Option<String>,
    port: Option<String>,
    slot: Option<String>,
    deployment_id: Option<String>,
    generation: Option<String>,
    tree: Option<String>,
}

impl TemplateVars {
    /// Context for mapping materialization: per-variant values only
    /// (`variant`, `application`, `release`). Trees are content-addressed and
    /// shared across slots, so slot/server/deployment variables
    /// (`deploy_dir`, `server`, `target`, `user`, `address`, `port`, `slot`,
    /// `deployment_id`, `generation`, `tree`) must never be rendered into a
    /// tree; a mapping that references them fails loudly.
    pub fn mapping(application: &str, release: &str, variant: &str) -> TemplateVars {
        TemplateVars {
            deploy_dir: None,
            variant: Some(variant.to_string()),
            application: Some(application.to_string()),
            release: Some(release.to_string()),
            target: None,
            server: None,
            user: None,
            address: None,
            port: None,
            slot: None,
            deployment_id: None,
            generation: None,
            tree: None,
        }
    }

    /// Base slot context available at activation/verification time: the
    /// per-slot deployment location plus the configuration-level values. The
    /// server-level (`user`/`address`/`port`), slot ID, and
    /// deployment-scoped variables start unset — fill them with
    /// [`TemplateVars::with_server`], [`TemplateVars::with_slot_id`], and
    /// [`TemplateVars::with_deployment`] at sites that have them.
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
            user: None,
            address: None,
            port: None,
            slot: None,
            deployment_id: None,
            generation: None,
            tree: None,
        }
    }

    /// Add the server's connection metadata: the deployment account
    /// (`user`, from `[[servers]].user`), the address, and the SSH `port`.
    /// Together with `server` (the ID) these describe the physical host the
    /// slot deploys onto.
    pub fn with_server(mut self, user: &str, address: &str, port: u16) -> TemplateVars {
        self.user = Some(user.to_string());
        self.address = Some(address.to_string());
        self.port = Some(port.to_string());
        self
    }

    /// Add the placement-slot ID (`[[slots]].id`), distinct from `server`
    /// (the physical server the slot deploys onto).
    pub fn with_slot_id(mut self, slot: &str) -> TemplateVars {
        self.slot = Some(slot.to_string());
        self
    }

    /// Add the per-deployment identity, available only in the per-server
    /// activation/verification path: the deployment ID being pushed, the
    /// generation being activated, and the activated tree digest. Pass
    /// `None` at sites that do not know them (e.g. the reconciliation loop);
    /// a template referencing an unfilled deployment variable fails loudly.
    pub fn with_deployment(
        mut self,
        deployment_id: Option<&crate::model::DeploymentId>,
        generation: Option<&crate::model::GenerationId>,
        tree: Option<&crate::model::TreeDigest>,
    ) -> TemplateVars {
        self.deployment_id = deployment_id.map(|d| d.as_str().to_string());
        self.generation = generation.map(|g| g.as_str().to_string());
        self.tree = tree.map(|t| t.as_str().to_string());
        self
    }

    /// Same context with a different `variant`. Compensation re-runs the
    /// PRIOR generation's contract, whose variant can differ from the desired
    /// one; everything else (deploy_dir, application, server metadata,
    /// deployment identity, ...) is unchanged.
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
            "user" => self.user.as_deref(),
            "address" => self.address.as_deref(),
            "port" => self.port.as_deref(),
            "slot" => self.slot.as_deref(),
            "deployment_id" => self.deployment_id.as_deref(),
            "generation" => self.generation.as_deref(),
            "tree" => self.tree.as_deref(),
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
    use crate::model::{DeploymentId, GenerationId, TreeDigest};

    fn slot_vars() -> TemplateVars {
        TemplateVars::slot(
            Path::new("/srv/deploy/example"),
            "standard",
            "example",
            "v1",
            "production",
            "server-01",
        )
        .with_server("deploy", "10.0.0.5", 22)
        .with_slot_id("app-1")
        .with_deployment(
            Some(&DeploymentId::new("deploy-1")),
            Some(&GenerationId::new("gen-1")),
            Some(&TreeDigest::new("abc123")),
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
                &TemplateVars::mapping("example", "v1", "standard"),
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
            "{{ deploy_dir }}|{{ variant }}|{{ application }}|{{ release }}|{{ target }}|{{ server }}|{{ user }}|{{ address }}|{{ port }}|{{ slot }}|{{ deployment_id }}|{{ generation }}|{{ tree }}",
            &v,
        )
        .unwrap();
        assert_eq!(
            all,
            "/srv/deploy/example|standard|example|v1|production|server-01|deploy|10.0.0.5|22|app-1|deploy-1|gen-1|abc123"
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
        // A mapping context knows only variant/application/release:
        // referencing deploy_dir there must fail loudly rather than render an
        // empty path component.
        let m = TemplateVars::mapping("example", "v1", "standard");
        let err = render_template("artifacts/{{ deploy_dir }}", &m).unwrap_err();
        assert!(
            err.to_string()
                .contains("variable 'deploy_dir' is not available in this context")
        );
    }

    #[test]
    fn mapping_context_rejects_server_and_deployment_variables() {
        // Trees are content-addressed and shared across slots: slot-level,
        // server-level, and deployment-scoped variables must never render
        // into a tree. Every one of them fails loudly in the mapping context.
        let m = TemplateVars::mapping("example", "v1", "standard");
        for name in [
            "deploy_dir",
            "target",
            "server",
            "user",
            "address",
            "port",
            "slot",
            "deployment_id",
            "generation",
            "tree",
        ] {
            let t = format!("artifacts/{{{{ {name} }}}}");
            let err = render_template(&t, &m).unwrap_err();
            assert!(
                err.to_string().contains(&format!(
                    "variable '{name}' is not available in this context"
                )),
                "mapping context must reject '{name}' (got: {err})"
            );
        }
        // The mapping context DOES provide variant/application/release.
        assert_eq!(
            render_template("{{ variant }}/{{ application }}/{{ release }}", &m).unwrap(),
            "standard/example/v1"
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
        let v = TemplateVars::slot(Path::new("/srv/a"), "standard", "app", "v2", "prod", "s1")
            .with_server("deploy", "10.0.0.5", 22)
            .with_slot_id("app-1")
            .with_deployment(
                Some(&DeploymentId::new("d1")),
                Some(&GenerationId::new("g1")),
                Some(&TreeDigest::new("t1")),
            );
        let prior = v.with_variant("old");
        assert_eq!(
            render_template(
                "{{ variant }}|{{ deploy_dir }}|{{ release }}|{{ user }}|{{ slot }}|{{ generation }}",
                &prior
            )
            .unwrap(),
            "old|/srv/a|v2|deploy|app-1|g1"
        );
    }
}
