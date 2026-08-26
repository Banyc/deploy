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
//! | `release`       | the immutable `ReleaseId` of the deployed artifact (`rel-sha256-…`)  |
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
//! | slot + [`TemplateVars::with_artifact`]              | replaces `release`, `variant`, `tree` from one `ArtifactRef` |
//! | slot + [`TemplateVars::with_assignment`]            | replaces `release`, `variant`, `tree`, `deployment_id`, `generation` from one `GenerationAssignment` |
//!
//! Materialization is the constrained case: trees are content-addressed and
//! shared across slots, so mapping paths may only use per-variant values
//! (`variant`, `application`, `release`) — never per-slot or per-server
//! values such as `deploy_dir`, `user`, or `address` (two slots with
//! different `deploy_dir`s must still produce the same tree digest). The
//! mapping `release` is the release NAME from `deploy.toml`, not the
//! `ReleaseId`: the immutable `ReleaseId` is derived from the materialized
//! trees, so it cannot be known — and must not be rendered — into a tree
//! without creating a circular digest. Activation/verification, where the
//! deployed [`ArtifactRef`](crate::model::ArtifactRef) is known, always
//! render the artifact's own `ReleaseId`.
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
    /// (`variant`, `application`, `release`). `release` is the release NAME
    /// from `deploy.toml` — the immutable `ReleaseId` is derived from the
    /// materialized trees, so at materialization time it is not yet knowable
    /// (rendering it into a tree would be a circular dependency). Trees are
    /// content-addressed and shared across slots, so slot/server/deployment
    /// variables (`deploy_dir`, `server`, `target`, `user`, `address`,
    /// `port`, `slot`, `deployment_id`, `generation`, `tree`) must never be
    /// rendered into a tree; a mapping that references them fails loudly.
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
    /// per-slot deployment location plus the artifact's identity — `variant`
    /// and the immutable `release` `ReleaseId` of the artifact actually being
    /// deployed (never the caller's current release name). The server-level
    /// (`user`/`address`/`port`), slot ID, and deployment-scoped variables
    /// start unset — fill them with [`TemplateVars::with_server`],
    /// [`TemplateVars::with_slot_id`], and
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

    /// Same context with the artifact-scoped variables replaced from ONE
    /// [`crate::model::ArtifactRef`]: `variant`, the immutable `release`
    /// `ReleaseId`, and `tree` are all taken from the same artifact.
    /// Compensation re-runs the PRIOR generation's contract, whose
    /// release/variant/tree can all differ from the desired artifact; setting
    /// the triple together never leaves a torn combination (e.g. a prior
    /// variant rendered with the desired release). Everything else
    /// (deploy_dir, application, server metadata, deployment identity, ...)
    /// is unchanged.
    pub fn with_artifact(&self, artifact: &crate::model::ArtifactRef) -> TemplateVars {
        let mut out = self.clone();
        out.variant = Some(artifact.variant.as_str().to_string());
        out.release = Some(artifact.release.as_str().to_string());
        out.tree = Some(artifact.tree.as_str().to_string());
        out
    }

    /// Same context with the FIVE deployment-scoped variables replaced from
    /// ONE [`crate::remote::helper::GenerationAssignment`]: `variant`,
    /// `release`, and `tree` from the assignment's artifact, plus
    /// `deployment_id` and `generation` from the assignment's own identity
    /// fields. The deployment identity must move WITH the artifact: a
    /// compensation-rendered unit/argv describes the PRIOR generation, so it
    /// must carry the prior deployment's `deployment_id`/`generation`, never
    /// the failed (new) generation's. This supersedes
    /// [`TemplateVars::with_artifact`] for compensation, which replaces only
    /// the artifact triple and would leave the deployment identity pointing at
    /// the failed generation. Everything else (deploy_dir, application, server
    /// metadata, ...) is unchanged.
    pub fn with_assignment(
        &self,
        assignment: &crate::remote::helper::GenerationAssignment,
    ) -> TemplateVars {
        let mut out = self.clone();
        out.variant = Some(assignment.artifact.variant.as_str().to_string());
        out.release = Some(assignment.artifact.release.as_str().to_string());
        out.tree = Some(assignment.artifact.tree.as_str().to_string());
        out.deployment_id = Some(assignment.deployment_id.as_str().to_string());
        out.generation = Some(assignment.generation_id.as_str().to_string());
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
    use crate::model::{
        ArtifactRef, DeploymentId, GenerationId, ReleaseId, TreeDigest, VariantName,
        test_deployment_id, test_generation_id, test_tree_digest,
    };

    fn slot_vars() -> TemplateVars {
        TemplateVars::slot(
            Path::new("/srv/deploy/example"),
            "standard",
            "example",
            "rel-sha256-7b278acf5041d50a9704392ac9fac4c6c02ca2cf3be9e5aee61668c8070526d2",
            "production",
            "server-01",
        )
        .with_server("deploy", "10.0.0.5", 22)
        .with_slot_id("app-1")
        .with_deployment(
            Some(&test_deployment_id("deploy-1")),
            Some(&test_generation_id("gen-1")),
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
            format!(
                "/srv/deploy/example|standard|example|rel-sha256-7b278acf5041d50a9704392ac9fac4c6c02ca2cf3be9e5aee61668c8070526d2|production|server-01|deploy|10.0.0.5|22|app-1|{}|{}|abc123",
                test_deployment_id("deploy-1"),
                test_generation_id("gen-1"),
            )
        );
        // `release` renders the immutable ReleaseId of the deployed artifact,
        // not the human release name from deploy.toml.
        assert_ne!(
            render_template("{{ release }}", &v).unwrap(),
            "v1",
            "the ReleaseId must not be confused with the short label"
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

    /// Template output is LITERAL text: a `deploy_dir` (or any variable)
    /// containing spaces, `$`, backticks, or braces is passed through verbatim
    /// in argv elements — never shell-escaped, quoted, or split — because the
    /// adapter receives argv element-wise with no shell in between.
    #[test]
    fn special_chars_in_deploy_dir_render_literal() {
        let v = TemplateVars::slot(
            Path::new("/srv/Deploy Dir$/app"),
            "standard",
            "app",
            "rel-sha256-111",
            "prod",
            "s1",
        )
        .with_server("deploy", "10.0.0.5", 22)
        .with_slot_id("app-1")
        .with_deployment(
            Some(&DeploymentId::new("d1")),
            Some(&GenerationId::new("g1")),
            Some(&test_tree_digest("t1")),
        );
        let argv = render_argv(
            &[
                "{{ deploy_dir }}/bin/probe".to_string(),
                "--root={{ deploy_dir }}".to_string(),
                "{{ variant }}".to_string(),
            ],
            &v,
        )
        .unwrap();
        assert_eq!(
            argv,
            vec![
                "/srv/Deploy Dir$/app/bin/probe".to_string(),
                "--root=/srv/Deploy Dir$/app".to_string(),
                "standard".to_string(),
            ],
            "spaces and $ must pass through as literal text (no escaping, no quoting)"
        );
        // A deploy_dir containing a backtick or brace is equally literal in
        // plain template text.
        let v2 = TemplateVars::slot(
            Path::new("/srv/`tick`/{braced}"),
            "standard",
            "app",
            "rel-sha256-111",
            "prod",
            "s1",
        );
        assert_eq!(
            render_template("{{ deploy_dir }}/current", &v2).unwrap(),
            "/srv/`tick`/{braced}/current"
        );
    }

    #[test]
    fn with_artifact_replaces_artifact_vars_together() {
        let v = TemplateVars::slot(
            Path::new("/srv/a"),
            "standard",
            "app",
            "rel-sha256-111",
            "prod",
            "s1",
        )
        .with_server("deploy", "10.0.0.5", 22)
        .with_slot_id("app-1")
        .with_deployment(
            Some(&DeploymentId::new("d1")),
            Some(&GenerationId::new("g1")),
            Some(&test_tree_digest("t1")),
        );
        // The prior artifact differs in every artifact-scoped variable: a
        // historical release, a different variant, a different tree.
        let prior = v.with_artifact(&ArtifactRef {
            release: ReleaseId::new("rel-sha256-999"),
            variant: VariantName::new("legacy"),
            tree: test_tree_digest("t9"),
        });
        // release + variant + tree move TOGETHER to the prior artifact: never
        // a torn combination (prior variant with the desired release/tree).
        assert_eq!(
            render_template(
                "{{ variant }}|{{ deploy_dir }}|{{ release }}|{{ user }}|{{ slot }}|{{ generation }}|{{ tree }}",
                &prior
            )
            .unwrap(),
            format!(
                "legacy|/srv/a|rel-sha256-999|deploy|app-1|g1|{}",
                test_tree_digest("t9")
            )
        );
        // The source context is unchanged (with_artifact clones).
        assert_eq!(
            render_template("{{ release }}", &v).unwrap(),
            "rel-sha256-111"
        );
        assert_eq!(render_template("{{ variant }}", &v).unwrap(), "standard");
    }

    #[test]
    fn with_assignment_replaces_all_five_from_one_assignment() {
        let v = TemplateVars::slot(
            Path::new("/srv/a"),
            "standard",
            "app",
            "rel-sha256-111",
            "prod",
            "s1",
        )
        .with_server("deploy", "10.0.0.5", 22)
        .with_slot_id("app-1")
        .with_deployment(
            Some(&DeploymentId::new("d-failed")),
            Some(&GenerationId::new("g-failed")),
            Some(&test_tree_digest("t-failed")),
        );
        // The prior assignment differs in every one of the five values: a
        // historical release, a different variant/tree, and the PRIOR
        // deployment identity (not the failed generation's).
        let prior = v.with_assignment(&crate::remote::helper::GenerationAssignment {
            deployment_id: DeploymentId::new("d-prior"),
            generation_id: GenerationId::new("g-prior"),
            artifact: ArtifactRef {
                release: ReleaseId::new("rel-sha256-999"),
                variant: VariantName::new("legacy"),
                tree: test_tree_digest("t9"),
            },
            behavior_sha256: "b".to_string(),
            prior_generation: None,
            created_at: "2020-01-01T00:00:00Z".to_string(),
            target: Some(crate::model::TargetName::new("prod")),
        });
        // All five move TOGETHER from the one assignment: never a torn
        // combination (prior artifact with the failed deployment identity).
        assert_eq!(
            render_template(
                "{{ variant }}|{{ release }}|{{ tree }}|{{ deployment_id }}|{{ generation }}",
                &prior
            )
            .unwrap(),
            format!(
                "legacy|rel-sha256-999|{}|d-prior|g-prior",
                test_tree_digest("t9")
            )
        );
        // The failed generation's identities are gone from the prior context.
        assert!(
            !render_template("{{ deployment_id }}", &prior)
                .unwrap()
                .contains("d-failed")
        );
        assert!(
            !render_template("{{ generation }}", &prior)
                .unwrap()
                .contains("g-failed")
        );
        // The source context is unchanged (with_assignment clones).
        assert_eq!(
            render_template("{{ deployment_id }}", &v).unwrap(),
            "d-failed"
        );
        assert_eq!(
            render_template("{{ release }}", &v).unwrap(),
            "rel-sha256-111"
        );
    }

    #[test]
    fn historical_artifact_renders_its_own_release_id() {
        // A historical/rollback push deploys an artifact whose release is the
        // stored, immutable ReleaseId — the template must render that id, not
        // the caller's current release name (e.g. "v1").
        let artifact = ArtifactRef {
            release: ReleaseId::new(
                "rel-sha256-9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            ),
            variant: VariantName::new("standard"),
            tree: TreeDigest::new("abc123"),
        };
        let v = TemplateVars::slot(
            Path::new("/srv/deploy/example"),
            artifact.variant.as_str(),
            "example",
            artifact.release.as_str(),
            "production",
            "server-01",
        )
        .with_deployment(
            Some(&test_deployment_id("deploy-1")),
            Some(&test_generation_id("gen-1")),
            Some(&artifact.tree),
        );
        assert_eq!(
            render_template("{{ release }}", &v).unwrap(),
            artifact.release.as_str()
        );
        assert_eq!(
            render_template("{{ variant }}", &v).unwrap(),
            artifact.variant.as_str()
        );
        assert_eq!(render_template("{{ tree }}", &v).unwrap(), "abc123");
        // The ReleaseId is the immutable id, never the short label.
        assert_ne!(render_template("{{ release }}", &v).unwrap(), "v1");
    }
}
