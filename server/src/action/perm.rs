//! Action permission middleware for ABAC

use axum::{
    extract::{Path, Request, State},
    middleware::Next,
    response::Response,
};
use std::future::Future;
use std::pin::Pin;

use crate::{
    core::{
        abac::Environment,
        extract::Auth,
    },
    prelude::*,
    types::ActionAttrs,
};

/// Middleware factory for action permission checks
pub fn check_perm_action(action: &'static str) -> impl Fn(State<App>, Auth, Path<String>, Request, Next) -> Pin<Box<dyn Future<Output = Result<Response, Error>> + Send>> + Clone {
    move |state, auth, path, req, next| {
        Box::pin(check_action_permission(state, auth, path, req, next, action))
    }
}

async fn check_action_permission(
    State(app): State<App>,
    Auth(auth_ctx): Auth,
    Path(action_id): Path<String>,
    req: Request,
    next: Next,
    action: &str,
) -> Result<Response, Error> {
    use tracing::warn;

    // Load action attributes (STUB - Phase 3 will implement)
    let attrs = load_action_attrs(&app, auth_ctx.tn_id, &action_id, &auth_ctx.id_tag).await?;

    // Check permission
    let environment = Environment::new();
    let checker = app.permission_checker.read().await;

    if !checker.has_permission(&auth_ctx, action, &attrs, &environment) {
        warn!(
            subject = %auth_ctx.id_tag,
            action = action,
            action_id = %action_id,
            visibility = attrs.visibility,
            issuer_id_tag = %attrs.issuer_id_tag,
            action_type = attrs.typ,
            "Action permission denied"
        );
        return Err(Error::PermissionDenied);
    }

    Ok(next.run(req).await)
}

// STUB IMPLEMENTATION - Phase 3 will replace with real adapter calls
async fn load_action_attrs(_app: &App, _tn_id: TnId, _action_id: &str, _subject_id_tag: &str) -> ClResult<ActionAttrs> {
    // TODO: Call app.meta_adapter.get_action_attrs(tn_id, action_id).await
    Ok(ActionAttrs {
        typ: "post".into(),
        sub_typ: None,
        issuer_id_tag: "stub_user".into(),
        parent_id: None,
        root_id: None,
        audience_tag: vec![],
        tags: vec![],
        visibility: "public".into(),
    })
}
