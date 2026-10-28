//! OpenAPI document derived from utoipa annotations.

use axum::http::Method;

use utoipa::OpenApi;
use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};
use utoipa::openapi::{OpenApi as OpenApiDoc, SecurityRequirement};

use crate::rbac::registry::{self, Access};

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::api::health::healthz,
        crate::api::jwks::jwks,
        crate::api::auth::login,
        crate::api::auth::refresh,
        crate::api::auth::logout,
        crate::api::me::me,
        crate::api::token::token_openapi,
        crate::api::users::list_users,
        crate::api::users::get_user,
        crate::api::users::create_user,
        crate::api::users::patch_user,
        crate::api::users::assign_role,
        crate::api::users::unassign_role,
        crate::api::rbac::list_roles,
        crate::api::rbac::create_role,
        crate::api::rbac::list_permissions,
        crate::api::rbac::get_role_permissions,
        crate::api::rbac::set_role_permissions,
        crate::api::rbac::remove_role,
    ),
    components(schemas(
        crate::api::health::HealthResponse,
        crate::api::auth::LoginRequest,
        crate::api::auth::RefreshRequest,
        crate::api::auth::TokenResponse,
        crate::api::me::MeResponse,
        crate::api::token::TokenResponse,
        crate::api::users::UserResponse,
        crate::api::users::CreateUserRequest,
        crate::api::users::UpdateUserRequest,
        crate::api::users::ListQuery,
        crate::api::users::AssignRoleRequest,
        crate::api::rbac::RoleSummary,
        crate::api::rbac::CreateRoleRequest,
        crate::api::rbac::CreatedRole,
        crate::api::rbac::PermissionEntry,
        crate::api::rbac::SetPermissionsRequest,
    ))
)]
pub struct ApiDoc;

/// Bangun dokumen OpenAPI, lalu sisipkan security scheme dan security
/// requirement per operasi dari `rbac::registry::ROUTES` (satu sumber
/// kebenaran). Tidak ada string permission yang ditulis manual di sini.
pub fn openapi() -> OpenApiDoc {
    let mut api = ApiDoc::openapi();

    let components = api.components.get_or_insert_with(Default::default);
    components.security_schemes.insert(
        "bearerAuth".to_string(),
        utoipa::openapi::RefOr::T(SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer))),
    );

    for (path, item) in api.paths.paths.iter_mut() {
        if let Some(op) = item.get.as_mut() {
            enrich(op, Method::GET, path);
        }
        if let Some(op) = item.put.as_mut() {
            enrich(op, Method::PUT, path);
        }
        if let Some(op) = item.post.as_mut() {
            enrich(op, Method::POST, path);
        }
        if let Some(op) = item.delete.as_mut() {
            enrich(op, Method::DELETE, path);
        }
        if let Some(op) = item.patch.as_mut() {
            enrich(op, Method::PATCH, path);
        }
    }

    api
}

fn enrich(op: &mut utoipa::openapi::path::Operation, method: Method, path: &str) {
    let Some(route) = registry::find(&method, path) else {
        return;
    };
    match route.access {
        Access::Public => {
            op.security = None;
        }
        Access::Authenticated => {
            op.security = Some(vec![SecurityRequirement::new(
                "bearerAuth",
                Vec::<String>::new(),
            )]);
        }
        Access::Permission(permission) => {
            op.security = Some(vec![SecurityRequirement::new("bearerAuth", [permission])]);
        }
    }
}
