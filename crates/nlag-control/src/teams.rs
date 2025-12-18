//! Team Management with Role-Based Access Control (RBAC)
//!
//! Provides hierarchical team management with fine-grained permissions.
//!
//! ## Roles
//!
//! - **Owner**: Full access, can delete team, manage billing
//! - **Admin**: Can manage members, tunnels, domains, API keys
//! - **Developer**: Can create/manage own tunnels and domains
//! - **Viewer**: Read-only access to team resources
//!
//! ## Permissions
//!
//! Granular permissions for tunnel, domain, API key, and team operations.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Team management errors
#[derive(Debug, Error)]
pub enum TeamError {
    #[error("Team not found: {0}")]
    TeamNotFound(String),
    
    #[error("Member not found: {0}")]
    MemberNotFound(String),
    
    #[error("User already in team: {0}")]
    AlreadyMember(String),
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Invalid role: {0}")]
    InvalidRole(String),
    
    #[error("Cannot remove last owner")]
    LastOwner,
    
    #[error("Team limit reached: {0}")]
    LimitReached(String),
    
    #[error("Invitation expired")]
    InvitationExpired,
    
    #[error("Invalid invitation: {0}")]
    InvalidInvitation(String),
}

pub type Result<T> = std::result::Result<T, TeamError>;

/// Permission types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    // Tunnel permissions
    TunnelCreate,
    TunnelRead,
    TunnelUpdate,
    TunnelDelete,
    TunnelManageAll,
    
    // Domain permissions
    DomainReserve,
    DomainRead,
    DomainRelease,
    DomainManageAll,
    
    // API key permissions
    ApiKeyCreate,
    ApiKeyRead,
    ApiKeyRevoke,
    ApiKeyManageAll,
    
    // Team permissions
    TeamRead,
    TeamUpdate,
    TeamDelete,
    MemberInvite,
    MemberRemove,
    MemberUpdateRole,
    
    // Billing permissions
    BillingRead,
    BillingManage,
    
    // Settings permissions
    SettingsRead,
    SettingsUpdate,
    WebhooksManage,
    SsoManage,
}

impl Permission {
    /// Get all permissions
    pub fn all() -> HashSet<Permission> {
        use Permission::*;
        [
            TunnelCreate, TunnelRead, TunnelUpdate, TunnelDelete, TunnelManageAll,
            DomainReserve, DomainRead, DomainRelease, DomainManageAll,
            ApiKeyCreate, ApiKeyRead, ApiKeyRevoke, ApiKeyManageAll,
            TeamRead, TeamUpdate, TeamDelete, MemberInvite, MemberRemove, MemberUpdateRole,
            BillingRead, BillingManage,
            SettingsRead, SettingsUpdate, WebhooksManage, SsoManage,
        ].into_iter().collect()
    }
}

/// Role definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Role name
    pub name: String,
    
    /// Display name
    pub display_name: String,
    
    /// Description
    pub description: String,
    
    /// Permissions
    pub permissions: HashSet<Permission>,
    
    /// Is this a built-in role
    pub builtin: bool,
    
    /// Priority (for display ordering)
    pub priority: i32,
}

impl Role {
    /// Owner role - full access
    pub fn owner() -> Self {
        Self {
            name: "owner".to_string(),
            display_name: "Owner".to_string(),
            description: "Full access to all team resources".to_string(),
            permissions: Permission::all(),
            builtin: true,
            priority: 100,
        }
    }
    
    /// Admin role - manage team and resources
    pub fn admin() -> Self {
        use Permission::*;
        Self {
            name: "admin".to_string(),
            display_name: "Admin".to_string(),
            description: "Manage team members and resources".to_string(),
            permissions: [
                TunnelCreate, TunnelRead, TunnelUpdate, TunnelDelete, TunnelManageAll,
                DomainReserve, DomainRead, DomainRelease, DomainManageAll,
                ApiKeyCreate, ApiKeyRead, ApiKeyRevoke, ApiKeyManageAll,
                TeamRead, TeamUpdate, MemberInvite, MemberRemove, MemberUpdateRole,
                BillingRead,
                SettingsRead, SettingsUpdate, WebhooksManage,
            ].into_iter().collect(),
            builtin: true,
            priority: 80,
        }
    }
    
    /// Developer role - create and manage own resources
    pub fn developer() -> Self {
        use Permission::*;
        Self {
            name: "developer".to_string(),
            display_name: "Developer".to_string(),
            description: "Create and manage tunnels and domains".to_string(),
            permissions: [
                TunnelCreate, TunnelRead, TunnelUpdate, TunnelDelete,
                DomainReserve, DomainRead, DomainRelease,
                ApiKeyCreate, ApiKeyRead,
                TeamRead,
                SettingsRead,
            ].into_iter().collect(),
            builtin: true,
            priority: 60,
        }
    }
    
    /// Viewer role - read-only access
    pub fn viewer() -> Self {
        use Permission::*;
        Self {
            name: "viewer".to_string(),
            display_name: "Viewer".to_string(),
            description: "View-only access to team resources".to_string(),
            permissions: [
                TunnelRead,
                DomainRead,
                ApiKeyRead,
                TeamRead,
                SettingsRead,
            ].into_iter().collect(),
            builtin: true,
            priority: 40,
        }
    }
    
    /// Check if role has permission
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }
}

/// Team member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMember {
    /// User ID
    pub user_id: String,
    
    /// Email
    pub email: String,
    
    /// Display name
    pub name: Option<String>,
    
    /// Role name
    pub role: String,
    
    /// Joined at
    pub joined_at: DateTime<Utc>,
    
    /// Invited by
    pub invited_by: Option<String>,
    
    /// Last active
    pub last_active: Option<DateTime<Utc>>,
    
    /// Custom permissions (additions to role)
    #[serde(default)]
    pub extra_permissions: HashSet<Permission>,
    
    /// Denied permissions (removals from role)
    #[serde(default)]
    pub denied_permissions: HashSet<Permission>,
}

impl TeamMember {
    /// Check if member has permission (considering role + custom)
    pub fn has_permission(&self, permission: Permission, roles: &HashMap<String, Role>) -> bool {
        // Check denied first
        if self.denied_permissions.contains(&permission) {
            return false;
        }
        
        // Check extra permissions
        if self.extra_permissions.contains(&permission) {
            return true;
        }
        
        // Check role
        if let Some(role) = roles.get(&self.role) {
            role.has_permission(permission)
        } else {
            false
        }
    }
}

/// Team invitation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamInvitation {
    /// Invitation ID (token)
    pub id: String,
    
    /// Team ID
    pub team_id: String,
    
    /// Invitee email
    pub email: String,
    
    /// Role to assign
    pub role: String,
    
    /// Invited by user ID
    pub invited_by: String,
    
    /// Created at
    pub created_at: DateTime<Utc>,
    
    /// Expires at
    pub expires_at: DateTime<Utc>,
    
    /// Status
    pub status: InvitationStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Declined,
    Expired,
    Revoked,
}

/// Team
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    /// Team ID
    pub id: String,
    
    /// Team name
    pub name: String,
    
    /// Team slug (URL-safe)
    pub slug: String,
    
    /// Description
    pub description: Option<String>,
    
    /// Created at
    pub created_at: DateTime<Utc>,
    
    /// Updated at
    pub updated_at: DateTime<Utc>,
    
    /// Subscription tier
    pub tier: String,
    
    /// Max members allowed
    pub max_members: u32,
    
    /// Settings
    #[serde(default)]
    pub settings: TeamSettings,
    
    /// SSO provider ID (if using SSO)
    pub sso_provider_id: Option<String>,
    
    /// Is active
    pub active: bool,
}

/// Team settings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TeamSettings {
    /// Default role for new members
    #[serde(default = "default_role")]
    pub default_role: String,
    
    /// Require SSO for login
    #[serde(default)]
    pub require_sso: bool,
    
    /// Allow personal tunnels
    #[serde(default = "default_true")]
    pub allow_personal_tunnels: bool,
    
    /// Require approval for new tunnels
    #[serde(default)]
    pub require_tunnel_approval: bool,
    
    /// Allowed domains for invites
    #[serde(default)]
    pub allowed_email_domains: Vec<String>,
    
    /// IP allowlist
    #[serde(default)]
    pub ip_allowlist: Vec<String>,
}

fn default_role() -> String { "developer".to_string() }
fn default_true() -> bool { true }

/// Team manager
pub struct TeamManager {
    /// Teams by ID
    teams: DashMap<String, Team>,
    
    /// Team members by team ID
    members: DashMap<String, HashMap<String, TeamMember>>,
    
    /// Roles by name
    roles: DashMap<String, Role>,
    
    /// Invitations by token
    invitations: DashMap<String, TeamInvitation>,
    
    /// User to teams mapping
    user_teams: DashMap<String, HashSet<String>>,
}

impl TeamManager {
    /// Create a new team manager
    pub fn new() -> Arc<Self> {
        let manager = Arc::new(Self {
            teams: DashMap::new(),
            members: DashMap::new(),
            roles: DashMap::new(),
            invitations: DashMap::new(),
            user_teams: DashMap::new(),
        });
        
        // Register built-in roles
        manager.roles.insert("owner".to_string(), Role::owner());
        manager.roles.insert("admin".to_string(), Role::admin());
        manager.roles.insert("developer".to_string(), Role::developer());
        manager.roles.insert("viewer".to_string(), Role::viewer());
        
        manager
    }
    
    /// Create a new team
    pub fn create_team(
        &self,
        name: &str,
        owner_id: &str,
        owner_email: &str,
        tier: &str,
        max_members: u32,
    ) -> Result<Team> {
        let slug = name.to_lowercase()
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '-' })
            .collect::<String>();
        
        let now = Utc::now();
        let team = Team {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            slug,
            description: None,
            created_at: now,
            updated_at: now,
            tier: tier.to_string(),
            max_members,
            settings: TeamSettings::default(),
            sso_provider_id: None,
            active: true,
        };
        
        // Create owner member
        let owner_member = TeamMember {
            user_id: owner_id.to_string(),
            email: owner_email.to_string(),
            name: None,
            role: "owner".to_string(),
            joined_at: now,
            invited_by: None,
            last_active: Some(now),
            extra_permissions: HashSet::new(),
            denied_permissions: HashSet::new(),
        };
        
        // Store team
        self.teams.insert(team.id.clone(), team.clone());
        
        // Store member
        let mut members = HashMap::new();
        members.insert(owner_id.to_string(), owner_member);
        self.members.insert(team.id.clone(), members);
        
        // Update user-teams mapping
        self.user_teams
            .entry(owner_id.to_string())
            .or_default()
            .insert(team.id.clone());
        
        info!("Created team {} ({}) with owner {}", team.name, team.id, owner_email);
        
        Ok(team)
    }
    
    /// Get team by ID
    pub fn get_team(&self, team_id: &str) -> Option<Team> {
        self.teams.get(team_id).map(|t| t.clone())
    }
    
    /// Get team by slug
    pub fn get_team_by_slug(&self, slug: &str) -> Option<Team> {
        self.teams.iter()
            .find(|t| t.slug == slug)
            .map(|t| t.clone())
    }
    
    /// Update team
    pub fn update_team(&self, team_id: &str, name: Option<&str>, description: Option<&str>) -> Result<Team> {
        let mut team = self.teams.get_mut(team_id)
            .ok_or_else(|| TeamError::TeamNotFound(team_id.to_string()))?;
        
        if let Some(n) = name {
            team.name = n.to_string();
        }
        if let Some(d) = description {
            team.description = Some(d.to_string());
        }
        team.updated_at = Utc::now();
        
        Ok(team.clone())
    }
    
    /// Delete team
    pub fn delete_team(&self, team_id: &str) -> Result<()> {
        // Remove members from user_teams mapping
        if let Some(members) = self.members.get(team_id) {
            for user_id in members.keys() {
                if let Some(mut teams) = self.user_teams.get_mut(user_id) {
                    teams.remove(team_id);
                }
            }
        }
        
        self.members.remove(team_id);
        self.teams.remove(team_id)
            .ok_or_else(|| TeamError::TeamNotFound(team_id.to_string()))?;
        
        info!("Deleted team {}", team_id);
        Ok(())
    }
    
    /// Get teams for user
    pub fn get_user_teams(&self, user_id: &str) -> Vec<Team> {
        self.user_teams.get(user_id)
            .map(|teams| {
                teams.iter()
                    .filter_map(|id| self.teams.get(id).map(|t| t.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
    
    /// Get team members
    pub fn get_members(&self, team_id: &str) -> Result<Vec<TeamMember>> {
        self.members.get(team_id)
            .map(|m| m.values().cloned().collect())
            .ok_or_else(|| TeamError::TeamNotFound(team_id.to_string()))
    }
    
    /// Get team member
    pub fn get_member(&self, team_id: &str, user_id: &str) -> Option<TeamMember> {
        self.members.get(team_id)?
            .get(user_id)
            .cloned()
    }
    
    /// Create invitation
    pub fn create_invitation(
        &self,
        team_id: &str,
        email: &str,
        role: &str,
        invited_by: &str,
    ) -> Result<TeamInvitation> {
        // Validate team exists
        let team = self.teams.get(team_id)
            .ok_or_else(|| TeamError::TeamNotFound(team_id.to_string()))?;
        
        // Check member limit
        let members = self.members.get(team_id)
            .ok_or_else(|| TeamError::TeamNotFound(team_id.to_string()))?;
        
        if members.len() >= team.max_members as usize {
            return Err(TeamError::LimitReached(format!(
                "Team has reached member limit of {}", team.max_members
            )));
        }
        
        // Validate role exists
        if !self.roles.contains_key(role) {
            return Err(TeamError::InvalidRole(role.to_string()));
        }
        
        // Check email domain if restricted
        if !team.settings.allowed_email_domains.is_empty() {
            let domain = email.split('@').last().unwrap_or("");
            if !team.settings.allowed_email_domains.iter().any(|d| d == domain) {
                return Err(TeamError::PermissionDenied(format!(
                    "Email domain {} not allowed", domain
                )));
            }
        }
        
        // Check if already member
        if members.values().any(|m| m.email == email) {
            return Err(TeamError::AlreadyMember(email.to_string()));
        }
        
        drop(team);
        drop(members);
        
        let now = Utc::now();
        let invitation = TeamInvitation {
            id: format!("inv_{}", uuid::Uuid::new_v4().to_string().replace("-", "")),
            team_id: team_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            invited_by: invited_by.to_string(),
            created_at: now,
            expires_at: now + chrono::Duration::days(7),
            status: InvitationStatus::Pending,
        };
        
        self.invitations.insert(invitation.id.clone(), invitation.clone());
        
        info!("Created invitation {} for {} to team {}", invitation.id, email, team_id);
        
        Ok(invitation)
    }
    
    /// Accept invitation
    pub fn accept_invitation(&self, token: &str, user_id: &str) -> Result<TeamMember> {
        let mut invitation = self.invitations.get_mut(token)
            .ok_or_else(|| TeamError::InvalidInvitation(token.to_string()))?;
        
        // Check status
        if invitation.status != InvitationStatus::Pending {
            return Err(TeamError::InvalidInvitation("Invitation not pending".to_string()));
        }
        
        // Check expiry
        if Utc::now() > invitation.expires_at {
            invitation.status = InvitationStatus::Expired;
            return Err(TeamError::InvitationExpired);
        }
        
        let now = Utc::now();
        let member = TeamMember {
            user_id: user_id.to_string(),
            email: invitation.email.clone(),
            name: None,
            role: invitation.role.clone(),
            joined_at: now,
            invited_by: Some(invitation.invited_by.clone()),
            last_active: Some(now),
            extra_permissions: HashSet::new(),
            denied_permissions: HashSet::new(),
        };
        
        // Add member
        let team_id = invitation.team_id.clone();
        self.members
            .entry(team_id.clone())
            .or_default()
            .insert(user_id.to_string(), member.clone());
        
        // Update user-teams mapping
        self.user_teams
            .entry(user_id.to_string())
            .or_default()
            .insert(team_id.clone());
        
        // Update invitation status
        invitation.status = InvitationStatus::Accepted;
        
        info!("User {} accepted invitation to team {}", user_id, team_id);
        
        Ok(member)
    }
    
    /// Revoke invitation
    pub fn revoke_invitation(&self, token: &str) -> Result<()> {
        let mut invitation = self.invitations.get_mut(token)
            .ok_or_else(|| TeamError::InvalidInvitation(token.to_string()))?;
        
        if invitation.status == InvitationStatus::Pending {
            invitation.status = InvitationStatus::Revoked;
            Ok(())
        } else {
            Err(TeamError::InvalidInvitation("Cannot revoke non-pending invitation".to_string()))
        }
    }
    
    /// Remove member
    pub fn remove_member(&self, team_id: &str, user_id: &str) -> Result<()> {
        let mut members = self.members.get_mut(team_id)
            .ok_or_else(|| TeamError::TeamNotFound(team_id.to_string()))?;
        
        // Check if last owner
        let member = members.get(user_id)
            .ok_or_else(|| TeamError::MemberNotFound(user_id.to_string()))?;
        
        if member.role == "owner" {
            let owner_count = members.values()
                .filter(|m| m.role == "owner")
                .count();
            
            if owner_count <= 1 {
                return Err(TeamError::LastOwner);
            }
        }
        
        members.remove(user_id);
        
        // Update user-teams mapping
        if let Some(mut teams) = self.user_teams.get_mut(user_id) {
            teams.remove(team_id);
        }
        
        info!("Removed user {} from team {}", user_id, team_id);
        
        Ok(())
    }
    
    /// Update member role
    pub fn update_member_role(&self, team_id: &str, user_id: &str, new_role: &str) -> Result<TeamMember> {
        // Validate role
        if !self.roles.contains_key(new_role) {
            return Err(TeamError::InvalidRole(new_role.to_string()));
        }
        
        let mut members = self.members.get_mut(team_id)
            .ok_or_else(|| TeamError::TeamNotFound(team_id.to_string()))?;
        
        // Check if demoting last owner (check before mutable borrow)
        let current_role = members.get(user_id)
            .ok_or_else(|| TeamError::MemberNotFound(user_id.to_string()))?
            .role.clone();
        
        if current_role == "owner" && new_role != "owner" {
            let owner_count = members.values()
                .filter(|m| m.role == "owner")
                .count();
            
            if owner_count <= 1 {
                return Err(TeamError::LastOwner);
            }
        }
        
        let member = members.get_mut(user_id)
            .ok_or_else(|| TeamError::MemberNotFound(user_id.to_string()))?;
        member.role = new_role.to_string();
        
        info!("Updated role for {} in team {} to {}", user_id, team_id, new_role);
        
        Ok(member.clone())
    }
    
    /// Check permission
    pub fn check_permission(
        &self,
        team_id: &str,
        user_id: &str,
        permission: Permission,
    ) -> bool {
        let roles: HashMap<String, Role> = self.roles.iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect();
        
        self.members.get(team_id)
            .and_then(|m| m.get(user_id).cloned())
            .map(|member| member.has_permission(permission, &roles))
            .unwrap_or(false)
    }
    
    /// Require permission (returns error if denied)
    pub fn require_permission(
        &self,
        team_id: &str,
        user_id: &str,
        permission: Permission,
    ) -> Result<()> {
        if self.check_permission(team_id, user_id, permission) {
            Ok(())
        } else {
            Err(TeamError::PermissionDenied(format!("{:?}", permission)))
        }
    }
    
    /// Get role
    pub fn get_role(&self, name: &str) -> Option<Role> {
        self.roles.get(name).map(|r| r.clone())
    }
    
    /// List roles
    pub fn list_roles(&self) -> Vec<Role> {
        let mut roles: Vec<Role> = self.roles.iter().map(|r| r.clone()).collect();
        roles.sort_by(|a, b| b.priority.cmp(&a.priority));
        roles
    }
    
    /// Create custom role
    pub fn create_custom_role(
        &self,
        name: &str,
        display_name: &str,
        description: &str,
        permissions: HashSet<Permission>,
    ) -> Result<Role> {
        if self.roles.contains_key(name) {
            return Err(TeamError::InvalidRole(format!("Role {} already exists", name)));
        }
        
        let role = Role {
            name: name.to_string(),
            display_name: display_name.to_string(),
            description: description.to_string(),
            permissions,
            builtin: false,
            priority: 50,
        };
        
        self.roles.insert(name.to_string(), role.clone());
        
        info!("Created custom role: {}", name);
        
        Ok(role)
    }
    
    /// Update team settings
    pub fn update_settings(&self, team_id: &str, settings: TeamSettings) -> Result<Team> {
        let mut team = self.teams.get_mut(team_id)
            .ok_or_else(|| TeamError::TeamNotFound(team_id.to_string()))?;
        
        team.settings = settings;
        team.updated_at = Utc::now();
        
        Ok(team.clone())
    }
    
    /// Get pending invitations for team
    pub fn get_pending_invitations(&self, team_id: &str) -> Vec<TeamInvitation> {
        self.invitations.iter()
            .filter(|i| i.team_id == team_id && i.status == InvitationStatus::Pending)
            .map(|i| i.clone())
            .collect()
    }
    
    /// Cleanup expired invitations
    pub fn cleanup_expired_invitations(&self) {
        let now = Utc::now();
        
        for mut entry in self.invitations.iter_mut() {
            if entry.status == InvitationStatus::Pending && entry.expires_at < now {
                entry.status = InvitationStatus::Expired;
            }
        }
    }
}

impl Default for TeamManager {
    fn default() -> Self {
        Arc::try_unwrap(Self::new()).unwrap_or_else(|arc| (*arc).clone())
    }
}

impl Clone for TeamManager {
    fn clone(&self) -> Self {
        Self {
            teams: self.teams.clone(),
            members: self.members.clone(),
            roles: self.roles.clone(),
            invitations: self.invitations.clone(),
            user_teams: self.user_teams.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_create_team() {
        let manager = TeamManager::new();
        
        let team = manager.create_team(
            "Test Team",
            "owner123",
            "owner@example.com",
            "team",
            10,
        ).unwrap();
        
        assert_eq!(team.name, "Test Team");
        assert_eq!(team.slug, "test-team");
        
        // Owner should be a member
        let members = manager.get_members(&team.id).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].role, "owner");
    }
    
    #[test]
    fn test_invite_and_accept() {
        let manager = TeamManager::new();
        
        let team = manager.create_team(
            "Test Team",
            "owner123",
            "owner@example.com",
            "team",
            10,
        ).unwrap();
        
        let invitation = manager.create_invitation(
            &team.id,
            "newuser@example.com",
            "developer",
            "owner123",
        ).unwrap();
        
        let member = manager.accept_invitation(&invitation.id, "user456").unwrap();
        
        assert_eq!(member.email, "newuser@example.com");
        assert_eq!(member.role, "developer");
        
        // Should now have 2 members
        let members = manager.get_members(&team.id).unwrap();
        assert_eq!(members.len(), 2);
    }
    
    #[test]
    fn test_permission_check() {
        let manager = TeamManager::new();
        
        let team = manager.create_team(
            "Test Team",
            "owner123",
            "owner@example.com",
            "team",
            10,
        ).unwrap();
        
        // Owner should have all permissions
        assert!(manager.check_permission(&team.id, "owner123", Permission::TeamDelete));
        assert!(manager.check_permission(&team.id, "owner123", Permission::TunnelCreate));
        
        // Add a viewer
        let inv = manager.create_invitation(&team.id, "viewer@test.com", "viewer", "owner123").unwrap();
        manager.accept_invitation(&inv.id, "viewer1").unwrap();
        
        // Viewer should not have write permissions
        assert!(manager.check_permission(&team.id, "viewer1", Permission::TunnelRead));
        assert!(!manager.check_permission(&team.id, "viewer1", Permission::TunnelCreate));
    }
    
    #[test]
    fn test_role_update() {
        let manager = TeamManager::new();
        
        let team = manager.create_team(
            "Test Team",
            "owner123",
            "owner@example.com",
            "team",
            10,
        ).unwrap();
        
        // Add a developer
        let inv = manager.create_invitation(&team.id, "dev@test.com", "developer", "owner123").unwrap();
        manager.accept_invitation(&inv.id, "dev1").unwrap();
        
        // Promote to admin
        let member = manager.update_member_role(&team.id, "dev1", "admin").unwrap();
        assert_eq!(member.role, "admin");
        
        // Should now have admin permissions
        assert!(manager.check_permission(&team.id, "dev1", Permission::MemberInvite));
    }
    
    #[test]
    fn test_cannot_remove_last_owner() {
        let manager = TeamManager::new();
        
        let team = manager.create_team(
            "Test Team",
            "owner123",
            "owner@example.com",
            "team",
            10,
        ).unwrap();
        
        let result = manager.remove_member(&team.id, "owner123");
        assert!(matches!(result, Err(TeamError::LastOwner)));
        
        let result = manager.update_member_role(&team.id, "owner123", "developer");
        assert!(matches!(result, Err(TeamError::LastOwner)));
    }
    
    #[test]
    fn test_member_limit() {
        let manager = TeamManager::new();
        
        let team = manager.create_team(
            "Small Team",
            "owner123",
            "owner@example.com",
            "team",
            2, // Small limit
        ).unwrap();
        
        // Add one more member
        let inv = manager.create_invitation(&team.id, "user1@test.com", "developer", "owner123").unwrap();
        manager.accept_invitation(&inv.id, "user1").unwrap();
        
        // Should fail - limit reached
        let result = manager.create_invitation(&team.id, "user2@test.com", "developer", "owner123");
        assert!(matches!(result, Err(TeamError::LimitReached(_))));
    }
    
    #[test]
    fn test_custom_role() {
        let manager = TeamManager::new();
        
        let role = manager.create_custom_role(
            "billing_admin",
            "Billing Admin",
            "Can manage billing only",
            [Permission::BillingRead, Permission::BillingManage, Permission::TeamRead].into(),
        ).unwrap();
        
        assert!(!role.builtin);
        assert!(role.has_permission(Permission::BillingManage));
        assert!(!role.has_permission(Permission::TunnelCreate));
    }
    
    #[test]
    fn test_user_teams() {
        let manager = TeamManager::new();
        
        // Create two teams for same owner
        let team1 = manager.create_team("Team 1", "owner1", "owner@test.com", "team", 10).unwrap();
        let team2 = manager.create_team("Team 2", "owner1", "owner@test.com", "team", 10).unwrap();
        
        let teams = manager.get_user_teams("owner1");
        assert_eq!(teams.len(), 2);
        
        let team_ids: HashSet<String> = teams.iter().map(|t| t.id.clone()).collect();
        assert!(team_ids.contains(&team1.id));
        assert!(team_ids.contains(&team2.id));
    }
    
    #[test]
    fn test_email_domain_restriction() {
        let manager = TeamManager::new();
        
        let mut team = manager.create_team(
            "Corp Team",
            "owner123",
            "owner@corp.com",
            "team",
            10,
        ).unwrap();
        
        // Restrict to corp.com domain
        let settings = TeamSettings {
            allowed_email_domains: vec!["corp.com".to_string()],
            ..Default::default()
        };
        
        manager.update_settings(&team.id, settings).unwrap();
        
        // Should fail - wrong domain
        let result = manager.create_invitation(&team.id, "user@other.com", "developer", "owner123");
        assert!(matches!(result, Err(TeamError::PermissionDenied(_))));
        
        // Should work - correct domain
        let result = manager.create_invitation(&team.id, "user@corp.com", "developer", "owner123");
        assert!(result.is_ok());
    }
}
