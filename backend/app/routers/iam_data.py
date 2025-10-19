from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any

from app.database import get_db
from app.crud import get_current_upload_id, get_user_by_id, get_role_by_id, get_policy_by_id, get_group_by_id

router = APIRouter()

@router.get("/users/{user_id}")
async def get_user(user_id: str, db: Session = Depends(get_db)):
    """Get a specific user from the current upload"""
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "UserId": user.user_id,
        "UserName": user.user_name,
        "Arn": user.arn,
        "CreateDate": user.create_date,
        "AttachedManagedPolicies": user.attached_managed_policies,
        "GroupList": user.group_list,
        "UserPolicyList": user.user_policy_list,
        "Tags": user.tags
    }

@router.get("/roles/{role_id}")
async def get_role(role_id: str, db: Session = Depends(get_db)):
    """Get a specific role from the current upload"""
    role = get_role_by_id(db, role_id)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    return {
        "RoleId": role.role_id,
        "RoleName": role.role_name,
        "Arn": role.arn,
        "CreateDate": role.create_date,
        "AssumeRolePolicyDocument": role.assume_role_policy_document,
        "AttachedManagedPolicies": role.attached_managed_policies,
        "RolePolicyList": role.role_policy_list,
        "Tags": role.tags
    }

@router.get("/policies/{policy_id}")
async def get_policy(policy_id: str, db: Session = Depends(get_db)):
    """Get a specific policy from the current upload"""
    policy = get_policy_by_id(db, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    return {
        "PolicyId": policy.policy_id,
        "PolicyName": policy.policy_name,
        "Arn": policy.arn,
        "CreateDate": policy.create_date,
        "DefaultVersionId": policy.default_version_id,
        "PolicyVersionList": policy.policy_version_list,
        "AttachmentCount": policy.attachment_count,
        "IsAttachable": policy.is_attachable == "true",
        "Description": policy.description
    }

@router.get("/groups/{group_id}")
async def get_group(group_id: str, db: Session = Depends(get_db)):
    """Get a specific group from the current upload"""
    group = get_group_by_id(db, group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    return {
        "GroupId": group.group_id,
        "GroupName": group.group_name,
        "Arn": group.arn,
        "CreateDate": group.create_date,
        "AttachedManagedPolicies": group.attached_managed_policies,
        "GroupPolicyList": group.group_policy_list
    }
