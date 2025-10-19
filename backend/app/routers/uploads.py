from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
import uuid
from datetime import datetime

from app.database import get_db
from app.models import Upload, User, Role, Policy, Group
from app.schemas import Upload as UploadSchema, UploadCreate, UploadMetadata, ProcessedIAMData, CurrentUploadResponse
from app.crud import (
    create_upload,
    get_uploads,
    get_upload,
    delete_upload,
    set_current_upload,
    get_current_upload_id
)

router = APIRouter()

@router.post("/", response_model=UploadSchema)
async def create_new_upload(upload_data: UploadCreate, db: Session = Depends(get_db)):
    """Create a new upload with IAM data"""
    try:
        upload_id = str(uuid.uuid4())
        upload = create_upload(db, upload_id, upload_data)
        return upload
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to create upload: {str(e)}")

@router.get("/", response_model=List[UploadMetadata])
async def list_uploads(db: Session = Depends(get_db)):
    """Get all uploads metadata"""
    uploads = get_uploads(db)
    return [
        UploadMetadata(
            id=upload.id,
            name=upload.name,
            original_filename=upload.original_filename,
            uploaded_at=upload.uploaded_at.isoformat(),
            size=upload.size
        )
        for upload in uploads
    ]

@router.get("/{upload_id}", response_model=ProcessedIAMData)
async def get_upload_data(upload_id: str, db: Session = Depends(get_db)):
    """Get processed IAM data for a specific upload"""
    upload = get_upload(db, upload_id)
    if not upload:
        raise HTTPException(status_code=404, detail="Upload not found")

    # Reconstruct the processed data structure
    users = {user.user_id: {
        "UserId": user.user_id,
        "UserName": user.user_name,
        "Arn": user.arn,
        "CreateDate": user.create_date,
        "AttachedManagedPolicies": user.attached_managed_policies,
        "GroupList": user.group_list,
        "UserPolicyList": user.user_policy_list,
        "Tags": user.tags
    } for user in upload.users}

    roles = {role.role_id: {
        "RoleId": role.role_id,
        "RoleName": role.role_name,
        "Arn": role.arn,
        "CreateDate": role.create_date,
        "AssumeRolePolicyDocument": role.assume_role_policy_document,
        "AttachedManagedPolicies": role.attached_managed_policies,
        "RolePolicyList": role.role_policy_list,
        "Tags": role.tags
    } for role in upload.roles}

    policies = {policy.policy_id: {
        "PolicyId": policy.policy_id,
        "PolicyName": policy.policy_name,
        "Arn": policy.arn,
        "CreateDate": policy.create_date,
        "DefaultVersionId": policy.default_version_id,
        "PolicyVersionList": policy.policy_version_list,
        "AttachmentCount": policy.attachment_count,
        "IsAttachable": policy.is_attachable == "true",
        "Description": policy.description
    } for policy in upload.policies}

    groups = {group.group_id: {
        "GroupId": group.group_id,
        "GroupName": group.group_name,
        "Arn": group.arn,
        "CreateDate": group.create_date,
        "AttachedManagedPolicies": group.attached_managed_policies,
        "GroupPolicyList": group.group_policy_list
    } for group in upload.groups}

    return ProcessedIAMData(
        users=users,
        roles=roles,
        policies=policies,
        groups=groups
    )

@router.delete("/{upload_id}")
async def delete_upload_endpoint(upload_id: str, db: Session = Depends(get_db)):
    """Delete an upload and all associated data"""
    success = delete_upload(db, upload_id)
    if not success:
        raise HTTPException(status_code=404, detail="Upload not found")
    return {"message": "Upload deleted successfully"}

@router.post("/current/{upload_id}")
async def set_current_upload_endpoint(upload_id: str, db: Session = Depends(get_db)):
    """Set the current active upload"""
    success = set_current_upload(db, upload_id)
    if not success:
        raise HTTPException(status_code=404, detail="Upload not found")
    return {"message": "Current upload set successfully"}

@router.get("/current/id", response_model=CurrentUploadResponse)
async def get_current_upload_endpoint(db: Session = Depends(get_db)):
    """Get the current active upload ID"""
    upload_id = get_current_upload_id(db)
    return CurrentUploadResponse(upload_id=upload_id)
