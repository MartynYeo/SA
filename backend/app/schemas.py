from pydantic import BaseModel
from typing import Dict, List, Any, Optional
from datetime import datetime

# IAM Data Structures
class IAMUser(BaseModel):
    UserId: str
    UserName: str
    Arn: str
    CreateDate: str
    AttachedManagedPolicies: List[Dict[str, str]]
    GroupList: List[str]
    UserPolicyList: List[Dict[str, Any]]
    Tags: List[Dict[str, str]]

class IAMRole(BaseModel):
    RoleId: str
    RoleName: str
    Arn: str
    CreateDate: str
    AssumeRolePolicyDocument: Dict[str, Any]
    AttachedManagedPolicies: List[Dict[str, str]]
    RolePolicyList: List[Dict[str, Any]]
    Tags: List[Dict[str, str]]

class IAMPolicy(BaseModel):
    PolicyId: str
    PolicyName: str
    Arn: str
    CreateDate: str
    DefaultVersionId: str
    PolicyVersionList: List[Dict[str, Any]]
    AttachmentCount: int
    IsAttachable: bool
    Description: str

class IAMGroup(BaseModel):
    GroupId: str
    GroupName: str
    Arn: str
    CreateDate: str
    AttachedManagedPolicies: List[Dict[str, str]]
    GroupPolicyList: List[Dict[str, Any]]

class ProcessedIAMData(BaseModel):
    users: Dict[str, IAMUser]
    roles: Dict[str, IAMRole]
    policies: Dict[str, IAMPolicy]
    groups: Dict[str, IAMGroup]

# Upload schemas
class UploadBase(BaseModel):
    name: str
    original_filename: str
    size: int

class UploadCreate(UploadBase):
    data: ProcessedIAMData

class Upload(UploadBase):
    id: str
    uploaded_at: datetime

    class Config:
        from_attributes = True

class UploadMetadata(BaseModel):
    id: str
    name: str
    original_filename: str
    uploaded_at: str
    size: int

# Raw IAM data for processing
class RawIAMData(BaseModel):
    UserDetailList: List[IAMUser]
    RoleDetailList: List[IAMRole]
    Policies: List[IAMPolicy]
    GroupDetailList: List[IAMGroup]

# API Response schemas
class CurrentUploadResponse(BaseModel):
    upload_id: Optional[str]


# LLM Recommendations
class LLMRecommendationBase(BaseModel):
    upload_id: str
    policy_id: str
    policy_name: str
    recommendations: List[str]
    rationale: Optional[str] = None


class LLMRecommendationCreate(BaseModel):
    upload_id: str
    policy_id: str
    policy_name: str
    recommendations: List[str]
    rationale: Optional[str] = None


class LLMRecommendationResponse(LLMRecommendationBase):
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    class Config:
        from_attributes = True


# Recommended Policy schemas
class RecommendedPolicyBase(BaseModel):
    upload_id: str
    policy_id: str
    policy_name: str
    policy_document: Dict[str, Any]
    explanation: Optional[str] = None


class RecommendedPolicyCreate(BaseModel):
    upload_id: str
    policy_id: str
    policy_name: str
    policy_document: Dict[str, Any]
    explanation: Optional[str] = None


class RecommendedPolicyResponse(RecommendedPolicyBase):
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    class Config:
        from_attributes = True


# Attack Path schemas
class AttackPathBase(BaseModel):
    upload_id: str
    policy_id: str
    policy_name: str
    attack_scenarios: List[Dict[str, Any]]
    impact_assessment: Optional[str] = None


class AttackPathCreate(BaseModel):
    upload_id: str
    policy_id: str
    policy_name: str
    attack_scenarios: List[Dict[str, Any]]
    impact_assessment: Optional[str] = None


class AttackPathResponse(AttackPathBase):
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    class Config:
        from_attributes = True