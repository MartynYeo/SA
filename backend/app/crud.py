from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models import Upload, User, Role, Policy, Group, LLMRecommendation, RecommendedPolicy, AttackPath
from app.schemas import UploadCreate, ProcessedIAMData

def create_upload(db: Session, upload_id: str, upload_data: UploadCreate) -> Upload:
    """Create a new upload with associated IAM data"""
    # Create the upload record
    db_upload = Upload(
        id=upload_id,
        name=upload_data.name,
        original_filename=upload_data.original_filename,
        size=upload_data.size
    )
    db.add(db_upload)

    # Create users
    for user_id, user_data in upload_data.data.users.items():
        db_user = User(
            user_id=user_id,
            user_name=user_data.UserName,
            arn=user_data.Arn,
            create_date=user_data.CreateDate,
            attached_managed_policies=user_data.AttachedManagedPolicies,
            group_list=user_data.GroupList,
            user_policy_list=user_data.UserPolicyList,
            tags=user_data.Tags,
            upload_id=upload_id
        )
        db.add(db_user)

    # Create roles
    for role_id, role_data in upload_data.data.roles.items():
        db_role = Role(
            role_id=role_id,
            role_name=role_data.RoleName,
            arn=role_data.Arn,
            create_date=role_data.CreateDate,
            assume_role_policy_document=role_data.AssumeRolePolicyDocument,
            attached_managed_policies=role_data.AttachedManagedPolicies,
            role_policy_list=role_data.RolePolicyList,
            tags=role_data.Tags,
            upload_id=upload_id
        )
        db.add(db_role)

    # Create policies
    for policy_id, policy_data in upload_data.data.policies.items():
        db_policy = Policy(
            policy_id=policy_id,
            policy_name=policy_data.PolicyName,
            arn=policy_data.Arn,
            create_date=policy_data.CreateDate,
            default_version_id=policy_data.DefaultVersionId,
            policy_version_list=policy_data.PolicyVersionList,
            attachment_count=policy_data.AttachmentCount,
            is_attachable=str(policy_data.IsAttachable).lower(),
            description=policy_data.Description,
            upload_id=upload_id
        )
        db.add(db_policy)

    # Create groups
    for group_id, group_data in upload_data.data.groups.items():
        db_group = Group(
            group_id=group_id,
            group_name=group_data.GroupName,
            arn=group_data.Arn,
            create_date=group_data.CreateDate,
            attached_managed_policies=group_data.AttachedManagedPolicies,
            group_policy_list=group_data.GroupPolicyList,
            upload_id=upload_id
        )
        db.add(db_group)

    db.commit()
    db.refresh(db_upload)
    return db_upload

def get_uploads(db: Session) -> list[Upload]:
    """Get all uploads ordered by upload date (newest first)"""
    return db.query(Upload).order_by(desc(Upload.uploaded_at)).all()

def get_upload(db: Session, upload_id: str) -> Upload | None:
    """Get a specific upload by ID"""
    return db.query(Upload).filter(Upload.id == upload_id).first()

def delete_upload(db: Session, upload_id: str) -> bool:
    """Delete an upload and all associated data"""
    upload = db.query(Upload).filter(Upload.id == upload_id).first()
    if upload:
        db.delete(upload)
        db.commit()
        return True
    return False

def get_current_upload_id(db: Session) -> str | None:
    """Get the current active upload ID from the database"""
    # For now, we'll just return the most recent upload
    # In a more complex system, you might have a separate table for current upload
    most_recent = db.query(Upload).order_by(desc(Upload.uploaded_at)).first()
    return most_recent.id if most_recent else None

def set_current_upload(db: Session, upload_id: str) -> bool:
    """Set the current active upload (placeholder implementation)"""
    # For now, this is a no-op since we're using the most recent upload
    # In a real implementation, you might update a settings table
    upload = db.query(Upload).filter(Upload.id == upload_id).first()
    return upload is not None

# Individual IAM resource getters
def get_user_by_id(db: Session, user_id: str) -> User | None:
    """Get a user by ID from the current upload"""
    current_upload_id = get_current_upload_id(db)
    if not current_upload_id:
        return None
    return db.query(User).filter(
        User.user_id == user_id,
        User.upload_id == current_upload_id
    ).first()

def get_role_by_id(db: Session, role_id: str) -> Role | None:
    """Get a role by ID from the current upload"""
    current_upload_id = get_current_upload_id(db)
    if not current_upload_id:
        return None
    return db.query(Role).filter(
        Role.role_id == role_id,
        Role.upload_id == current_upload_id
    ).first()

def get_policy_by_id(db: Session, policy_id: str) -> Policy | None:
    """Get a policy by ID from the current upload"""
    current_upload_id = get_current_upload_id(db)
    if not current_upload_id:
        return None
    return db.query(Policy).filter(
        Policy.policy_id == policy_id,
        Policy.upload_id == current_upload_id
    ).first()

def get_group_by_id(db: Session, group_id: str) -> Group | None:
    """Get a group by ID from the current upload"""
    current_upload_id = get_current_upload_id(db)
    if not current_upload_id:
        return None
    return db.query(Group).filter(
        Group.group_id == group_id,
        Group.upload_id == current_upload_id
    ).first()


# LLM Recommendation CRUD
def upsert_llm_recommendation(
    db: Session,
    upload_id: str,
    policy_id: str,
    policy_name: str,
    recommendations: list[str],
    rationale: str | None,
) -> LLMRecommendation:
    existing = (
        db.query(LLMRecommendation)
        .filter(LLMRecommendation.upload_id == upload_id, LLMRecommendation.policy_id == policy_id)
        .first()
    )
    if existing:
        existing.policy_name = policy_name
        existing.recommendations = recommendations
        existing.rationale = rationale
        db.commit()
        db.refresh(existing)
        return existing

    rec = LLMRecommendation(
        upload_id=upload_id,
        policy_id=policy_id,
        policy_name=policy_name,
        recommendations=recommendations,
        rationale=rationale,
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec


def get_llm_recommendation(db: Session, upload_id: str, policy_id: str) -> LLMRecommendation | None:
    return (
        db.query(LLMRecommendation)
        .filter(LLMRecommendation.upload_id == upload_id, LLMRecommendation.policy_id == policy_id)
        .first()
    )


# Recommended Policy CRUD
def upsert_recommended_policy(
    db: Session,
    upload_id: str,
    policy_id: str,
    policy_name: str,
    policy_document: dict,
    explanation: str | None,
) -> RecommendedPolicy:
    existing = (
        db.query(RecommendedPolicy)
        .filter(RecommendedPolicy.upload_id == upload_id, RecommendedPolicy.policy_id == policy_id)
        .first()
    )
    if existing:
        existing.policy_name = policy_name
        existing.policy_document = policy_document
        existing.explanation = explanation
        db.commit()
        db.refresh(existing)
        return existing

    rec = RecommendedPolicy(
        upload_id=upload_id,
        policy_id=policy_id,
        policy_name=policy_name,
        policy_document=policy_document,
        explanation=explanation,
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec


def get_recommended_policy(db: Session, upload_id: str, policy_id: str) -> RecommendedPolicy | None:
    return (
        db.query(RecommendedPolicy)
        .filter(RecommendedPolicy.upload_id == upload_id, RecommendedPolicy.policy_id == policy_id)
        .first()
    )


# Attack Path CRUD
def upsert_attack_path(
    db: Session,
    upload_id: str,
    policy_id: str,
    policy_name: str,
    attack_scenarios: list,
    impact_assessment: str | None,
) -> AttackPath:
    existing = (
        db.query(AttackPath)
        .filter(AttackPath.upload_id == upload_id, AttackPath.policy_id == policy_id)
        .first()
    )
    if existing:
        existing.policy_name = policy_name
        existing.attack_scenarios = attack_scenarios
        existing.impact_assessment = impact_assessment
        db.commit()
        db.refresh(existing)
        return existing

    rec = AttackPath(
        upload_id=upload_id,
        policy_id=policy_id,
        policy_name=policy_name,
        attack_scenarios=attack_scenarios,
        impact_assessment=impact_assessment,
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec


def get_attack_path(db: Session, upload_id: str, policy_id: str) -> AttackPath | None:
    return (
        db.query(AttackPath)
        .filter(AttackPath.upload_id == upload_id, AttackPath.policy_id == policy_id)
        .first()
    )
