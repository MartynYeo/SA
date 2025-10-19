from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base

class Upload(Base):
    __tablename__ = "uploads"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    original_filename = Column(String, nullable=False)
    uploaded_at = Column(DateTime(timezone=True), server_default=func.now())
    size = Column(Integer, nullable=False)

    # Relationships
    users = relationship("User", back_populates="upload", cascade="all, delete-orphan")
    roles = relationship("Role", back_populates="upload", cascade="all, delete-orphan")
    policies = relationship("Policy", back_populates="upload", cascade="all, delete-orphan")
    groups = relationship("Group", back_populates="upload", cascade="all, delete-orphan")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, nullable=False, index=True)
    user_name = Column(String, nullable=False)
    arn = Column(String, nullable=False)
    create_date = Column(String, nullable=False)
    attached_managed_policies = Column(JSON, nullable=False)
    group_list = Column(JSON, nullable=False)
    user_policy_list = Column(JSON, nullable=False)
    tags = Column(JSON, nullable=False)

    # Foreign key
    upload_id = Column(String, ForeignKey("uploads.id"), nullable=False)
    upload = relationship("Upload", back_populates="users")

class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(String, nullable=False, index=True)
    role_name = Column(String, nullable=False)
    arn = Column(String, nullable=False)
    create_date = Column(String, nullable=False)
    assume_role_policy_document = Column(JSON, nullable=False)
    attached_managed_policies = Column(JSON, nullable=False)
    role_policy_list = Column(JSON, nullable=False)
    tags = Column(JSON, nullable=False)

    # Foreign key
    upload_id = Column(String, ForeignKey("uploads.id"), nullable=False)
    upload = relationship("Upload", back_populates="roles")

class Policy(Base):
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, index=True)
    policy_id = Column(String, nullable=False, index=True)
    policy_name = Column(String, nullable=False)
    arn = Column(String, nullable=False)
    create_date = Column(String, nullable=False)
    default_version_id = Column(String, nullable=False)
    policy_version_list = Column(JSON, nullable=False)
    attachment_count = Column(Integer, nullable=False)
    is_attachable = Column(String, nullable=False)  # boolean as string
    description = Column(String, nullable=True)

    # Foreign key
    upload_id = Column(String, ForeignKey("uploads.id"), nullable=False)
    upload = relationship("Upload", back_populates="policies")

class Group(Base):
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(String, nullable=False, index=True)
    group_name = Column(String, nullable=False)
    arn = Column(String, nullable=False)
    create_date = Column(String, nullable=False)
    attached_managed_policies = Column(JSON, nullable=False)
    group_policy_list = Column(JSON, nullable=False)

    # Foreign key
    upload_id = Column(String, ForeignKey("uploads.id"), nullable=False)
    upload = relationship("Upload", back_populates="groups")


class LLMRecommendation(Base):
    __tablename__ = "llm_recommendations"

    id = Column(Integer, primary_key=True, index=True)
    upload_id = Column(String, ForeignKey("uploads.id"), nullable=False, index=True)
    policy_id = Column(String, nullable=False, index=True)
    policy_name = Column(String, nullable=False)
    recommendations = Column(JSON, nullable=False)
    rationale = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    upload = relationship("Upload")


class RecommendedPolicy(Base):
    __tablename__ = "recommended_policies"

    id = Column(Integer, primary_key=True, index=True)
    upload_id = Column(String, ForeignKey("uploads.id"), nullable=False, index=True)
    policy_id = Column(String, nullable=False, index=True)
    policy_name = Column(String, nullable=False)
    policy_document = Column(JSON, nullable=False)
    explanation = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    upload = relationship("Upload")


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id = Column(Integer, primary_key=True, index=True)
    upload_id = Column(String, ForeignKey("uploads.id"), nullable=False, index=True)
    policy_id = Column(String, nullable=False, index=True)
    policy_name = Column(String, nullable=False)
    attack_scenarios = Column(JSON, nullable=False)
    impact_assessment = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    upload = relationship("Upload")