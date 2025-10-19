"""
Policy Service Module

Handles policy-related business logic including recommendation processing,
policy document generation, and database operations for policies.
"""

from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.crud import (
    upsert_llm_recommendation, 
    get_llm_recommendation, 
    get_current_upload_id, 
    upsert_recommended_policy, 
    get_recommended_policy
)
from app.schemas import LLMRecommendationResponse, RecommendedPolicyResponse
from app.modules.llm_service import llm_service


class PolicyService:
    """Service class for handling policy-related operations."""
    
    def __init__(self):
        self.llm_service = llm_service
    
    def generate_recommendations(self, policy_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate LLM-backed remediation recommendations.
        
        Args:
            policy_context: Dictionary containing policy information and detected flags
            
        Returns:
            Dictionary with recommendations and rationale
        """
        return self.llm_service.generate_recommendations(policy_context)
    
    def generate_recommended_policy(self, policy_context: Dict[str, Any], db: Session) -> Dict[str, Any]:
        """
        Generate a recommended policy document and store it in the database.
        
        Args:
            policy_context: Dictionary containing original policy and security issues
            db: Database session
            
        Returns:
            Dictionary with policy_document and explanation
        """
        # Generate the policy using LLM service
        result = self.llm_service.generate_recommended_policy(policy_context)
        
        # Store the recommended policy in the database
        current_upload_id = get_current_upload_id(db)
        if current_upload_id:
            upsert_recommended_policy(
                db=db,
                upload_id=current_upload_id,
                policy_id=policy_context["original_policy"]["policy_id"],
                policy_name=policy_context["original_policy"]["policy_name"],
                policy_document=result["policy_document"],
                explanation=result["explanation"],
            )
        
        return result
    
    def get_stored_recommended_policy(self, upload_id: str, policy_id: str, db: Session) -> Optional[RecommendedPolicyResponse]:
        """
        Get a stored recommended policy from the database.
        
        Args:
            upload_id: Upload ID
            policy_id: Policy ID
            db: Database session
            
        Returns:
            RecommendedPolicyResponse or None if not found
        """
        rec = get_recommended_policy(db, upload_id, policy_id)
        if not rec:
            return None
        
        return RecommendedPolicyResponse(
            upload_id=rec.upload_id,
            policy_id=rec.policy_id,
            policy_name=rec.policy_name,
            policy_document=rec.policy_document,
            explanation=rec.explanation,
            created_at=rec.created_at.isoformat() if rec.created_at else None,
            updated_at=rec.updated_at.isoformat() if rec.updated_at else None,
        )
    
    def persist_recommended_policy(self, upload_id: str, policy_id: str, policy_name: str, 
                                 policy_document: Dict[str, Any], explanation: Optional[str], 
                                 db: Session) -> RecommendedPolicyResponse:
        """
        Persist a recommended policy to the database.
        
        Args:
            upload_id: Upload ID
            policy_id: Policy ID
            policy_name: Policy name
            policy_document: Policy document
            explanation: Explanation text
            db: Database session
            
        Returns:
            RecommendedPolicyResponse
        """
        rec = upsert_recommended_policy(
            db=db,
            upload_id=upload_id,
            policy_id=policy_id,
            policy_name=policy_name,
            policy_document=policy_document,
            explanation=explanation,
        )
        
        return RecommendedPolicyResponse(
            upload_id=rec.upload_id,
            policy_id=rec.policy_id,
            policy_name=rec.policy_name,
            policy_document=rec.policy_document,
            explanation=rec.explanation,
            created_at=rec.created_at.isoformat() if rec.created_at else None,
            updated_at=rec.updated_at.isoformat() if rec.updated_at else None,
        )
    
    def regenerate_recommended_policy(self, policy_context: Dict[str, Any], db: Session) -> Dict[str, Any]:
        """
        Regenerate and store a recommended policy.
        
        Args:
            policy_context: Dictionary containing policy context
            db: Database session
            
        Returns:
            Dictionary with policy_document and explanation
        """
        # Generate the recommended policy (which will automatically store it)
        generated = self.generate_recommended_policy(policy_context, db)
        
        # Fetch it from the database to get the timestamps
        current_upload_id = get_current_upload_id(db)
        if current_upload_id:
            stored_policy = get_recommended_policy(db, current_upload_id, policy_context["original_policy"]["policy_id"])
            if stored_policy:
                return {
                    "policy_document": stored_policy.policy_document,
                    "explanation": stored_policy.explanation,
                    "upload_id": stored_policy.upload_id,
                    "policy_id": stored_policy.policy_id,
                    "policy_name": stored_policy.policy_name,
                    "created_at": stored_policy.created_at.isoformat() if stored_policy.created_at else None,
                    "updated_at": stored_policy.updated_at.isoformat() if stored_policy.updated_at else None,
                }
        
        # Fallback to the generated response
        return generated
    
    def get_stored_recommendation(self, upload_id: str, policy_id: str, db: Session) -> Optional[LLMRecommendationResponse]:
        """
        Get a stored recommendation from the database.
        
        Args:
            upload_id: Upload ID
            policy_id: Policy ID
            db: Database session
            
        Returns:
            LLMRecommendationResponse or None if not found
        """
        rec = get_llm_recommendation(db, upload_id, policy_id)
        if not rec:
            return None
        
        return LLMRecommendationResponse(
            upload_id=rec.upload_id,
            policy_id=rec.policy_id,
            policy_name=rec.policy_name,
            recommendations=rec.recommendations,
            rationale=rec.rationale,
            created_at=rec.created_at.isoformat() if rec.created_at else None,
            updated_at=rec.updated_at.isoformat() if rec.updated_at else None,
        )
    
    def persist_recommendation(self, upload_id: str, policy_id: str, policy_name: str, 
                             recommendations: List[str], rationale: Optional[str], 
                             db: Session) -> LLMRecommendationResponse:
        """
        Persist a recommendation to the database.
        
        Args:
            upload_id: Upload ID
            policy_id: Policy ID
            policy_name: Policy name
            recommendations: List of recommendations
            rationale: Rationale text
            db: Database session
            
        Returns:
            LLMRecommendationResponse
        """
        rec = upsert_llm_recommendation(
            db=db,
            upload_id=upload_id,
            policy_id=policy_id,
            policy_name=policy_name,
            recommendations=recommendations,
            rationale=rationale,
        )
        
        return LLMRecommendationResponse(
            upload_id=rec.upload_id,
            policy_id=rec.policy_id,
            policy_name=rec.policy_name,
            recommendations=rec.recommendations,
            rationale=rec.rationale,
            created_at=rec.created_at.isoformat() if rec.created_at else None,
            updated_at=rec.updated_at.isoformat() if rec.updated_at else None,
        )
    
    def regenerate_recommendations(self, policy_context: Dict[str, Any], db: Session) -> LLMRecommendationResponse:
        """
        Regenerate and store recommendations.
        
        Args:
            policy_context: Dictionary containing policy context
            db: Database session
            
        Returns:
            LLMRecommendationResponse
        """
        # Generate recommendations using LLM service
        generated = self.generate_recommendations(policy_context)
        
        # Store in database
        current_upload_id = get_current_upload_id(db)
        upload_id = current_upload_id or ""
        
        rec = upsert_llm_recommendation(
            db=db,
            upload_id=upload_id,
            policy_id=policy_context["policy_id"],
            policy_name=policy_context["policy_name"],
            recommendations=generated["recommendations"],
            rationale=generated["rationale"],
        )
        
        return LLMRecommendationResponse(
            upload_id=rec.upload_id,
            policy_id=rec.policy_id,
            policy_name=rec.policy_name,
            recommendations=rec.recommendations,
            rationale=rec.rationale,
            created_at=rec.created_at.isoformat() if rec.created_at else None,
            updated_at=rec.updated_at.isoformat() if rec.updated_at else None,
        )


# Create a singleton instance
policy_service = PolicyService()
