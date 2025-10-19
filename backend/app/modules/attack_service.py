"""
Attack Service Module

Handles attack path analysis business logic including attack scenario generation,
attack path processing, and database operations for attack paths.
"""

from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.crud import (
    upsert_attack_path, 
    get_attack_path, 
    get_current_upload_id
)
from app.schemas import AttackPathResponse
from app.modules.llm_service import llm_service


class AttackService:
    """Service class for handling attack path analysis operations."""
    
    def __init__(self):
        self.llm_service = llm_service
    
    def generate_attack_path(self, policy_context: Dict[str, Any], db: Session) -> AttackPathResponse:
        """
        Generate attack path scenarios and store them in the database.
        
        Args:
            policy_context: Dictionary containing policy context and security issues
            db: Database session
            
        Returns:
            AttackPathResponse
        """
        # Generate attack scenarios using LLM service
        result = self.llm_service.generate_attack_path(policy_context)
        
        # Store the attack path in the database
        current_upload_id = get_current_upload_id(db)
        if current_upload_id:
            stored_attack_path = upsert_attack_path(
                db=db,
                upload_id=current_upload_id,
                policy_id=policy_context["policy_context"]["policy_id"],
                policy_name=policy_context["policy_context"]["policy_name"],
                attack_scenarios=result["attack_scenarios"],
                impact_assessment=result["impact_assessment"],
            )
            return AttackPathResponse(
                upload_id=stored_attack_path.upload_id,
                policy_id=stored_attack_path.policy_id,
                policy_name=stored_attack_path.policy_name,
                attack_scenarios=stored_attack_path.attack_scenarios,
                impact_assessment=stored_attack_path.impact_assessment,
                created_at=stored_attack_path.created_at.isoformat() if stored_attack_path.created_at else None,
                updated_at=stored_attack_path.updated_at.isoformat() if stored_attack_path.updated_at else None,
            )
        else:
            # Fallback if no current upload
            return AttackPathResponse(
                upload_id="",
                policy_id=policy_context["policy_context"]["policy_id"],
                policy_name=policy_context["policy_context"]["policy_name"],
                attack_scenarios=result["attack_scenarios"],
                impact_assessment=result["impact_assessment"]
            )
    
    def get_stored_attack_path(self, upload_id: str, policy_id: str, db: Session) -> Optional[AttackPathResponse]:
        """
        Get a stored attack path analysis from the database.
        
        Args:
            upload_id: Upload ID
            policy_id: Policy ID
            db: Database session
            
        Returns:
            AttackPathResponse or None if not found
        """
        attack_path = get_attack_path(db, upload_id, policy_id)
        if not attack_path:
            return None
        
        return AttackPathResponse(
            upload_id=attack_path.upload_id,
            policy_id=attack_path.policy_id,
            policy_name=attack_path.policy_name,
            attack_scenarios=attack_path.attack_scenarios,
            impact_assessment=attack_path.impact_assessment,
            created_at=attack_path.created_at.isoformat() if attack_path.created_at else None,
            updated_at=attack_path.updated_at.isoformat() if attack_path.updated_at else None,
        )
    
    def persist_attack_path(self, upload_id: str, policy_id: str, policy_name: str, 
                          attack_scenarios: List[Dict[str, Any]], impact_assessment: Optional[str], 
                          db: Session) -> AttackPathResponse:
        """
        Persist an attack path analysis to the database.
        
        Args:
            upload_id: Upload ID
            policy_id: Policy ID
            policy_name: Policy name
            attack_scenarios: List of attack scenarios
            impact_assessment: Impact assessment text
            db: Database session
            
        Returns:
            AttackPathResponse
        """
        attack_path = upsert_attack_path(
            db=db,
            upload_id=upload_id,
            policy_id=policy_id,
            policy_name=policy_name,
            attack_scenarios=attack_scenarios,
            impact_assessment=impact_assessment,
        )
        
        return AttackPathResponse(
            upload_id=attack_path.upload_id,
            policy_id=attack_path.policy_id,
            policy_name=attack_path.policy_name,
            attack_scenarios=attack_path.attack_scenarios,
            impact_assessment=attack_path.impact_assessment,
            created_at=attack_path.created_at.isoformat() if attack_path.created_at else None,
            updated_at=attack_path.updated_at.isoformat() if attack_path.updated_at else None,
        )
    
    def regenerate_attack_path(self, policy_context: Dict[str, Any], db: Session) -> AttackPathResponse:
        """
        Regenerate and store an attack path analysis.
        
        Args:
            policy_context: Dictionary containing policy context
            db: Database session
            
        Returns:
            AttackPathResponse
        """
        # Generate the attack path (which will automatically store it)
        generated = self.generate_attack_path(policy_context, db)
        
        # Return the stored result with timestamps
        return generated


# Create a singleton instance
attack_service = AttackService()
