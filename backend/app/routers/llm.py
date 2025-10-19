from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Any, Dict, List, Optional

from app.config import settings
from app.database import get_db
from app.schemas import LLMRecommendationResponse, RecommendedPolicyResponse, AttackPathResponse
from app.modules.policy_service import policy_service
from app.modules.attack_service import attack_service


router = APIRouter()


class PolicyContext(BaseModel):
    policy_name: str
    policy_id: str
    statements: List[Dict[str, Any]]
    detected_flags: List[Dict[str, Any]]


class RecommendationRequest(BaseModel):
    policy: PolicyContext
    organization_context: Optional[str] = None


class RecommendationResponse(BaseModel):
    recommendations: List[str]
    rationale: Optional[str] = None


class RecommendedPolicyResponse(BaseModel):
    policy_document: Dict[str, Any]
    explanation: Optional[str] = None




@router.post("/recommendations", response_model=RecommendationResponse)
async def generate_recommendations(payload: RecommendationRequest):
    """Generate LLM-backed remediation recommendations using Gemini.

    Expects policy context (name, id, statements, detected flags) and returns
    concise, actionable recommendations tailored to least-privilege hardening.
    """
    if settings.llm_disabled:
        raise HTTPException(status_code=503, detail="LLM is disabled by configuration")
    
    try:
        policy_context = {
            "policy_name": payload.policy.policy_name,
            "policy_id": payload.policy.policy_id,
            "statements": payload.policy.statements,
            "detected_flags": payload.policy.detected_flags,
            "organization_context": payload.organization_context or "",
        }
        
        result = policy_service.generate_recommendations(policy_context)
        return RecommendationResponse(
            recommendations=result["recommendations"],
            rationale=result["rationale"]
        )
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/recommended-policy", response_model=RecommendedPolicyResponse)
async def generate_recommended_policy(payload: RecommendationRequest, db: Session = Depends(get_db)):
    """Generate a recommended policy document using Gemini based on security analysis.
    
    Takes the current policy context and security flags to generate an improved
    policy document that addresses security concerns while maintaining functionality.
    """
    if settings.llm_disabled:
        raise HTTPException(status_code=503, detail="LLM is disabled by configuration")
    
    try:
        policy_context = {
            "original_policy": {
                "policy_name": payload.policy.policy_name,
                "policy_id": payload.policy.policy_id,
                "statements": payload.policy.statements,
            },
            "detected_security_issues": payload.policy.detected_flags,
            "organization_context": payload.organization_context or "",
        }
        
        result = policy_service.generate_recommended_policy(policy_context, db)
        return RecommendedPolicyResponse(
            policy_document=result["policy_document"],
            explanation=result["explanation"]
        )
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/recommended-policy/{upload_id}/{policy_id}", response_model=RecommendedPolicyResponse)
async def get_stored_recommended_policy(upload_id: str, policy_id: str, db: Session = Depends(get_db)):
    """Get a stored recommended policy for a specific upload and policy."""
    if settings.llm_disabled:
        raise HTTPException(status_code=503, detail="LLM is disabled by configuration")
    
    result = policy_service.get_stored_recommended_policy(upload_id, policy_id, db)
    if not result:
        raise HTTPException(status_code=404, detail="Recommended policy not found")
    
    return result


class RecommendedPolicyPersistRequest(BaseModel):
    upload_id: str
    policy_id: str
    policy_name: str
    policy_document: Dict[str, Any]
    explanation: Optional[str] = None


@router.post("/recommended-policy/persist", response_model=RecommendedPolicyResponse)
async def persist_recommended_policy(body: RecommendedPolicyPersistRequest, db: Session = Depends(get_db)):
    """Persist a recommended policy to the database."""
    if settings.llm_disabled:
        raise HTTPException(status_code=503, detail="LLM is disabled by configuration")
    
    return policy_service.persist_recommended_policy(
        body.upload_id,
        body.policy_id,
        body.policy_name,
        body.policy_document,
        body.explanation,
        db
    )


@router.post("/recommended-policy/regenerate", response_model=RecommendedPolicyResponse)
async def regenerate_recommended_policy(payload: RecommendationRequest, db: Session = Depends(get_db)):
    """Regenerate and store a recommended policy."""
    if settings.llm_disabled:
        raise HTTPException(status_code=503, detail="LLM is disabled by configuration")
    
    try:
        policy_context = {
            "original_policy": {
                "policy_name": payload.policy.policy_name,
                "policy_id": payload.policy.policy_id,
                "statements": payload.policy.statements,
            },
            "detected_security_issues": payload.policy.detected_flags,
            "organization_context": payload.organization_context or "",
        }
        
        result = policy_service.regenerate_recommended_policy(policy_context, db)
        return RecommendedPolicyResponse(
            policy_document=result["policy_document"],
            explanation=result["explanation"]
        )
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/attack-path", response_model=AttackPathResponse)
async def generate_attack_path(payload: RecommendationRequest, db: Session = Depends(get_db)):
    """Generate attack path scenarios showing how an attacker could exploit the policy.
    
    Takes the current policy context and security flags to generate realistic
    attack scenarios with AWS CLI commands demonstrating potential abuse.
    """
    if settings.llm_disabled:
        raise HTTPException(status_code=503, detail="LLM is disabled by configuration")
    
    try:
        policy_context = {
            "policy_context": {
                "policy_name": payload.policy.policy_name,
                "policy_id": payload.policy.policy_id,
                "statements": payload.policy.statements,
            },
            "detected_security_issues": payload.policy.detected_flags,
            "organization_context": payload.organization_context or "",
        }
        
        return attack_service.generate_attack_path(policy_context, db)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack-path/{upload_id}/{policy_id}", response_model=AttackPathResponse)
async def get_stored_attack_path(upload_id: str, policy_id: str, db: Session = Depends(get_db)):
    """Get a stored attack path analysis for a specific upload and policy."""
    if settings.llm_disabled:
        raise HTTPException(status_code=503, detail="LLM is disabled by configuration")
    
    result = attack_service.get_stored_attack_path(upload_id, policy_id, db)
    if not result:
        raise HTTPException(status_code=404, detail="Attack path not found")
    
    return result


class AttackPathPersistRequest(BaseModel):
    upload_id: str
    policy_id: str
    policy_name: str
    attack_scenarios: List[Dict[str, Any]]
    impact_assessment: Optional[str] = None


@router.post("/attack-path/persist", response_model=AttackPathResponse)
async def persist_attack_path(body: AttackPathPersistRequest, db: Session = Depends(get_db)):
    """Persist an attack path analysis to the database."""
    if settings.llm_disabled:
        raise HTTPException(status_code=503, detail="LLM is disabled by configuration")
    
    return attack_service.persist_attack_path(
        body.upload_id,
        body.policy_id,
        body.policy_name,
        body.attack_scenarios,
        body.impact_assessment,
        db
    )


@router.post("/attack-path/regenerate", response_model=AttackPathResponse)
async def regenerate_attack_path(payload: RecommendationRequest, db: Session = Depends(get_db)):
    """Regenerate and store an attack path analysis."""
    if settings.llm_disabled:
        raise HTTPException(status_code=503, detail="LLM is disabled by configuration")
    
    try:
        policy_context = {
            "policy_context": {
                "policy_name": payload.policy.policy_name,
                "policy_id": payload.policy.policy_id,
                "statements": payload.policy.statements,
            },
            "detected_security_issues": payload.policy.detected_flags,
            "organization_context": payload.organization_context or "",
        }
        
        return attack_service.regenerate_attack_path(policy_context, db)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/recommendations/{upload_id}/{policy_id}", response_model=LLMRecommendationResponse)
async def get_recommendation(upload_id: str, policy_id: str, db: Session = Depends(get_db)):
    if settings.llm_disabled:
        raise HTTPException(status_code=503, detail="LLM is disabled by configuration")
    
    result = policy_service.get_stored_recommendation(upload_id, policy_id, db)
    if not result:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    
    return result


class PersistRequest(BaseModel):
    upload_id: str
    policy_id: str
    policy_name: str
    recommendations: List[str]
    rationale: Optional[str] = None


@router.post("/recommendations/persist", response_model=LLMRecommendationResponse)
async def persist_recommendation(body: PersistRequest, db: Session = Depends(get_db)):
    if settings.llm_disabled:
        raise HTTPException(status_code=503, detail="LLM is disabled by configuration")
    
    return policy_service.persist_recommendation(
        body.upload_id,
        body.policy_id,
        body.policy_name,
        body.recommendations,
        body.rationale,
        db
    )


@router.post("/recommendations/regenerate", response_model=LLMRecommendationResponse)
async def regenerate_recommendations(payload: RecommendationRequest, db: Session = Depends(get_db)):
    if settings.llm_disabled:
        raise HTTPException(status_code=503, detail="LLM is disabled by configuration")
    
    try:
        policy_context = {
            "policy_name": payload.policy.policy_name,
            "policy_id": payload.policy.policy_id,
            "statements": payload.policy.statements,
            "detected_flags": payload.policy.detected_flags,
            "organization_context": payload.organization_context or "",
        }
        
        return policy_service.regenerate_recommendations(policy_context, db)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


