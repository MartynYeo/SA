"""
LLM Service Module

Handles all interactions with the Gemini LLM API for generating recommendations,
policy improvements, and attack path analysis.
"""

from typing import Any, Dict, List, Optional
import json
import re

from app.config import settings

try:
    import google.generativeai as genai
except Exception:  # pragma: no cover
    genai = None  # type: ignore


class LLMService:
    """Service class for handling LLM operations with Gemini API."""
    
    def __init__(self):
        self.model_name = "gemini-flash-latest"
        self._configure_genai()
    
    def _configure_genai(self):
        """Configure the Gemini API with the API key."""
        if genai is None:
            raise RuntimeError("Gemini SDK not available on server")
        
        if not settings.gemini_api_key:
            raise RuntimeError("Gemini API key is not configured")
        
        genai.configure(api_key=settings.gemini_api_key)
    
    def _get_model(self):
        """Get the configured Gemini model."""
        return genai.GenerativeModel(self.model_name)
    
    def generate_recommendations(self, policy_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate LLM-backed remediation recommendations using Gemini.
        
        Args:
            policy_context: Dictionary containing policy information and detected flags
            
        Returns:
            Dictionary with recommendations and rationale
        """
        system_prompt = (
            "You are a senior cloud security engineer. Given AWS IAM policy statements "
            "and detected risky flags, produce specific remediation recommendations. "
            "Favor least-privilege, resource scoping, and conditional constraints. "
            "Return clear, concise bullet recommendations. Include a short rationale paragraph."
            "The recommendations should be formatted in markdown format for easy readability."
        )

        prompt_parts = [
            system_prompt,
            "\nContext:",
            str(policy_context),
            "\nOutput format:\n- recommendations: 3-7 bullets\n- rationale: 1 short paragraph",
        ]
        
        try:
            model = self._get_model()
            resp = model.generate_content("\n".join(prompt_parts))
            text = getattr(resp, "text", None) or ""
        except Exception as e:
            raise RuntimeError(f"Gemini call failed: {e}")

        # Parse the response
        recommendations: List[str] = []
        rationale: Optional[str] = None

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        in_recs = True
        rationale_lines: List[str] = []
        
        for line in lines:
            if line.lower().startswith("rationale"):
                in_recs = False
                continue
            if in_recs and (line.startswith("-") or line.startswith("•")):
                recommendations.append(line.lstrip("-• "))
            elif not in_recs:
                rationale_lines.append(line)

        if not recommendations:
            # Fallback: return whole text as rationale if parsing fails
            rationale = text.strip() or "LLM did not return content"
        else:
            rationale = " ".join(rationale_lines) if rationale_lines else None

        return {
            "recommendations": recommendations[:7],
            "rationale": rationale
        }
    
    def generate_recommended_policy(self, policy_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a recommended policy document using Gemini based on security analysis.
        
        Args:
            policy_context: Dictionary containing original policy and security issues
            
        Returns:
            Dictionary with policy_document and explanation
        """
        system_prompt = (
            "You are a senior cloud security engineer. Given an AWS IAM policy with detected "
            "security issues, generate an improved policy document that addresses the security "
            "concerns while maintaining the necessary functionality. "
            "Return a valid JSON policy document and a brief explanation of changes made. "
            "Focus on least-privilege principles, resource scoping, and conditional constraints. "
            "The policy should be production-ready and follow AWS IAM best practices."
        )

        prompt_parts = [
            system_prompt,
            "\nOriginal Policy Context:",
            str(policy_context),
            "\nOutput format:\n"
            "POLICY_JSON:\n"
            "{\n"
            '  "Version": "2012-10-17",\n'
            '  "Statement": [...]\n'
            "}\n\n"
            "EXPLANATION:\n"
            "Brief explanation of changes made and security improvements."
        ]
        
        try:
            model = self._get_model()
            resp = model.generate_content("\n".join(prompt_parts))
            text = getattr(resp, "text", None) or ""
        except Exception as e:
            raise RuntimeError(f"Gemini call failed: {e}")

        # Parse the response to extract JSON policy and explanation
        try:
            # Extract JSON policy - handle both raw JSON and markdown code blocks
            json_match = re.search(r'POLICY_JSON:\s*(?:```json\s*)?(\{.*?\})\s*(?:```\s*)?(?=EXPLANATION:|$)', text, re.DOTALL)
            if json_match:
                policy_json_str = json_match.group(1).strip()
                policy_document = json.loads(policy_json_str)
            else:
                # Fallback: try to find any JSON object in the response, including in code blocks
                json_match = re.search(r'(?:```json\s*)?(\{.*?"Version".*?\})(?:\s*```)?', text, re.DOTALL)
                if json_match:
                    policy_document = json.loads(json_match.group(1).strip())
                else:
                    raise ValueError("No valid policy JSON found in response")
            
            # Extract explanation
            explanation_match = re.search(r'EXPLANATION:\s*(.*?)$', text, re.DOTALL)
            explanation = explanation_match.group(1).strip() if explanation_match else None
            
            return {
                "policy_document": policy_document,
                "explanation": explanation
            }
            
        except (json.JSONDecodeError, ValueError) as e:
            raise RuntimeError(f"Failed to parse recommended policy from LLM response: {e}")
    
    def generate_attack_path(self, policy_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate attack path scenarios showing how an attacker could exploit the policy.
        
        Args:
            policy_context: Dictionary containing policy context and security issues
            
        Returns:
            Dictionary with attack_scenarios and impact_assessment
        """
        system_prompt = (
            "You are a senior cloud security penetration tester. Given an AWS IAM policy with detected "
            "security issues, generate realistic attack scenarios that demonstrate how a malicious actor "
            "could exploit these permissions. For each scenario, provide:\n"
            "1. Attack scenario description\n"
            "2. Specific AWS CLI commands that would be used\n"
            "3. Potential impact of the attack\n"
            "4. Prerequisites for the attack\n\n"
            "Focus on practical, real-world attack vectors that demonstrate the business impact. "
            "Be specific about the AWS CLI commands and explain the attack chain step by step. "
            "Consider privilege escalation, data exfiltration, resource manipulation, and lateral movement."
        )

        prompt_parts = [
            system_prompt,
            "\nPolicy Context:",
            str(policy_context),
            "\nOutput format (JSON):\n"
            "{\n"
            '  "attack_scenarios": [\n'
            "    {\n"
            '      "title": "Attack scenario name",\n'
            '      "description": "Detailed description of the attack",\n'
            '      "prerequisites": "What the attacker needs",\n'
            '      "steps": [\n'
            "        {\n"
            '          "step": 1,\n'
            '          "description": "Step description",\n'
            '          "aws_cli_command": "aws command here",\n'
            '          "explanation": "Why this command works"\n'
            "        }\n"
            "      ],\n"
            '      "impact": "Business impact description",\n'
            '      "severity": "HIGH|MEDIUM|LOW"\n'
            "    }\n"
            "  ],\n"
            '  "impact_assessment": "Overall security impact summary"\n'
            "}"
        ]
        
        try:
            model = self._get_model()
            resp = model.generate_content("\n".join(prompt_parts))
            text = getattr(resp, "text", None) or ""
        except Exception as e:
            raise RuntimeError(f"Gemini call failed: {e}")

        # Parse the response to extract attack scenarios
        try:
            # Try to extract JSON from the response
            json_match = re.search(r'\{.*"attack_scenarios".*\}', text, re.DOTALL)
            if json_match:
                attack_data = json.loads(json_match.group(0))
                attack_scenarios = attack_data.get("attack_scenarios", [])
                impact_assessment = attack_data.get("impact_assessment")
            else:
                # Fallback: create a simple structure from the text
                attack_scenarios = [{
                    "title": "Attack Analysis",
                    "description": text,
                    "prerequisites": "Valid AWS credentials with the analyzed policy permissions",
                    "steps": [],
                    "impact": "Potential security compromise based on policy permissions",
                    "severity": "MEDIUM"
                }]
                impact_assessment = "Unable to parse structured attack scenarios from AI response"
            
            return {
                "attack_scenarios": attack_scenarios,
                "impact_assessment": impact_assessment
            }
            
        except (json.JSONDecodeError, ValueError) as e:
            # Return the raw text as a single scenario
            attack_scenarios = [{
                "title": "Security Analysis",
                "description": text,
                "prerequisites": "Valid AWS credentials",
                "steps": [],
                "impact": "Review the analysis for potential security risks",
                "severity": "MEDIUM"
            }]
            impact_assessment = "Raw analysis provided due to parsing issues"
            
            return {
                "attack_scenarios": attack_scenarios,
                "impact_assessment": impact_assessment
            }


# Create a singleton instance
llm_service = LLMService()
