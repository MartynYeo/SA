import { ProcessedIAMData, UploadMetadata } from './types';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
let LLM_DISABLED_RUNTIME: boolean | null = null;

interface ApiResponse<T> {
  data?: T;
  error?: string;
}

class ApiService {
  private async request<T>(
    endpoint: string,
    options?: RequestInit
  ): Promise<ApiResponse<T>> {
    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        headers: {
          'Content-Type': 'application/json',
          ...options?.headers,
        },
        ...options,
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return {
          error: errorData.detail || `HTTP ${response.status}: ${response.statusText}`
        };
      }

      const data = await response.json();
      return { data };
    } catch (error) {
      console.error('API request failed:', error);
      return {
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      };
    }
  }

  async getRuntimeConfig(): Promise<{ data?: { llm_disabled: boolean }; error?: string }> {
    return this.request(`/api/config`);
  }

  async saveUpload(
    name: string,
    originalFilename: string,
    size: number,
    data: ProcessedIAMData
  ): Promise<{ success: boolean; uploadId?: string; error?: string }> {
    const response = await this.request<{ id: string }>('/api/uploads/', {
      method: 'POST',
      body: JSON.stringify({
        name,
        original_filename: originalFilename,
        size,
        data,
      }),
    });

    if (response.error) {
      return { success: false, error: response.error };
    }

    return { success: true, uploadId: response.data?.id };
  }

  async getUpload(uploadId: string): Promise<{ data?: ProcessedIAMData; error?: string }> {
    return this.request<ProcessedIAMData>(`/api/uploads/${uploadId}`);
  }

  async getAllUploads(): Promise<{ data?: UploadMetadata[]; error?: string }> {
    const response = await this.request<UploadMetadata[]>('/api/uploads/');

    if (response.error) {
      return { error: response.error };
    }

    return { data: response.data };
  }

  async deleteUpload(uploadId: string): Promise<{ success: boolean; error?: string }> {
    const response = await this.request('/api/uploads/' + uploadId, {
      method: 'DELETE',
    });

    if (response.error) {
      return { success: false, error: response.error };
    }

    return { success: true };
  }

  async getCurrentUploadId(): Promise<{ uploadId?: string | null; error?: string }> {
    const response = await this.request<{ upload_id: string | null }>('/api/uploads/current/id');

    if (response.error) {
      return { error: response.error };
    }

    return { uploadId: response.data?.upload_id };
  }

  async setCurrentUploadId(uploadId: string | null): Promise<{ success: boolean; error?: string }> {
    if (!uploadId) {
      return { success: true }; // No-op for now
    }

    const response = await this.request(`/api/uploads/current/${uploadId}`, {
      method: 'POST',
    });

    if (response.error) {
      return { success: false, error: response.error };
    }

    return { success: true };
  }

  async getUser(userId: string): Promise<{ data?: any; error?: string }> {
    return this.request(`/api/iam/users/${userId}`);
  }

  async getRole(roleId: string): Promise<{ data?: any; error?: string }> {
    return this.request(`/api/iam/roles/${roleId}`);
  }

  async getPolicy(policyId: string): Promise<{ data?: any; error?: string }> {
    return this.request(`/api/iam/policies/${policyId}`);
  }

  async getGroup(groupId: string): Promise<{ data?: any; error?: string }> {
    return this.request(`/api/iam/groups/${groupId}`);
  }

  async getLLMRecommendations(input: {
    policyName: string;
    policyId: string;
    statements: any[];
    detectedFlags: any[];
    organizationContext?: string;
  }): Promise<{ data?: { recommendations: string[]; rationale?: string }; error?: string }> {
    if (LLM_DISABLED_RUNTIME === null) {
      const cfg = await this.getRuntimeConfig();
      LLM_DISABLED_RUNTIME = cfg.data?.llm_disabled ?? false;
    }
    if (LLM_DISABLED_RUNTIME) return { error: 'LLM is disabled' };
    return this.request(`/api/llm/recommendations`, {
      method: 'POST',
      body: JSON.stringify({
        policy: {
          policy_name: input.policyName,
          policy_id: input.policyId,
          statements: input.statements,
          detected_flags: input.detectedFlags,
        },
        organization_context: input.organizationContext || '',
      }),
    });
  }

  async getStoredLLMRecommendation(uploadId: string, policyId: string): Promise<{ data?: { upload_id: string; policy_id: string; policy_name: string; recommendations: string[]; rationale?: string; created_at?: string; updated_at?: string }; error?: string }> {
    if (LLM_DISABLED_RUNTIME === null) {
      const cfg = await this.getRuntimeConfig();
      LLM_DISABLED_RUNTIME = cfg.data?.llm_disabled ?? false;
    }
    if (LLM_DISABLED_RUNTIME) return { error: 'LLM is disabled' };
    return this.request(`/api/llm/recommendations/${uploadId}/${policyId}`);
  }

  async persistLLMRecommendation(input: { uploadId: string; policyId: string; policyName: string; recommendations: string[]; rationale?: string }): Promise<{ data?: { upload_id: string; policy_id: string; policy_name: string; recommendations: string[]; rationale?: string; created_at?: string; updated_at?: string }; error?: string }> {
    if (LLM_DISABLED_RUNTIME === null) {
      const cfg = await this.getRuntimeConfig();
      LLM_DISABLED_RUNTIME = cfg.data?.llm_disabled ?? false;
    }
    if (LLM_DISABLED_RUNTIME) return { error: 'LLM is disabled' };
    return this.request(`/api/llm/recommendations/persist`, {
      method: 'POST',
      body: JSON.stringify({
        upload_id: input.uploadId,
        policy_id: input.policyId,
        policy_name: input.policyName,
        recommendations: input.recommendations,
        rationale: input.rationale || null,
      }),
    });
  }

  async regenerateLLMRecommendation(input: {
    policyName: string;
    policyId: string;
    statements: any[];
    detectedFlags: any[];
    organizationContext?: string;
  }): Promise<{ data?: { upload_id: string; policy_id: string; policy_name: string; recommendations: string[]; rationale?: string; created_at?: string; updated_at?: string }; error?: string }> {
    if (LLM_DISABLED_RUNTIME === null) {
      const cfg = await this.getRuntimeConfig();
      LLM_DISABLED_RUNTIME = cfg.data?.llm_disabled ?? false;
    }
    if (LLM_DISABLED_RUNTIME) return { error: 'LLM is disabled' };
    return this.request(`/api/llm/recommendations/regenerate`, {
      method: 'POST',
      body: JSON.stringify({
        policy: {
          policy_name: input.policyName,
          policy_id: input.policyId,
          statements: input.statements,
          detected_flags: input.detectedFlags,
        },
        organization_context: input.organizationContext || '',
      }),
    });
  }

  async generateRecommendedPolicy(input: {
    policyName: string;
    policyId: string;
    statements: any[];
    detectedFlags: any[];
    organizationContext?: string;
  }): Promise<{ data?: { policy_document: Record<string, any>; explanation?: string }; error?: string }> {
    if (LLM_DISABLED_RUNTIME === null) {
      const cfg = await this.getRuntimeConfig();
      LLM_DISABLED_RUNTIME = cfg.data?.llm_disabled ?? false;
    }
    if (LLM_DISABLED_RUNTIME) return { error: 'LLM is disabled' };
    return this.request(`/api/llm/recommended-policy`, {
      method: 'POST',
      body: JSON.stringify({
        policy: {
          policy_name: input.policyName,
          policy_id: input.policyId,
          statements: input.statements,
          detected_flags: input.detectedFlags,
        },
        organization_context: input.organizationContext || '',
      }),
    });
  }

  async getStoredRecommendedPolicy(uploadId: string, policyId: string): Promise<{ data?: { upload_id: string; policy_id: string; policy_name: string; policy_document: Record<string, any>; explanation?: string; created_at?: string; updated_at?: string }; error?: string }> {
    if (LLM_DISABLED_RUNTIME === null) {
      const cfg = await this.getRuntimeConfig();
      LLM_DISABLED_RUNTIME = cfg.data?.llm_disabled ?? false;
    }
    if (LLM_DISABLED_RUNTIME) return { error: 'LLM is disabled' };
    return this.request(`/api/llm/recommended-policy/${uploadId}/${policyId}`);
  }

  async persistRecommendedPolicy(input: { uploadId: string; policyId: string; policyName: string; policyDocument: Record<string, any>; explanation?: string }): Promise<{ data?: { upload_id: string; policy_id: string; policy_name: string; policy_document: Record<string, any>; explanation?: string; created_at?: string; updated_at?: string }; error?: string }> {
    if (LLM_DISABLED_RUNTIME === null) {
      const cfg = await this.getRuntimeConfig();
      LLM_DISABLED_RUNTIME = cfg.data?.llm_disabled ?? false;
    }
    if (LLM_DISABLED_RUNTIME) return { error: 'LLM is disabled' };
    return this.request(`/api/llm/recommended-policy/persist`, {
      method: 'POST',
      body: JSON.stringify({
        upload_id: input.uploadId,
        policy_id: input.policyId,
        policy_name: input.policyName,
        policy_document: input.policyDocument,
        explanation: input.explanation || null,
      }),
    });
  }

  async regenerateRecommendedPolicy(input: {
    policyName: string;
    policyId: string;
    statements: any[];
    detectedFlags: any[];
    organizationContext?: string;
  }): Promise<{ data?: { upload_id: string; policy_id: string; policy_name: string; policy_document: Record<string, any>; explanation?: string; created_at?: string; updated_at?: string }; error?: string }> {
    if (LLM_DISABLED_RUNTIME === null) {
      const cfg = await this.getRuntimeConfig();
      LLM_DISABLED_RUNTIME = cfg.data?.llm_disabled ?? false;
    }
    if (LLM_DISABLED_RUNTIME) return { error: 'LLM is disabled' };
    return this.request(`/api/llm/recommended-policy/regenerate`, {
      method: 'POST',
      body: JSON.stringify({
        policy: {
          policy_name: input.policyName,
          policy_id: input.policyId,
          statements: input.statements,
          detected_flags: input.detectedFlags,
        },
        organization_context: input.organizationContext || '',
      }),
    });
  }

  async generateAttackPath(input: {
    policyName: string;
    policyId: string;
    statements: any[];
    detectedFlags: any[];
    organizationContext?: string;
  }): Promise<{ data?: { upload_id: string; policy_id: string; policy_name: string; attack_scenarios: any[]; impact_assessment?: string; created_at?: string; updated_at?: string }; error?: string }> {
    if (LLM_DISABLED_RUNTIME === null) {
      const cfg = await this.getRuntimeConfig();
      LLM_DISABLED_RUNTIME = cfg.data?.llm_disabled ?? false;
    }
    if (LLM_DISABLED_RUNTIME) return { error: 'LLM is disabled' };
    return this.request(`/api/llm/attack-path`, {
      method: 'POST',
      body: JSON.stringify({
        policy: {
          policy_name: input.policyName,
          policy_id: input.policyId,
          statements: input.statements,
          detected_flags: input.detectedFlags,
        },
        organization_context: input.organizationContext || '',
      }),
    });
  }

  async getStoredAttackPath(uploadId: string, policyId: string): Promise<{ data?: { upload_id: string; policy_id: string; policy_name: string; attack_scenarios: any[]; impact_assessment?: string; created_at?: string; updated_at?: string }; error?: string }> {
    if (LLM_DISABLED_RUNTIME === null) {
      const cfg = await this.getRuntimeConfig();
      LLM_DISABLED_RUNTIME = cfg.data?.llm_disabled ?? false;
    }
    if (LLM_DISABLED_RUNTIME) return { error: 'LLM is disabled' };
    return this.request(`/api/llm/attack-path/${uploadId}/${policyId}`);
  }

  async persistAttackPath(input: { uploadId: string; policyId: string; policyName: string; attackScenarios: any[]; impactAssessment?: string }): Promise<{ data?: { upload_id: string; policy_id: string; policy_name: string; attack_scenarios: any[]; impact_assessment?: string; created_at?: string; updated_at?: string }; error?: string }> {
    if (LLM_DISABLED_RUNTIME === null) {
      const cfg = await this.getRuntimeConfig();
      LLM_DISABLED_RUNTIME = cfg.data?.llm_disabled ?? false;
    }
    if (LLM_DISABLED_RUNTIME) return { error: 'LLM is disabled' };
    return this.request(`/api/llm/attack-path/persist`, {
      method: 'POST',
      body: JSON.stringify({
        upload_id: input.uploadId,
        policy_id: input.policyId,
        policy_name: input.policyName,
        attack_scenarios: input.attackScenarios,
        impact_assessment: input.impactAssessment || null,
      }),
    });
  }

  async regenerateAttackPath(input: {
    policyName: string;
    policyId: string;
    statements: any[];
    detectedFlags: any[];
    organizationContext?: string;
  }): Promise<{ data?: { upload_id: string; policy_id: string; policy_name: string; attack_scenarios: any[]; impact_assessment?: string; created_at?: string; updated_at?: string }; error?: string }> {
    if (LLM_DISABLED_RUNTIME === null) {
      const cfg = await this.getRuntimeConfig();
      LLM_DISABLED_RUNTIME = cfg.data?.llm_disabled ?? false;
    }
    if (LLM_DISABLED_RUNTIME) return { error: 'LLM is disabled' };
    return this.request(`/api/llm/attack-path/regenerate`, {
      method: 'POST',
      body: JSON.stringify({
        policy: {
          policy_name: input.policyName,
          policy_id: input.policyId,
          statements: input.statements,
          detected_flags: input.detectedFlags,
        },
        organization_context: input.organizationContext || '',
      }),
    });
  }
}

export const apiService = new ApiService();
