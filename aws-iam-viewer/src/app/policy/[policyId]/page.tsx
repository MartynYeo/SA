'use client';

import { useEffect, useState } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { CopyField } from '@/components/ui/copy-field';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { ArrowLeft, FileText, Users, Shield, UserCheck, AlertTriangle, AlertCircle, ChevronDown, ChevronRight, Zap } from 'lucide-react';
import { IAMPolicy, ProcessedIAMData, IAMUser, IAMRole, IAMGroup } from '@/lib/types';
import { formatDateTime, findAttachedEntities } from '@/lib/iam-utils';
import { JSONViewer } from '@/components/ui/json-viewer';
import { apiService } from '@/lib/api';
import { analyzePolicy, PolicyAnalysisResult } from '@/lib/policy-analysis';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

export default function PolicyDetailsPage() {
  const [policy, setPolicy] = useState<IAMPolicy | null>(null);
  const [data, setData] = useState<ProcessedIAMData | null>(null);
  const [policyDocument, setPolicyDocument] = useState<Record<string, unknown> | null>(null);
  const [attachedUsers, setAttachedUsers] = useState<IAMUser[]>([]);
  const [attachedRoles, setAttachedRoles] = useState<IAMRole[]>([]);
  const [attachedGroups, setAttachedGroups] = useState<IAMGroup[]>([]);
  const [securityAnalysis, setSecurityAnalysis] = useState<PolicyAnalysisResult | null>(null);
  const router = useRouter();
  const [llmRecs, setLlmRecs] = useState<{ recommendations: string[]; rationale?: string } | null>(null);
  const [llmLoading, setLlmLoading] = useState(false);
  const [llmError, setLlmError] = useState<string | null>(null);
  const params = useParams();
  const policyId = params.policyId as string;
  const [securityAnalysisOpen, setSecurityAnalysisOpen] = useState(true);
  const [recommendedPolicy, setRecommendedPolicy] = useState<{ policy_document: Record<string, any>; explanation?: string } | null>(null);
  const [recommendedPolicyLoading, setRecommendedPolicyLoading] = useState(false);
  const [recommendedPolicyError, setRecommendedPolicyError] = useState<string | null>(null);
  const [attackPath, setAttackPath] = useState<{ attack_scenarios: any[]; impact_assessment?: string } | null>(null);
  const [attackPathLoading, setAttackPathLoading] = useState(false);
  const [attackPathError, setAttackPathError] = useState<string | null>(null);
  const [activeLlmTab, setActiveLlmTab] = useState<'explanation' | 'recommended-policy' | 'attack-path'>('explanation');

  useEffect(() => {
    const loadPolicyData = async () => {
      try {
        const currentResult = await apiService.getCurrentUploadId();
        if (currentResult.error || !currentResult.uploadId) {
          router.push('/');
          return;
        }
        const currentUploadId = currentResult.uploadId;

        const uploadResult = await apiService.getUpload(currentResult.uploadId);
        if (uploadResult.error || !uploadResult.data) {
          router.push('/');
          return;
        }

        const policyData = uploadResult.data.policies[policyId];
        if (!policyData) {
          router.push('/dashboard');
          return;
        }

        setData(uploadResult.data!);
        setPolicy(policyData);

        // Find the default policy version document
        const document = policyData.PolicyVersionList?.find((version: { VersionId: string; Document: Record<string, unknown> }) => 
          version.VersionId === policyData.DefaultVersionId
        )?.Document || null;
        setPolicyDocument(document);

        // Find attached entities
        const { users, roles, groups } = findAttachedEntities(policyData.Arn, uploadResult.data!);
        setAttachedUsers(users);
        setAttachedRoles(roles);
        setAttachedGroups(groups);

        // Perform security analysis
        const analysis = analyzePolicy(policyData);
        setSecurityAnalysis(analysis);

        // Try to load stored recommended policy
        try {
          const cfg = await apiService.getRuntimeConfig();
          const runtimeDisabled = !!cfg.data?.llm_disabled;
          if (!runtimeDisabled) {
            const storedPolicy = await apiService.getStoredRecommendedPolicy(currentUploadId, policyData.PolicyId);
            if (storedPolicy.data) {
              setRecommendedPolicy({
                policy_document: storedPolicy.data.policy_document,
                explanation: storedPolicy.data.explanation,
              });
            }
          }
        } catch (e: any) {
          // Ignore errors when loading stored recommended policy
          console.log('No stored recommended policy found:', e?.message);
        }

        // Try to load stored attack path
        try {
          const cfg = await apiService.getRuntimeConfig();
          const runtimeDisabled = !!cfg.data?.llm_disabled;
          if (!runtimeDisabled) {
            const storedAttackPath = await apiService.getStoredAttackPath(currentUploadId, policyData.PolicyId);
            if (storedAttackPath.data) {
              setAttackPath({
                attack_scenarios: storedAttackPath.data.attack_scenarios,
                impact_assessment: storedAttackPath.data.impact_assessment,
              });
            }
          }
        } catch (e: any) {
          // Ignore errors when loading stored attack path
          console.log('No stored attack path found:', e?.message);
        }

        // Try to load stored LLM Explanation
        try {
          const cfg = await apiService.getRuntimeConfig();
          const runtimeDisabled = !!cfg.data?.llm_disabled;
          if (!runtimeDisabled) {
            const stored = await apiService.getStoredLLMRecommendation(currentResult.uploadId, policyData.PolicyId);
            if (stored.data) {
              setLlmRecs({ recommendations: stored.data.recommendations, rationale: stored.data.rationale });
            }
          }
        } catch (e: any) {
          // Ignore errors when loading stored LLM explanation
          console.log('No stored LLM explanation found:', e?.message);
        }
      } catch (error) {
        console.error('Failed to load policy data:', error);
        router.push('/');
      }
    };

    loadPolicyData();
  }, [policyId, router]);

  const handleGenerateExplanation = async () => {
    if (!policy || !securityAnalysis) return;
    try {
      setLlmLoading(true);
      setLlmError(null);
      const defaultVersion = policy.PolicyVersionList?.find((v: any) => v.VersionId === policy.DefaultVersionId);
      const statements = Array.isArray(defaultVersion?.Document?.Statement) ? defaultVersion!.Document!.Statement : [];
      
      // Use regenerate endpoint if explanation already exists, otherwise generate new
      const resp = llmRecs 
        ? await apiService.regenerateLLMRecommendation({
            policyName: policy.PolicyName,
            policyId: policy.PolicyId,
            statements,
            detectedFlags: securityAnalysis.flags,
          })
        : await apiService.getLLMRecommendations({
        policyName: policy.PolicyName,
        policyId: policy.PolicyId,
        statements,
        detectedFlags: securityAnalysis.flags,
      });
      
      if (resp.error) {
        setLlmError(resp.error);
      } else if (resp.data) {
        setLlmRecs({ recommendations: resp.data.recommendations, rationale: resp.data.rationale });
        
        // If using the generate endpoint (not regenerate), persist the result
        if (!llmRecs) {
          const currentResult = await apiService.getCurrentUploadId();
          if (currentResult.uploadId) {
            await apiService.persistLLMRecommendation({
              uploadId: currentResult.uploadId,
              policyId: policy.PolicyId,
              policyName: policy.PolicyName,
              recommendations: resp.data.recommendations,
              rationale: resp.data.rationale,
            }).catch(() => {});
          }
        }
      }
    } catch (e: any) {
      setLlmError(e?.message || 'Failed to generate explanation');
    } finally {
      setLlmLoading(false);
    }
  };

  const handleGenerateRecommendedPolicy = async () => {
    if (!policy || !securityAnalysis) return;
    try {
      setRecommendedPolicyLoading(true);
      setRecommendedPolicyError(null);
      const defaultVersion = policy.PolicyVersionList?.find((v: any) => v.VersionId === policy.DefaultVersionId);
      const statements = Array.isArray(defaultVersion?.Document?.Statement) ? defaultVersion!.Document!.Statement : [];
      
      // Use regenerate endpoint if policy already exists, otherwise generate new
      const resp = recommendedPolicy 
        ? await apiService.regenerateRecommendedPolicy({
            policyName: policy.PolicyName,
            policyId: policy.PolicyId,
            statements,
            detectedFlags: securityAnalysis.flags,
          })
        : await apiService.generateRecommendedPolicy({
            policyName: policy.PolicyName,
            policyId: policy.PolicyId,
            statements,
            detectedFlags: securityAnalysis.flags,
          });
      
      if (resp.error) {
        setRecommendedPolicyError(resp.error);
      } else if (resp.data) {
        setRecommendedPolicy({
          policy_document: resp.data.policy_document,
          explanation: resp.data.explanation,
        });
      }
    } catch (e: any) {
      setRecommendedPolicyError(e?.message || 'Failed to generate recommended policy');
    } finally {
      setRecommendedPolicyLoading(false);
    }
  };

  const handleGenerateAttackPath = async () => {
    if (!policy || !securityAnalysis) return;
    try {
      setAttackPathLoading(true);
      setAttackPathError(null);
      const defaultVersion = policy.PolicyVersionList?.find((v: any) => v.VersionId === policy.DefaultVersionId);
      const statements = Array.isArray(defaultVersion?.Document?.Statement) ? defaultVersion!.Document!.Statement : [];
      
      // Use regenerate endpoint if attack path already exists, otherwise generate new
      const resp = attackPath 
        ? await apiService.regenerateAttackPath({
            policyName: policy.PolicyName,
            policyId: policy.PolicyId,
            statements,
            detectedFlags: securityAnalysis.flags,
          })
        : await apiService.generateAttackPath({
            policyName: policy.PolicyName,
            policyId: policy.PolicyId,
            statements,
            detectedFlags: securityAnalysis.flags,
          });
      
      if (resp.error) {
        setAttackPathError(resp.error);
      } else if (resp.data) {
        setAttackPath({
          attack_scenarios: resp.data.attack_scenarios,
          impact_assessment: resp.data.impact_assessment,
        });
      }
    } catch (e: any) {
      setAttackPathError(e?.message || 'Failed to generate attack path analysis');
    } finally {
      setAttackPathLoading(false);
    }
  };

  if (!policy || !data) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center space-x-4">
        <Button variant="outline" onClick={() => router.back()}>
          <ArrowLeft className="h-4 w-4 mr-2" />
          Back
        </Button>
        <div>
          <h1 className="text-3xl font-bold">Policy Details: {policy.PolicyName}</h1>
          <p className="text-muted-foreground">Comprehensive policy information and attachments</p>
        </div>
      </div>

      {/* Quick Info Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-muted/50 rounded-lg p-4">
          <div className="text-sm text-muted-foreground">Attachment Count</div>
          <div className="text-2xl font-bold">{policy.AttachmentCount}</div>
        </div>
        <div className="bg-muted/50 rounded-lg p-4">
          <div className="text-sm text-muted-foreground">Attachable</div>
          <Badge variant={policy.IsAttachable ? "default" : "destructive"} className="mt-1">
            {policy.IsAttachable ? "Yes" : "No"}
          </Badge>
        </div>
        <div className="bg-muted/50 rounded-lg p-4">
          <div className="text-sm text-muted-foreground">Security Status</div>
          <Badge variant={securityAnalysis?.isHighRisk ? "destructive" : "default"} className="mt-1">
            {securityAnalysis?.isHighRisk ? "High Risk" : "Secure"}
          </Badge>
        </div>
        <div className="bg-muted/50 rounded-lg p-4">
          <div className="text-sm text-muted-foreground">Created</div>
          <div className="text-sm font-medium">{formatDateTime(policy.CreateDate)}</div>
        </div>
      </div>

      {/* Security Analysis - Collapsible */}
      {securityAnalysis && (
        <Collapsible open={securityAnalysisOpen} onOpenChange={setSecurityAnalysisOpen}>
          <CollapsibleTrigger asChild>
            <Button variant="ghost" className="w-full justify-between p-4 h-auto bg-muted/30 hover:bg-muted/50">
              <div className="flex items-center space-x-2">
                <AlertTriangle className={`h-5 w-5 ${securityAnalysis.isHighRisk ? 'text-red-600' : 'text-green-600'}`} />
                <span className="text-lg font-semibold">Security Analysis</span>
                {securityAnalysis.isHighRisk && (
                  <Badge variant="destructive">HIGH RISK</Badge>
                )}
                {securityAnalysis.flags.length > 0 && (
                  <Badge variant="secondary">{securityAnalysis.flags.length} issue{securityAnalysis.flags.length !== 1 ? 's' : ''}</Badge>
                )}
              </div>
              {securityAnalysisOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="mt-2">
            {securityAnalysis.flags.length > 0 ? (
              <div className="space-y-3">
                {securityAnalysis.flags.map((flag, index) => (
                  <div key={index} className={`border rounded-lg p-4 ${
                    flag.severity === 'HIGH' ? 'border-red-200 bg-red-50' : 
                    flag.severity === 'MEDIUM' ? 'border-yellow-200 bg-yellow-50' : 
                    'border-blue-200 bg-blue-50'
                  }`}>
                    <div className="flex items-start space-x-3">
                      <AlertCircle className={`h-5 w-5 mt-0.5 ${
                        flag.severity === 'HIGH' ? 'text-red-600' : 
                        flag.severity === 'MEDIUM' ? 'text-yellow-600' : 
                        'text-blue-600'
                      }`} />
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-2">
                          <h3 className="font-semibold">{flag.title}</h3>
                          <Badge variant={flag.severity === 'HIGH' ? 'destructive' : flag.severity === 'MEDIUM' ? 'secondary' : 'outline'}>
                            {flag.severity}
                          </Badge>
                        </div>
                        <p className="text-sm text-muted-foreground mb-2">{flag.description}</p>
                        <div className="bg-white/50 rounded-md p-2">
                          <p className="text-xs font-medium text-blue-800 mb-1">Recommendation:</p>
                          <p className="text-xs text-blue-700">{flag.recommendation}</p>
                        </div>
                        {flag.affectedStatements.length > 0 && (
                          <div className="mt-2">
                            <p className="text-xs text-muted-foreground">
                              Affected statement(s): {flag.affectedStatements.join(', ')}
                            </p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                <div className="flex items-center space-x-3">
                  <Shield className="h-6 w-6 text-green-600" />
                  <div>
                    <h3 className="font-semibold text-green-800">No Security Issues Found</h3>
                    <p className="text-sm text-green-700">This policy appears to be secure and follows security best practices.</p>
                  </div>
                </div>
              </div>
            )}
          </CollapsibleContent>
        </Collapsible>
      )}


      {/* LLM Features Navigation */}
      <div className="bg-gradient-to-r from-blue-50 to-purple-50 border border-blue-200 rounded-lg p-4 mb-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-blue-900">AI-Powered Analysis</h2>
          <div className="flex space-x-2">
            <Button
              variant={activeLlmTab === 'explanation' ? 'default' : 'outline'}
              size="sm"
              onClick={() => setActiveLlmTab('explanation')}
              className="flex items-center space-x-2"
            >
              <AlertCircle className="h-4 w-4" />
              <span>Explanation</span>
              {llmLoading && activeLlmTab === 'explanation' && (
                <Badge variant="secondary" className="ml-1">Loading...</Badge>
              )}
            </Button>
            <Button
              variant={activeLlmTab === 'recommended-policy' ? 'default' : 'outline'}
              size="sm"
              onClick={() => setActiveLlmTab('recommended-policy')}
              className="flex items-center space-x-2"
            >
              <Shield className="h-4 w-4" />
              <span>Recommended Policy</span>
              {recommendedPolicyLoading && activeLlmTab === 'recommended-policy' && (
                <Badge variant="secondary" className="ml-1">Loading...</Badge>
              )}
            </Button>
            <Button
              variant={activeLlmTab === 'attack-path' ? 'default' : 'outline'}
              size="sm"
              onClick={() => setActiveLlmTab('attack-path')}
              className="flex items-center space-x-2"
            >
              <Zap className="h-4 w-4" />
              <span>Attack Path</span>
              {attackPathLoading && activeLlmTab === 'attack-path' && (
                <Badge variant="secondary" className="ml-1">Loading...</Badge>
              )}
            </Button>
          </div>
            </div>

        {/* LLM Content Area */}
        <div className="bg-white rounded-lg border p-4 min-h-[200px]">
          {activeLlmTab === 'explanation' && (
            <div>
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-semibold">Security Analysis Explanation</h3>
                <Button 
                  onClick={handleGenerateExplanation} 
                  variant="outline" 
                  size="sm" 
                  disabled={llmLoading || !policy || !securityAnalysis}
                >
                  {llmLoading ? 'Generating...' : llmRecs ? 'Regenerate' : 'Generate Explanation'}
              </Button>
            </div>
              
            {llmLoading ? (
                <div className="text-center py-8">
                  <p className="text-muted-foreground">Generating explanation with Gemini...</p>
                </div>
            ) : llmError ? (
                <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                  <p className="text-red-600">{llmError}</p>
                </div>
            ) : llmRecs ? (
              <div className="space-y-4">
                {llmRecs.recommendations && llmRecs.recommendations.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2">Recommendations:</h4>
                  <ul className="list-disc pl-6 space-y-2">
                    {llmRecs.recommendations.map((rec, idx) => (
                      <li key={idx} className="text-sm">
                            <ReactMarkdown remarkPlugins={[remarkGfm]}
                              components={{
                                a: ({...props}: any) => <a {...props} className="text-blue-600 hover:underline" />,
                                code: ({inline, children, ...props}: any) => {
                                  const content = Array.isArray(children) ? children.join('') : String(children);
                                  if (inline || !content.includes('\n')) {
                                    return <code className="rounded bg-muted px-1 py-0.5 text-xs font-mono">{children}</code>;
                                  }
                                  return <pre className="bg-muted rounded p-3 overflow-x-auto text-sm"><code>{children}</code></pre>;
                                },
                                ul: ({...props}: any) => <ul {...props} className="list-disc pl-6 my-2 space-y-1" />,
                                ol: ({...props}: any) => <ol {...props} className="list-decimal pl-6 my-2 space-y-1" />,
                                p: ({...props}: any) => <p {...props} className="my-2 leading-relaxed" />,
                                li: ({...props}: any) => <li {...props} className="mb-1" />,
                              }}
                            >{rec}</ReactMarkdown>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {llmRecs.rationale && (
                    <div>
                      <h4 className="font-medium mb-2">Rationale:</h4>
                      <div className="text-sm bg-gray-50 rounded-lg p-3">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}
                          components={{
                            a: ({...props}: any) => <a {...props} className="text-blue-600 hover:underline" />,
                            code: ({inline, children, ...props}: any) => {
                              const content = Array.isArray(children) ? children.join('') : String(children);
                              if (inline || !content.includes('\n')) {
                                return <code className="rounded bg-muted px-1 py-0.5 text-xs font-mono">{children}</code>;
                              }
                              return <pre className="bg-muted rounded p-3 overflow-x-auto text-sm"><code>{children}</code></pre>;
                            },
                            ul: ({...props}: any) => <ul {...props} className="list-disc pl-6 my-2 space-y-1" />,
                            ol: ({...props}: any) => <ol {...props} className="list-decimal pl-6 my-2 space-y-1" />,
                            p: ({...props}: any) => <p {...props} className="my-2 leading-relaxed" />,
                            li: ({...props}: any) => <li {...props} className="mb-1" />,
                          }}
                        >{llmRecs.rationale}</ReactMarkdown>
                      </div>
                    </div>
                  )}
                  {!llmRecs.recommendations?.length && !llmRecs.rationale && (
                    <p className="text-muted-foreground">Received response but no structured recommendations. Please check backend output.</p>
                  )}
                </div>
              ) : (
                <div className="text-center py-8">
                  <p className="text-muted-foreground mb-4">
                    Generate AI-powered security analysis and recommendations for this policy.
                  </p>
                  <p className="text-sm text-muted-foreground">
                    The AI will analyze the policy permissions and security issues to provide 
                    detailed explanations and actionable recommendations.
                  </p>
                </div>
              )}
            </div>
          )}

          {activeLlmTab === 'recommended-policy' && (
            <div>
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-semibold">LLM-Generated Recommended Policy</h3>
                <Button 
                  onClick={handleGenerateRecommendedPolicy}
                  disabled={recommendedPolicyLoading || !policy || !securityAnalysis}
                  variant="outline"
                  size="sm"
                >
                  {recommendedPolicyLoading ? 'Generating...' : recommendedPolicy ? 'Regenerate' : 'Generate Policy'}
                </Button>
              </div>
              
              {recommendedPolicyLoading ? (
                <div className="text-center py-8">
                  <p className="text-muted-foreground">Generating recommended policy with Gemini...</p>
                </div>
              ) : recommendedPolicyError ? (
                <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                  <p className="text-red-600">{recommendedPolicyError}</p>
                </div>
              ) : recommendedPolicy ? (
                <div className="space-y-6">
                  {recommendedPolicy.explanation && (
                    <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                      <h4 className="font-semibold text-blue-800 mb-2">Changes Explanation</h4>
                      <div className="text-sm text-blue-700">
                    <ReactMarkdown remarkPlugins={[remarkGfm]}
                      components={{
                            a: ({...props}: any) => <a {...props} className="text-blue-600 hover:underline" />,
                            code: ({inline, children, ...props}: any) => {
                          const content = Array.isArray(children) ? children.join('') : String(children);
                          if (inline || !content.includes('\n')) {
                            return <code className="rounded bg-muted px-1 py-0.5 text-xs font-mono">{children}</code>;
                          }
                          return <pre className="bg-muted rounded p-3 overflow-x-auto text-sm"><code>{children}</code></pre>;
                        },
                            ul: ({...props}: any) => <ul {...props} className="list-disc pl-6 my-2 space-y-1" />,
                            ol: ({...props}: any) => <ol {...props} className="list-decimal pl-6 my-2 space-y-1" />,
                            p: ({...props}: any) => <p {...props} className="my-2 leading-relaxed" />,
                            li: ({...props}: any) => <li {...props} className="mb-1" />,
                          }}
                        >{recommendedPolicy.explanation}</ReactMarkdown>
                      </div>
                    </div>
                  )}
                  
                  <div>
                    <h4 className="font-semibold mb-2">Recommended Policy Document</h4>
                    <JSONViewer data={recommendedPolicy.policy_document} />
                  </div>
                </div>
              ) : (
                <div className="text-center py-8">
                  <p className="text-muted-foreground mb-4">
                    Generate a security-hardened version of this policy using AI recommendations.
                  </p>
                  <p className="text-sm text-muted-foreground">
                    The AI will analyze the current policy and security issues to create an improved version 
                    that maintains functionality while addressing security concerns.
                  </p>
                  </div>
                )}
            </div>
          )}

          {activeLlmTab === 'attack-path' && (
            <div>
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-semibold">Attack Path Analysis</h3>
                <Button 
                  onClick={handleGenerateAttackPath}
                  disabled={attackPathLoading || !policy || !securityAnalysis}
                  variant="outline"
                  size="sm"
                >
                  {attackPathLoading ? 'Analyzing...' : attackPath ? 'Regenerate' : 'Generate Attack Scenarios'}
                </Button>
              </div>
              
              {attackPathLoading ? (
                <div className="text-center py-8">
                  <p className="text-muted-foreground">Analyzing potential attack vectors with Gemini...</p>
                </div>
              ) : attackPathError ? (
                <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                  <p className="text-red-600">{attackPathError}</p>
                </div>
              ) : attackPath ? (
                <div className="space-y-6">
                  {attackPath.impact_assessment && (
                    <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
                      <h4 className="font-semibold text-orange-800 mb-2">Impact Assessment</h4>
                      <p className="text-sm text-orange-700">{attackPath.impact_assessment}</p>
                    </div>
                  )}
                  
                  {attackPath.attack_scenarios && attackPath.attack_scenarios.length > 0 ? (
                    <div className="space-y-4">
                      <h4 className="font-semibold">Attack Scenarios</h4>
                      {attackPath.attack_scenarios.map((scenario, idx) => (
                        <div key={idx} className={`border rounded-lg p-4 ${
                          scenario.severity === 'HIGH' ? 'border-red-300 bg-red-50' : 
                          scenario.severity === 'MEDIUM' ? 'border-orange-300 bg-orange-50' : 
                          'border-yellow-300 bg-yellow-50'
                        }`}>
                          <div className="flex items-start justify-between mb-3">
                            <h5 className="font-semibold text-lg">{scenario.title}</h5>
                            <Badge variant={
                              scenario.severity === 'HIGH' ? 'destructive' : 
                              scenario.severity === 'MEDIUM' ? 'secondary' : 
                              'outline'
                            }>
                              {scenario.severity}
                            </Badge>
                          </div>
                          
                          <div className="space-y-3">
                            <div>
                              <h6 className="font-medium text-sm mb-1">Description:</h6>
                              <p className="text-sm text-gray-700">{scenario.description}</p>
                            </div>
                            
                            {scenario.prerequisites && (
                              <div>
                                <h6 className="font-medium text-sm mb-1">Prerequisites:</h6>
                                <p className="text-sm text-gray-700">{scenario.prerequisites}</p>
                              </div>
                            )}
                            
                            {scenario.steps && scenario.steps.length > 0 && (
                              <div>
                                <h6 className="font-medium text-sm mb-2">Attack Steps:</h6>
                                <div className="space-y-2">
                                  {scenario.steps.map((step: any, stepIdx: number) => (
                                    <div key={stepIdx} className="bg-white rounded-md p-3 border">
                                      <div className="flex items-start space-x-2 mb-2">
                                        <Badge variant="outline" className="text-xs">Step {step.step}</Badge>
                                        <p className="text-sm font-medium">{step.description}</p>
                                      </div>
                                      {step.aws_cli_command && (
                                        <div className="mt-2">
                                          <p className="text-xs text-gray-600 mb-1">AWS CLI Command:</p>
                                          <code className="block bg-gray-900 text-green-400 p-2 rounded text-xs font-mono overflow-x-auto">
                                            {step.aws_cli_command}
                                          </code>
                                        </div>
                                      )}
                                      {step.explanation && (
                                        <div className="mt-2">
                                          <p className="text-xs text-gray-600 mb-1">Explanation:</p>
                                          <p className="text-xs text-gray-700">{step.explanation}</p>
                                        </div>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                            
                            {scenario.impact && (
                              <div>
                                <h6 className="font-medium text-sm mb-1">Business Impact:</h6>
                                <p className="text-sm text-gray-700">{scenario.impact}</p>
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-8">
                      <p className="text-muted-foreground">No attack scenarios generated.</p>
                    </div>
                )}
              </div>
            ) : (
                <div className="text-center py-8">
                  <p className="text-muted-foreground mb-4">
                    Generate attack path analysis to see how an attacker could exploit this policy.
                  </p>
                  <p className="text-sm text-muted-foreground">
                    The AI will analyze the policy permissions and security issues to demonstrate 
                    realistic attack scenarios with specific AWS CLI commands.
                  </p>
                </div>
              )}
            </div>
            )}
          </div>
      </div>

      {/* Main Content Tabs */}
      <Tabs defaultValue="details" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="details" className="flex items-center space-x-2">
            <FileText className="h-4 w-4" />
            <span>Details</span>
          </TabsTrigger>
          <TabsTrigger value="document" className="flex items-center space-x-2">
            <FileText className="h-4 w-4" />
            <span>Document</span>
          </TabsTrigger>
          <TabsTrigger value="users" className="flex items-center space-x-2">
            <Users className="h-4 w-4" />
            <span>Users ({attachedUsers.length})</span>
          </TabsTrigger>
          <TabsTrigger value="roles-groups" className="flex items-center space-x-2">
            <Shield className="h-4 w-4" />
            <span>Roles & Groups ({attachedRoles.length + attachedGroups.length})</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="details" className="mt-6">
          <div className="bg-muted/50 rounded-lg p-6 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Policy Name</label>
                <CopyField value={policy.PolicyName}>
                  <p className="text-sm font-medium">{policy.PolicyName}</p>
                </CopyField>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Policy ID</label>
                <CopyField value={policy.PolicyId}>
                  <p className="text-sm">{policy.PolicyId}</p>
                </CopyField>
              </div>
              <div className="md:col-span-2">
                <label className="text-sm font-medium text-muted-foreground">ARN</label>
                <CopyField value={policy.Arn}>
                  <p className="text-sm font-mono break-all">{policy.Arn}</p>
                </CopyField>
              </div>
            </div>
            {policy.Description && (
              <div>
                <label className="text-sm font-medium text-muted-foreground">Description</label>
                <p className="text-sm">{policy.Description}</p>
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="document" className="mt-6">
          <div className="bg-muted/50 rounded-lg p-6">
            <div className="flex items-center space-x-2 mb-4">
              <FileText className="h-5 w-5" />
              <h3 className="text-lg font-semibold">Policy Document</h3>
              <span className="text-sm text-muted-foreground">
                (Default version {policy.DefaultVersionId})
              </span>
            </div>
            {policyDocument ? (
              <JSONViewer data={policyDocument} />
            ) : (
              <p className="text-muted-foreground">Policy document not available</p>
            )}
          </div>
        </TabsContent>


        <TabsContent value="users" className="mt-6">
          {attachedUsers.length > 0 ? (
            <div className="bg-muted/50 rounded-lg p-6">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>User Name</TableHead>
                    <TableHead>ARN</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {attachedUsers.map((user) => (
                    <TableRow key={user.UserId}>
                      <TableCell className="font-medium">
                        <CopyField value={user.UserName}>
                          {user.UserName}
                        </CopyField>
                      </TableCell>
                      <TableCell>
                        <CopyField value={user.Arn}>
                          <span className="font-mono text-sm">{user.Arn}</span>
                        </CopyField>
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => router.push(`/user/${user.UserId}`)}
                        >
                          View User
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="bg-muted/50 rounded-lg p-6">
              <p className="text-muted-foreground">Not attached to any users</p>
            </div>
          )}
        </TabsContent>

        <TabsContent value="roles-groups" className="mt-6">
          <div className="space-y-6">
            {/* Roles Section */}
            <div>
              <h3 className="text-lg font-semibold mb-4 flex items-center space-x-2">
                <Shield className="h-5 w-5" />
                <span>Attached to Roles ({attachedRoles.length})</span>
              </h3>
              {attachedRoles.length > 0 ? (
                <div className="bg-muted/50 rounded-lg p-6">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Role Name</TableHead>
                        <TableHead>ARN</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {attachedRoles.map((role) => (
                        <TableRow key={role.RoleId}>
                          <TableCell className="font-medium">
                            <CopyField value={role.RoleName}>
                              {role.RoleName}
                            </CopyField>
                          </TableCell>
                          <TableCell>
                            <CopyField value={role.Arn}>
                              <span className="font-mono text-sm">{role.Arn}</span>
                            </CopyField>
                          </TableCell>
                          <TableCell>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => router.push(`/role/${role.RoleId}`)}
                            >
                              View Role
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ) : (
                <div className="bg-muted/50 rounded-lg p-6">
                  <p className="text-muted-foreground">Not attached to any roles</p>
                </div>
              )}
            </div>

            {/* Groups Section */}
            <div>
              <h3 className="text-lg font-semibold mb-4 flex items-center space-x-2">
                <UserCheck className="h-5 w-5" />
                <span>Attached to Groups ({attachedGroups.length})</span>
              </h3>
              {attachedGroups.length > 0 ? (
                <div className="bg-muted/50 rounded-lg p-6">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Group Name</TableHead>
                        <TableHead>ARN</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {attachedGroups.map((group) => (
                        <TableRow key={group.GroupId}>
                          <TableCell className="font-medium">
                            <CopyField value={group.GroupName}>
                              {group.GroupName}
                            </CopyField>
                          </TableCell>
                          <TableCell>
                            <CopyField value={group.Arn}>
                              <span className="font-mono text-sm">{group.Arn}</span>
                            </CopyField>
                          </TableCell>
                          <TableCell>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => router.push(`/group/${group.GroupId}`)}
                            >
                              View Group
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ) : (
                <div className="bg-muted/50 rounded-lg p-6">
                  <p className="text-muted-foreground">Not attached to any groups</p>
                </div>
              )}
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
} 