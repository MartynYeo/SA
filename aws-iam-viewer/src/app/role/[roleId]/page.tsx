'use client';

import { useEffect, useState } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { CopyField } from '@/components/ui/copy-field';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { ArrowLeft, Shield, FileText, ChevronDown, ChevronRight, Users } from 'lucide-react';
import { IAMRole, ProcessedIAMData, IAMPolicy } from '@/lib/types';
import { formatDateTime, findAssumableRolesForRole, findRoleAssumptionChain } from '@/lib/iam-utils';
import { JSONViewer } from '@/components/ui/json-viewer';
import { apiService } from '@/lib/api';

export default function RoleDetailsPage() {
  const [role, setRole] = useState<IAMRole | null>(null);
  const [data, setData] = useState<ProcessedIAMData | null>(null);
  const [rolePolicies, setRolePolicies] = useState<IAMPolicy[]>([]);
  const [assumableRoles, setAssumableRoles] = useState<IAMRole[]>([]);
  const [rolesThatCanAssume, setRolesThatCanAssume] = useState<IAMRole[]>([]);
  const [assumptionChain, setAssumptionChain] = useState<IAMRole[]>([]);
  const [assumeRolePolicyOpen, setAssumeRolePolicyOpen] = useState(true);
  const [inlinePoliciesOpen, setInlinePoliciesOpen] = useState(false);
  const router = useRouter();
  const params = useParams();
  const roleId = params.roleId as string;

  useEffect(() => {
    const loadRoleData = async () => {
      try {
        const currentResult = await apiService.getCurrentUploadId();
        if (currentResult.error || !currentResult.uploadId) {
          router.push('/');
          return;
        }

        const uploadResult = await apiService.getUpload(currentResult.uploadId);
        if (uploadResult.error || !uploadResult.data) {
          router.push('/');
          return;
        }

        const roleData = uploadResult.data.roles[roleId];
        if (!roleData) {
          router.push('/dashboard');
          return;
        }

        setData(uploadResult.data!);
        setRole(roleData);

        // Get policy details for this role
        const policies = roleData.AttachedManagedPolicies.map((attachedPolicy: { PolicyArn: string }) => {
          const policyArn = attachedPolicy.PolicyArn;
          return Object.values(uploadResult.data!.policies as Record<string, IAMPolicy>).find((policy: IAMPolicy) => policy.Arn === policyArn);
        }).filter((policy): policy is IAMPolicy => policy !== undefined);

        setRolePolicies(policies);

        // Get roles that this role can assume
        const assumableRoles = findAssumableRolesForRole(roleData, uploadResult.data!.roles as Record<string, IAMRole>);
        setAssumableRoles(assumableRoles);

        // Get roles that can assume this role
        const rolesThatCanAssume = Object.values(uploadResult.data!.roles as Record<string, IAMRole>).filter((otherRole: IAMRole) => {
          if (otherRole.RoleId === roleData.RoleId) return false;
          const otherRoleAssumableRoles = findAssumableRolesForRole(otherRole, uploadResult.data!.roles as Record<string, IAMRole>);
          return otherRoleAssumableRoles.some(r => r.RoleId === roleData.RoleId);
        });
        setRolesThatCanAssume(rolesThatCanAssume);

        // Get the complete assumption chain
        const chain = findRoleAssumptionChain(roleData, uploadResult.data!.roles as Record<string, IAMRole>);
        setAssumptionChain(chain);
      } catch (error) {
        console.error('Failed to load role data:', error);
        router.push('/');
      }
    };

    loadRoleData();
  }, [roleId, router]);

  if (!role || !data) {
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
          <h1 className="text-3xl font-bold">Role Details: {role.RoleName}</h1>
          <p className="text-muted-foreground">Comprehensive role information and permissions</p>
        </div>
      </div>

      {/* Quick Info Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-muted/50 rounded-lg p-4">
          <div className="text-sm text-muted-foreground">Attached Policies</div>
          <div className="text-2xl font-bold">{rolePolicies.length}</div>
        </div>
        <div className="bg-muted/50 rounded-lg p-4">
          <div className="text-sm text-muted-foreground">Inline Policies</div>
          <div className="text-2xl font-bold">{role.RolePolicyList?.length || 0}</div>
        </div>
        <div className="bg-muted/50 rounded-lg p-4">
          <div className="text-sm text-muted-foreground">Can Assume</div>
          <div className="text-2xl font-bold">{assumableRoles.length}</div>
        </div>
        <div className="bg-muted/50 rounded-lg p-4">
          <div className="text-sm text-muted-foreground">Created</div>
          <div className="text-sm font-medium">{formatDateTime(role.CreateDate)}</div>
        </div>
      </div>

      {/* Assume Role Policy - Collapsible */}
      <Collapsible open={assumeRolePolicyOpen} onOpenChange={setAssumeRolePolicyOpen}>
        <CollapsibleTrigger asChild>
          <Button variant="ghost" className="w-full justify-between p-4 h-auto bg-muted/30 hover:bg-muted/50">
            <div className="flex items-center space-x-2">
              <Shield className="h-5 w-5" />
              <span className="text-lg font-semibold">Assume Role Policy</span>
              <span className="text-sm text-muted-foreground">(Who can assume this role)</span>
            </div>
            {assumeRolePolicyOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </Button>
        </CollapsibleTrigger>
        <CollapsibleContent className="mt-2">
          <div className="bg-muted/50 rounded-lg p-6">
            {role.AssumeRolePolicyDocument && Object.keys(role.AssumeRolePolicyDocument).length > 0 ? (
              <JSONViewer data={role.AssumeRolePolicyDocument} />
            ) : (
              <p className="text-muted-foreground">Assume role policy not available</p>
            )}
          </div>
        </CollapsibleContent>
      </Collapsible>

      {/* Inline Policies - Collapsible */}
      {role.RolePolicyList && role.RolePolicyList.length > 0 && (
        <Collapsible open={inlinePoliciesOpen} onOpenChange={setInlinePoliciesOpen}>
          <CollapsibleTrigger asChild>
            <Button variant="ghost" className="w-full justify-between p-4 h-auto bg-muted/30 hover:bg-muted/50">
              <div className="flex items-center space-x-2">
                <FileText className="h-5 w-5" />
                <span className="text-lg font-semibold">Inline Policies</span>
                <Badge variant="secondary">{role.RolePolicyList.length} policies</Badge>
              </div>
              {inlinePoliciesOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="mt-2">
            <div className="bg-muted/50 rounded-lg p-6 space-y-6">
              {role.RolePolicyList.map((policy, index: number) => (
                <div key={index} className="space-y-2">
                  <h3 className="text-lg font-medium">{policy.PolicyName}</h3>
                  <JSONViewer data={policy.PolicyDocument} />
                </div>
              ))}
            </div>
          </CollapsibleContent>
        </Collapsible>
      )}

      {/* Main Content Tabs */}
      <Tabs defaultValue="details" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="details" className="flex items-center space-x-2">
            <Shield className="h-4 w-4" />
            <span>Details</span>
          </TabsTrigger>
          <TabsTrigger value="policies" className="flex items-center space-x-2">
            <FileText className="h-4 w-4" />
            <span>Policies ({rolePolicies.length})</span>
          </TabsTrigger>
          <TabsTrigger value="assumable" className="flex items-center space-x-2">
            <Users className="h-4 w-4" />
            <span>Can Assume ({assumableRoles.length})</span>
          </TabsTrigger>
          <TabsTrigger value="relationships" className="flex items-center space-x-2">
            <Shield className="h-4 w-4" />
            <span>Relationships</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="details" className="mt-6">
          <div className="bg-muted/50 rounded-lg p-6 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Role Name</label>
                <CopyField value={role.RoleName}>
                  <p className="text-sm font-medium">{role.RoleName}</p>
                </CopyField>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Role ID</label>
                <CopyField value={role.RoleId}>
                  <p className="text-sm">{role.RoleId}</p>
                </CopyField>
              </div>
              <div className="md:col-span-2">
                <label className="text-sm font-medium text-muted-foreground">ARN</label>
                <CopyField value={role.Arn}>
                  <p className="text-sm font-mono break-all">{role.Arn}</p>
                </CopyField>
              </div>
            </div>
            {role.Tags && role.Tags.length > 0 && (
              <div>
                <label className="text-sm font-medium text-muted-foreground">Tags</label>
                <div className="flex flex-wrap gap-2 mt-1">
                  {role.Tags.map((tag, index) => (
                    <Badge key={index} variant="outline">
                      {tag.Key}: {tag.Value}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="policies" className="mt-6">
          {rolePolicies.length > 0 ? (
            <div className="bg-muted/50 rounded-lg p-6">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Policy Name</TableHead>
                    <TableHead>ARN</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rolePolicies.map((policy) => (
                    <TableRow key={policy.PolicyId}>
                      <TableCell className="font-medium">
                        <CopyField value={policy.PolicyName}>
                          {policy.PolicyName}
                        </CopyField>
                      </TableCell>
                      <TableCell>
                        <CopyField value={policy.Arn}>
                          <span className="font-mono text-sm">{policy.Arn}</span>
                        </CopyField>
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => router.push(`/policy/${policy.PolicyId}`)}
                        >
                          View Policy
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="bg-muted/50 rounded-lg p-6">
              <p className="text-muted-foreground">No policies directly attached to this role</p>
            </div>
          )}
        </TabsContent>

        <TabsContent value="assumable" className="mt-6">
          {assumableRoles.length > 0 ? (
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
                  {assumableRoles.map((assumableRole) => (
                    <TableRow key={assumableRole.RoleId}>
                      <TableCell className="font-medium">
                        <CopyField value={assumableRole.RoleName}>
                          {assumableRole.RoleName}
                        </CopyField>
                      </TableCell>
                      <TableCell>
                        <CopyField value={assumableRole.Arn}>
                          <span className="font-mono text-sm">{assumableRole.Arn}</span>
                        </CopyField>
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => router.push(`/role/${assumableRole.RoleId}`)}
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
              <p className="text-muted-foreground">This role cannot assume any other roles</p>
            </div>
          )}
        </TabsContent>

        <TabsContent value="relationships" className="mt-6">
          <div className="space-y-6">
            {/* Roles That Can Assume This Role */}
            <div>
              <h3 className="text-lg font-semibold mb-4 flex items-center space-x-2">
                <Shield className="h-5 w-5" />
                <span>Roles That Can Assume This Role ({rolesThatCanAssume.length})</span>
              </h3>
              {rolesThatCanAssume.length > 0 ? (
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
                      {rolesThatCanAssume.map((assumingRole) => (
                        <TableRow key={assumingRole.RoleId}>
                          <TableCell className="font-medium">
                            <CopyField value={assumingRole.RoleName}>
                              {assumingRole.RoleName}
                            </CopyField>
                          </TableCell>
                          <TableCell>
                            <CopyField value={assumingRole.Arn}>
                              <span className="font-mono text-sm">{assumingRole.Arn}</span>
                            </CopyField>
                          </TableCell>
                          <TableCell>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => router.push(`/role/${assumingRole.RoleId}`)}
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
                  <p className="text-muted-foreground">No other roles can assume this role</p>
                </div>
              )}
            </div>

            {/* Complete Assumption Chain */}
            <div>
              <h3 className="text-lg font-semibold mb-4 flex items-center space-x-2">
                <Shield className="h-5 w-5" />
                <span>Complete Assumption Chain ({assumptionChain.length} roles)</span>
              </h3>
              {assumptionChain.length > 1 ? (
                <div className="bg-muted/50 rounded-lg p-6">
                  <div className="mb-4">
                    <p className="text-sm text-muted-foreground mb-2">
                      This role is part of an assumption chain. Clicking any role in this chain will show all related roles and their relationships.
                    </p>
                  </div>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Role Name</TableHead>
                        <TableHead>ARN</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {assumptionChain.map((chainRole) => (
                        <TableRow key={chainRole.RoleId}>
                          <TableCell className="font-medium">
                            <CopyField value={chainRole.RoleName}>
                              {chainRole.RoleName}
                              {chainRole.RoleId === role.RoleId && (
                                <Badge variant="secondary" className="ml-2">Current</Badge>
                              )}
                            </CopyField>
                          </TableCell>
                          <TableCell>
                            <CopyField value={chainRole.Arn}>
                              <span className="font-mono text-sm">{chainRole.Arn}</span>
                            </CopyField>
                          </TableCell>
                          <TableCell>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => router.push(`/role/${chainRole.RoleId}`)}
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
                  <p className="text-muted-foreground">This role is not part of an assumption chain</p>
                </div>
              )}
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
} 