'use client';

import { useEffect, useState } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { CopyField } from '@/components/ui/copy-field';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { ArrowLeft, UserCheck, FileText, Users, ChevronDown, ChevronRight, Shield } from 'lucide-react';
import { IAMGroup, ProcessedIAMData, IAMUser, IAMPolicy } from '@/lib/types';
import { formatDateTime, findGroupUsers } from '@/lib/iam-utils';
import { JSONViewer } from '@/components/ui/json-viewer';
import { apiService } from '@/lib/api';

export default function GroupDetailsPage() {
  const [group, setGroup] = useState<IAMGroup | null>(null);
  const [data, setData] = useState<ProcessedIAMData | null>(null);
  const [groupPolicies, setGroupPolicies] = useState<IAMPolicy[]>([]);
  const [groupUsers, setGroupUsers] = useState<IAMUser[]>([]);
  const [inlinePoliciesOpen, setInlinePoliciesOpen] = useState(false);
  const router = useRouter();
  const params = useParams();
  const groupId = params.groupId as string;

  useEffect(() => {
    const loadGroupData = async () => {
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

        const groupData = uploadResult.data.groups[groupId];
        if (!groupData) {
          router.push('/dashboard');
          return;
        }

        setData(uploadResult.data!);
        setGroup(groupData);

        // Get policy details for this group
        const policies = groupData.AttachedManagedPolicies.map((attachedPolicy: { PolicyArn: string }) => {
          const policyArn = attachedPolicy.PolicyArn;
          return Object.values(uploadResult.data!.policies as Record<string, IAMPolicy>).find((policy: IAMPolicy) => policy.Arn === policyArn);
        }).filter((policy): policy is IAMPolicy => policy !== undefined);

        // Find users that are members of this group
        const users = findGroupUsers(groupData.GroupName, uploadResult.data!.users);

        setGroupPolicies(policies);
        setGroupUsers(users);
      } catch (error) {
        console.error('Failed to load group data:', error);
        router.push('/');
      }
    };

    loadGroupData();
  }, [groupId, router]);

  if (!group || !data) {
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
          <h1 className="text-3xl font-bold">Group Details: {group.GroupName}</h1>
          <p className="text-muted-foreground">Comprehensive group information and members</p>
        </div>
      </div>

      {/* Quick Info Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-muted/50 rounded-lg p-4">
          <div className="text-sm text-muted-foreground">Group Members</div>
          <div className="text-2xl font-bold">{groupUsers.length}</div>
        </div>
        <div className="bg-muted/50 rounded-lg p-4">
          <div className="text-sm text-muted-foreground">Attached Policies</div>
          <div className="text-2xl font-bold">{groupPolicies.length}</div>
        </div>
        <div className="bg-muted/50 rounded-lg p-4">
          <div className="text-sm text-muted-foreground">Inline Policies</div>
          <div className="text-2xl font-bold">{group.GroupPolicyList?.length || 0}</div>
        </div>
        <div className="bg-muted/50 rounded-lg p-4">
          <div className="text-sm text-muted-foreground">Created</div>
          <div className="text-sm font-medium">{formatDateTime(group.CreateDate)}</div>
        </div>
      </div>

      {/* Inline Policies - Collapsible */}
      {group.GroupPolicyList && group.GroupPolicyList.length > 0 && (
        <Collapsible open={inlinePoliciesOpen} onOpenChange={setInlinePoliciesOpen}>
          <CollapsibleTrigger asChild>
            <Button variant="ghost" className="w-full justify-between p-4 h-auto bg-muted/30 hover:bg-muted/50">
              <div className="flex items-center space-x-2">
                <FileText className="h-5 w-5" />
                <span className="text-lg font-semibold">Inline Policies</span>
                <Badge variant="secondary">{group.GroupPolicyList.length} policies</Badge>
              </div>
              {inlinePoliciesOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="mt-2">
            <div className="bg-muted/50 rounded-lg p-6 space-y-6">
              {group.GroupPolicyList.map((policy, index: number) => (
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
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="details" className="flex items-center space-x-2">
            <UserCheck className="h-4 w-4" />
            <span>Details</span>
          </TabsTrigger>
          <TabsTrigger value="members" className="flex items-center space-x-2">
            <Users className="h-4 w-4" />
            <span>Members ({groupUsers.length})</span>
          </TabsTrigger>
          <TabsTrigger value="policies" className="flex items-center space-x-2">
            <Shield className="h-4 w-4" />
            <span>Policies ({groupPolicies.length})</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="details" className="mt-6">
          <div className="bg-muted/50 rounded-lg p-6 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Group Name</label>
                <CopyField value={group.GroupName}>
                  <p className="text-sm font-medium">{group.GroupName}</p>
                </CopyField>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Group ID</label>
                <CopyField value={group.GroupId}>
                  <p className="text-sm">{group.GroupId}</p>
                </CopyField>
              </div>
              <div className="md:col-span-2">
                <label className="text-sm font-medium text-muted-foreground">ARN</label>
                <CopyField value={group.Arn}>
                  <p className="text-sm font-mono break-all">{group.Arn}</p>
                </CopyField>
              </div>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="members" className="mt-6">
          {groupUsers.length > 0 ? (
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
                  {groupUsers.map((user) => (
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
              <p className="text-muted-foreground">No users are members of this group</p>
            </div>
          )}
        </TabsContent>

        <TabsContent value="policies" className="mt-6">
          {groupPolicies.length > 0 ? (
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
                  {groupPolicies.map((policy) => (
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
              <p className="text-muted-foreground">No policies directly attached to this group</p>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
} 