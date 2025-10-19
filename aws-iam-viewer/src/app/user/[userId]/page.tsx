'use client';

import { useEffect, useState } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { CopyField } from '@/components/ui/copy-field';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { ArrowLeft, User, Shield, Users, FileText, ChevronDown, ChevronRight } from 'lucide-react';
import { IAMUser, ProcessedIAMData, IAMGroup, IAMPolicy, IAMRole } from '@/lib/types';
import { formatDateTime, findAssumableRoles } from '@/lib/iam-utils';
import { JSONViewer } from '@/components/ui/json-viewer';
import { apiService } from '@/lib/api';

export default function UserDetailsPage() {
  const [user, setUser] = useState<IAMUser | null>(null);
  const [data, setData] = useState<ProcessedIAMData | null>(null);
  const [userGroups, setUserGroups] = useState<IAMGroup[]>([]);
  const [userPolicies, setUserPolicies] = useState<IAMPolicy[]>([]);
  const [assumableRoles, setAssumableRoles] = useState<IAMRole[]>([]);
  const [inlinePoliciesOpen, setInlinePoliciesOpen] = useState(false);

  const router = useRouter();
  const params = useParams();
  const userId = params.userId as string;

  useEffect(() => {
    const loadUserData = async () => {
      try {
        // First get the current upload to get all data
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

        const processedData = uploadResult.data;
        const userData = processedData.users[userId];

        if (!userData) {
          router.push('/dashboard');
          return;
        }

        setData(processedData);
        setUser(userData);

        // Get group details for this user
                const groups = userData.GroupList.map((groupName: string) =>
          Object.values(processedData.groups as Record<string, IAMGroup>).find((group: IAMGroup) => group.GroupName === groupName)
        ).filter((group): group is IAMGroup => group !== undefined);

        // Get policy details for this user
        const policies = userData.AttachedManagedPolicies.map((attachedPolicy: { PolicyArn: string }) => {
          const policyArn = attachedPolicy.PolicyArn;
          return Object.values(processedData.policies as Record<string, IAMPolicy>).find((policy: IAMPolicy) => policy.Arn === policyArn);
        }).filter((policy): policy is IAMPolicy => policy !== undefined);

        // Get assumable roles
        const roles = findAssumableRoles(userData, processedData.roles);

        setUserGroups(groups);
        setUserPolicies(policies);
        setAssumableRoles(roles);
      } catch (error) {
        console.error('Failed to load user data:', error);
        router.push('/');
      }
    };

    loadUserData();
  }, [userId, router]);



  if (!user || !data) {
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
          <h1 className="text-3xl font-bold">User Details: {user.UserName}</h1>
          <p className="text-muted-foreground">Comprehensive user information and permissions</p>
        </div>
      </div>

      {/* Quick Info Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-muted/50 rounded-lg p-4">
          <div className="text-sm text-muted-foreground">Group Memberships</div>
          <div className="text-2xl font-bold">{userGroups.length}</div>
        </div>
        <div className="bg-muted/50 rounded-lg p-4">
          <div className="text-sm text-muted-foreground">Attached Policies</div>
          <div className="text-2xl font-bold">{userPolicies.length}</div>
        </div>
        <div className="bg-muted/50 rounded-lg p-4">
          <div className="text-sm text-muted-foreground">Assumable Roles</div>
          <div className="text-2xl font-bold">{assumableRoles.length}</div>
        </div>
        <div className="bg-muted/50 rounded-lg p-4">
          <div className="text-sm text-muted-foreground">Created</div>
          <div className="text-sm font-medium">{formatDateTime(user.CreateDate)}</div>
        </div>
      </div>

      {/* Inline Policies - Collapsible */}
      {user.UserPolicyList && user.UserPolicyList.length > 0 && (
        <Collapsible open={inlinePoliciesOpen} onOpenChange={setInlinePoliciesOpen}>
          <CollapsibleTrigger asChild>
            <Button variant="ghost" className="w-full justify-between p-4 h-auto bg-muted/30 hover:bg-muted/50">
              <div className="flex items-center space-x-2">
                <FileText className="h-5 w-5" />
                <span className="text-lg font-semibold">Inline Policies</span>
                <Badge variant="secondary">{user.UserPolicyList.length} policies</Badge>
              </div>
              {inlinePoliciesOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="mt-2">
            <div className="bg-muted/50 rounded-lg p-6 space-y-6">
              {user.UserPolicyList.map((policy, index) => (
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
            <User className="h-4 w-4" />
            <span>Details</span>
          </TabsTrigger>
          <TabsTrigger value="groups" className="flex items-center space-x-2">
            <Users className="h-4 w-4" />
            <span>Groups ({userGroups.length})</span>
          </TabsTrigger>
          <TabsTrigger value="policies" className="flex items-center space-x-2">
            <Shield className="h-4 w-4" />
            <span>Policies ({userPolicies.length})</span>
          </TabsTrigger>
          <TabsTrigger value="roles" className="flex items-center space-x-2">
            <FileText className="h-4 w-4" />
            <span>Roles ({assumableRoles.length})</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="details" className="mt-6">
          <div className="bg-muted/50 rounded-lg p-6 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">User Name</label>
                <CopyField value={user.UserName}>
                  <p className="text-sm font-medium">{user.UserName}</p>
                </CopyField>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">User ID</label>
                <CopyField value={user.UserId}>
                  <p className="text-sm">{user.UserId}</p>
                </CopyField>
              </div>
              <div className="md:col-span-2">
                <label className="text-sm font-medium text-muted-foreground">ARN</label>
                <CopyField value={user.Arn}>
                  <p className="text-sm font-mono break-all">{user.Arn}</p>
                </CopyField>
              </div>
            </div>
            {user.Tags && user.Tags.length > 0 && (
              <div>
                <label className="text-sm font-medium text-muted-foreground">Tags</label>
                <div className="flex flex-wrap gap-2 mt-1">
                  {user.Tags.map((tag, index) => (
                    <Badge key={index} variant="outline">
                      {tag.Key}: {tag.Value}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="groups" className="mt-6">
          {userGroups.length > 0 ? (
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
                  {userGroups.map((group) => (
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
              <p className="text-muted-foreground">User is not a member of any groups</p>
            </div>
          )}
        </TabsContent>

        <TabsContent value="policies" className="mt-6">
          {userPolicies.length > 0 ? (
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
                  {userPolicies.map((policy) => (
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
              <p className="text-muted-foreground">No policies directly attached to this user</p>
            </div>
          )}
        </TabsContent>

        <TabsContent value="roles" className="mt-6">
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
                  {assumableRoles.map((role) => (
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
              <p className="text-muted-foreground">User cannot assume any roles</p>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
} 