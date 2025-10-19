'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { CopyField } from '@/components/ui/copy-field';
import { Search, Users, Shield, FileText, UserCheck, AlertTriangle, AlertCircle } from 'lucide-react';
import { ProcessedIAMData, IAMRole, IAMPolicy } from '@/lib/types';
import { formatDateTime, truncateArn } from '@/lib/iam-utils';
import { apiService } from '@/lib/api';
import { analyzeAllPolicies, getSecuritySummary, PolicyAnalysisResult } from '@/lib/policy-analysis';

export default function DashboardPage() {
  const [data, setData] = useState<ProcessedIAMData | null>(null);
  const [currentUpload, setCurrentUpload] = useState<{ name: string; data: ProcessedIAMData } | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeTab, setActiveTab] = useState('users');
  const [securityAnalysis, setSecurityAnalysis] = useState<PolicyAnalysisResult[]>([]);
  const [securitySummary, setSecuritySummary] = useState<any>(null);
  const router = useRouter();

  useEffect(() => {
    const loadCurrentUpload = async () => {
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

        // For compatibility with existing UI, create a mock upload object
        setCurrentUpload({
          name: `Upload ${currentResult.uploadId.slice(0, 8)}`,
          data: uploadResult.data
        });
        setData(uploadResult.data);
        
        // Perform security analysis
        const analysis = analyzeAllPolicies(uploadResult.data.policies);
        const summary = getSecuritySummary(uploadResult.data.policies);
        setSecurityAnalysis(analysis);
        setSecuritySummary(summary);
      } catch (error) {
        console.error('Failed to load current upload:', error);
        router.push('/');
      }
    };

    loadCurrentUpload();
  }, [router]);

  if (!data || !currentUpload) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }

  const { users, roles, policies, groups } = data;

  const filteredUsers = Object.entries(users).filter(([, user]) =>
    user.UserName.toLowerCase().includes(searchTerm.toLowerCase()) ||
    user.Arn.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Categorize roles into user-defined and AWS service roles
  const categorizeRoles = (roles: Record<string, IAMRole>) => {
    const userRoles: [string, IAMRole][] = [];
    const serviceRoles: [string, IAMRole][] = [];
    
    Object.entries(roles).forEach(([roleId, role]) => {
      // AWS service roles have pattern: arn:aws:iam::accountid:role/aws-service-role/service.amazonaws.com/rolename
      if (role.Arn.includes('/aws-service-role/')) {
        serviceRoles.push([roleId, role]);
      } else {
        userRoles.push([roleId, role]);
      }
    });
    
    return { userRoles, serviceRoles };
  };

  const { userRoles, serviceRoles } = categorizeRoles(roles);

  const filteredUserRoles = userRoles.filter(([, role]) =>
    role.RoleName.toLowerCase().includes(searchTerm.toLowerCase()) ||
    role.Arn.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredServiceRoles = serviceRoles.filter(([, role]) =>
    role.RoleName.toLowerCase().includes(searchTerm.toLowerCase()) ||
    role.Arn.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Categorize policies into user-defined, AWS service role policies, and AWS managed policies
  const categorizePolicies = (policies: Record<string, IAMPolicy>) => {
    const userPolicies: [string, IAMPolicy][] = [];
    const serviceRolePolicies: [string, IAMPolicy][] = [];
    const managedPolicies: [string, IAMPolicy][] = [];
    
    Object.entries(policies).forEach(([policyId, policy]) => {
      // AWS service role policies have pattern: arn:aws:iam::aws:policy/aws-service-role/policy name
      // or arn:aws:iam::aws:policy/service-role/policy name
      if (policy.Arn.includes('::aws:policy/aws-service-role/') || policy.Arn.includes(':policy/service-role/')) {
        serviceRolePolicies.push([policyId, policy]);
      }
      // AWS managed policies have pattern: arn:aws:iam::aws:policy/policy-name (without service-role path)
      else if (policy.Arn.includes('::aws:policy/') && !policy.Arn.includes('/aws-service-role/') && !policy.Arn.includes('/service-role/')) {
        managedPolicies.push([policyId, policy]);
      } else {
        userPolicies.push([policyId, policy]);
      }
    });
    
    return { userPolicies, serviceRolePolicies, managedPolicies };
  };

  const { userPolicies, serviceRolePolicies, managedPolicies } = categorizePolicies(policies);

  const filteredUserPolicies = userPolicies.filter(([, policy]) =>
    policy.PolicyName.toLowerCase().includes(searchTerm.toLowerCase()) ||
    policy.Arn.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredServiceRolePolicies = serviceRolePolicies.filter(([, policy]) =>
    policy.PolicyName.toLowerCase().includes(searchTerm.toLowerCase()) ||
    policy.Arn.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredManagedPolicies = managedPolicies.filter(([, policy]) =>
    policy.PolicyName.toLowerCase().includes(searchTerm.toLowerCase()) ||
    policy.Arn.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredGroups = Object.entries(groups).filter(([, group]) =>
    group.GroupName.toLowerCase().includes(searchTerm.toLowerCase()) ||
    group.Arn.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">IAM Dashboard</h1>
          <p className="text-muted-foreground">
            Analyzing: {currentUpload.name}
          </p>
        </div>
        <Button variant="outline" onClick={() => router.push('/')}>
          Upload New File
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Users</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{Object.keys(users).length}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Roles</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{Object.keys(roles).length}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Policies</CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{Object.keys(policies).length}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Groups</CardTitle>
            <UserCheck className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{Object.keys(groups).length}</div>
          </CardContent>
        </Card>
      </div>

      {/* Security Analysis Cards */}
      {securitySummary && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className={securitySummary.highRiskPolicies > 0 ? "border-red-200 bg-red-50" : ""}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">High Risk Policies</CardTitle>
              <AlertTriangle className={`h-4 w-4 ${securitySummary.highRiskPolicies > 0 ? "text-red-600" : "text-muted-foreground"}`} />
            </CardHeader>
            <CardContent>
              <div className={`text-2xl font-bold ${securitySummary.highRiskPolicies > 0 ? "text-red-600" : ""}`}>
                {securitySummary.highRiskPolicies}
              </div>
              <p className="text-xs text-muted-foreground">
                of {securitySummary.totalPolicies} policies
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Security Flags</CardTitle>
              <AlertCircle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{securitySummary.totalSecurityFlags}</div>
              <p className="text-xs text-muted-foreground">
                {securitySummary.highSeverityFlags} high severity
              </p>
            </CardContent>
          </Card>

          

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Security Status</CardTitle>
              <Shield className={`h-4 w-4 ${securitySummary.highRiskPolicies > 0 ? "text-red-600" : "text-green-600"}`} />
            </CardHeader>
            <CardContent>
              <div className={`text-lg font-bold ${securitySummary.highRiskPolicies > 0 ? "text-red-600" : "text-green-600"}`}>
                {securitySummary.highRiskPolicies > 0 ? "⚠️ At Risk" : "✅ Secure"}
              </div>
              <p className="text-xs text-muted-foreground">
                Policy analysis
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="users">Users</TabsTrigger>
          <TabsTrigger value="roles">Roles</TabsTrigger>
          <TabsTrigger value="policies">Policies</TabsTrigger>
          <TabsTrigger value="groups">Groups</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
        </TabsList>

        <TabsContent value="users" className="space-y-4">
          <div className="flex items-center space-x-2">
            <Search className="h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search users..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="max-w-sm"
            />
          </div>
          
          <Card>
            <CardHeader>
              <CardTitle>Users</CardTitle>
              <CardDescription>
                {filteredUsers.length} of {Object.keys(users).length} users
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>User Name</TableHead>
                    <TableHead>ARN</TableHead>
                    <TableHead>Create Date</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredUsers.map(([userId, user]) => (
                    <TableRow key={userId}>
                      <TableCell className="font-medium">
                        <CopyField value={user.UserName}>
                          {user.UserName}
                        </CopyField>
                      </TableCell>
                      <TableCell>
                        <CopyField value={user.Arn} displayValue={truncateArn(user.Arn)} />
                      </TableCell>
                      <TableCell>
                        <CopyField value={formatDateTime(user.CreateDate)}>
                          {formatDateTime(user.CreateDate)}
                        </CopyField>
                      </TableCell>
                      <TableCell>
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => router.push(`/user/${userId}`)}
                        >
                          View Details
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="roles" className="space-y-6">
          <div className="flex items-center space-x-2">
            <Search className="h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search roles..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="max-w-sm"
            />
          </div>
          
          {/* User-Defined Roles */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Shield className="h-5 w-5" />
                <span>User-Defined Roles</span>
                <Badge variant="secondary">{userRoles.length}</Badge>
              </CardTitle>
              <CardDescription>
                {filteredUserRoles.length} of {userRoles.length} user-defined roles
              </CardDescription>
            </CardHeader>
            <CardContent>
              {filteredUserRoles.length > 0 ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Role Name</TableHead>
                      <TableHead>ARN</TableHead>
                      <TableHead>Create Date</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredUserRoles.map(([roleId, role]) => (
                      <TableRow key={roleId}>
                        <TableCell className="font-medium">
                          <CopyField value={role.RoleName}>
                            {role.RoleName}
                          </CopyField>
                        </TableCell>
                        <TableCell>
                          <CopyField value={role.Arn} displayValue={truncateArn(role.Arn)} />
                        </TableCell>
                        <TableCell>
                          <CopyField value={formatDateTime(role.CreateDate)}>
                            {formatDateTime(role.CreateDate)}
                          </CopyField>
                        </TableCell>
                        <TableCell>
                          <Button 
                            variant="outline" 
                            size="sm"
                            onClick={() => router.push(`/role/${roleId}`)}
                          >
                            View Details
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <div className="text-center py-8">
                  <p className="text-muted-foreground">
                    {searchTerm ? 'No user-defined roles match your search.' : 'No user-defined roles found.'}
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* AWS Service Roles */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Shield className="h-5 w-5" />
                <span>AWS Service-Linked Roles</span>
                <Badge variant="secondary">{serviceRoles.length}</Badge>
              </CardTitle>
              <CardDescription>
                {filteredServiceRoles.length} of {serviceRoles.length} AWS service-linked roles
              </CardDescription>
            </CardHeader>
            <CardContent>
              {filteredServiceRoles.length > 0 ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Role Name</TableHead>
                      <TableHead>ARN</TableHead>
                      <TableHead>Create Date</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredServiceRoles.map(([roleId, role]) => (
                      <TableRow key={roleId}>
                        <TableCell className="font-medium">
                          <CopyField value={role.RoleName}>
                            {role.RoleName}
                          </CopyField>
                        </TableCell>
                        <TableCell>
                          <CopyField value={role.Arn} displayValue={truncateArn(role.Arn)} />
                        </TableCell>
                        <TableCell>
                          <CopyField value={formatDateTime(role.CreateDate)}>
                            {formatDateTime(role.CreateDate)}
                          </CopyField>
                        </TableCell>
                        <TableCell>
                          <Button 
                            variant="outline" 
                            size="sm"
                            onClick={() => router.push(`/role/${roleId}`)}
                          >
                            View Details
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <div className="text-center py-8">
                  <p className="text-muted-foreground">
                    {searchTerm ? 'No AWS service roles match your search.' : 'No AWS service roles found.'}
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="policies" className="space-y-6">
          <div className="flex items-center space-x-2">
            <Search className="h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search policies..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="max-w-sm"
            />
          </div>
          
          {/* User-Defined Policies */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <FileText className="h-5 w-5" />
                <span>User-Defined Policies</span>
                <Badge variant="secondary">{userPolicies.length}</Badge>
              </CardTitle>
              <CardDescription>
                {filteredUserPolicies.length} of {userPolicies.length} user-defined policies
              </CardDescription>
            </CardHeader>
            <CardContent>
              {filteredUserPolicies.length > 0 ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Policy Name</TableHead>
                      <TableHead>ARN</TableHead>
                      <TableHead>Create Date</TableHead>
                      <TableHead>Attachment Count</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                  {filteredUserPolicies.map(([policyId, policy]) => {
                    const isHighRisk = securityAnalysis.some(a => a.policyId === policyId && a.isHighRisk);
                    return (
                    <TableRow key={policyId} className={isHighRisk ? "bg-red-50" : ""}>
                        <TableCell className="font-medium">
                          <CopyField value={policy.PolicyName}>
                            {policy.PolicyName}
                          </CopyField>
                        </TableCell>
                        <TableCell>
                          <CopyField value={policy.Arn} displayValue={truncateArn(policy.Arn)} />
                        </TableCell>
                        <TableCell>
                          <CopyField value={formatDateTime(policy.CreateDate)}>
                            {formatDateTime(policy.CreateDate)}
                          </CopyField>
                        </TableCell>
                        <TableCell>
                          <Badge variant="secondary">{policy.AttachmentCount}</Badge>
                        </TableCell>
                        <TableCell>
                          <Button 
                            variant="outline" 
                            size="sm"
                            onClick={() => router.push(`/policy/${policyId}`)}
                          >
                            View Details
                          </Button>
                        </TableCell>
                    </TableRow>
                  );})}
                  </TableBody>
                </Table>
              ) : (
                <div className="text-center py-8">
                  <p className="text-muted-foreground">
                    {searchTerm ? 'No user-defined policies match your search.' : 'No user-defined policies found.'}
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* AWS Service Role Policies */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <FileText className="h-5 w-5" />
                <span>AWS Service Role Policies</span>
                <Badge variant="secondary">{serviceRolePolicies.length}</Badge>
              </CardTitle>
              <CardDescription>
                {filteredServiceRolePolicies.length} of {serviceRolePolicies.length} AWS service role policies
              </CardDescription>
            </CardHeader>
            <CardContent>
              {filteredServiceRolePolicies.length > 0 ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Policy Name</TableHead>
                      <TableHead>ARN</TableHead>
                      <TableHead>Create Date</TableHead>
                      <TableHead>Attachment Count</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredServiceRolePolicies.map(([policyId, policy]) => {
                      const isHighRisk = securityAnalysis.some(a => a.policyId === policyId && a.isHighRisk);
                      return (
                      <TableRow key={policyId} className={isHighRisk ? "bg-red-50" : ""}>
                        <TableCell className="font-medium">
                          <CopyField value={policy.PolicyName}>
                            {policy.PolicyName}
                          </CopyField>
                        </TableCell>
                        <TableCell>
                          <CopyField value={policy.Arn} displayValue={truncateArn(policy.Arn)} />
                        </TableCell>
                        <TableCell>
                          <CopyField value={formatDateTime(policy.CreateDate)}>
                            {formatDateTime(policy.CreateDate)}
                          </CopyField>
                        </TableCell>
                        <TableCell>
                          <Badge variant="secondary">{policy.AttachmentCount}</Badge>
                        </TableCell>
                        <TableCell>
                          <Button 
                            variant="outline" 
                            size="sm"
                            onClick={() => router.push(`/policy/${policyId}`)}
                          >
                            View Details
                          </Button>
                        </TableCell>
                      </TableRow>
                    );})}
                  </TableBody>
                </Table>
              ) : (
                <div className="text-center py-8">
                  <p className="text-muted-foreground">
                    {searchTerm ? 'No AWS service role policies match your search.' : 'No AWS service role policies found.'}
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* AWS Managed Policies */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <FileText className="h-5 w-5" />
                <span>AWS Managed Policies</span>
                <Badge variant="secondary">{managedPolicies.length}</Badge>
              </CardTitle>
              <CardDescription>
                {filteredManagedPolicies.length} of {managedPolicies.length} AWS managed policies
              </CardDescription>
            </CardHeader>
            <CardContent>
              {filteredManagedPolicies.length > 0 ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Policy Name</TableHead>
                      <TableHead>ARN</TableHead>
                      <TableHead>Create Date</TableHead>
                      <TableHead>Attachment Count</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredManagedPolicies.map(([policyId, policy]) => {
                      const isHighRisk = securityAnalysis.some(a => a.policyId === policyId && a.isHighRisk);
                      return (
                      <TableRow key={policyId} className={isHighRisk ? "bg-red-50" : ""}>
                        <TableCell className="font-medium">
                          <CopyField value={policy.PolicyName}>
                            {policy.PolicyName}
                          </CopyField>
                        </TableCell>
                        <TableCell>
                          <CopyField value={policy.Arn} displayValue={truncateArn(policy.Arn)} />
                        </TableCell>
                        <TableCell>
                          <CopyField value={formatDateTime(policy.CreateDate)}>
                            {formatDateTime(policy.CreateDate)}
                          </CopyField>
                        </TableCell>
                        <TableCell>
                          <Badge variant="secondary">{policy.AttachmentCount}</Badge>
                        </TableCell>
                        <TableCell>
                          <Button 
                            variant="outline" 
                            size="sm"
                            onClick={() => router.push(`/policy/${policyId}`)}
                          >
                            View Details
                          </Button>
                        </TableCell>
                      </TableRow>
                    );})}
                  </TableBody>
                </Table>
              ) : (
                <div className="text-center py-8">
                  <p className="text-muted-foreground">
                    {searchTerm ? 'No AWS managed policies match your search.' : 'No AWS managed policies found.'}
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="groups" className="space-y-4">
          <div className="flex items-center space-x-2">
            <Search className="h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search groups..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="max-w-sm"
            />
          </div>
          
          <Card>
            <CardHeader>
              <CardTitle>Groups</CardTitle>
              <CardDescription>
                {filteredGroups.length} of {Object.keys(groups).length} groups
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Group Name</TableHead>
                    <TableHead>ARN</TableHead>
                    <TableHead>Create Date</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredGroups.map(([groupId, group]) => (
                    <TableRow key={groupId}>
                      <TableCell className="font-medium">
                        <CopyField value={group.GroupName}>
                          {group.GroupName}
                        </CopyField>
                      </TableCell>
                      <TableCell>
                        <CopyField value={group.Arn} displayValue={truncateArn(group.Arn)} />
                      </TableCell>
                      <TableCell>
                        <CopyField value={formatDateTime(group.CreateDate)}>
                          {formatDateTime(group.CreateDate)}
                        </CopyField>
                      </TableCell>
                      <TableCell>
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => router.push(`/group/${groupId}`)}
                        >
                          View Details
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security" className="space-y-4">
          <div className="flex items-center space-x-2">
            <Search className="h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search flagged policies..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="max-w-sm"
            />
          </div>
          
          {/* High Risk Policies */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <AlertTriangle className="h-5 w-5 text-red-600" />
                <span>High Risk Policies</span>
                <Badge variant="destructive">
                  {securityAnalysis.filter(p => p.isHighRisk).length}
                </Badge>
              </CardTitle>
              <CardDescription>
                Policies with dangerous permissions that could lead to privilege escalation
              </CardDescription>
            </CardHeader>
            <CardContent>
              {securityAnalysis.filter(p => p.isHighRisk).length > 0 ? (
                <div className="space-y-4">
                  {securityAnalysis
                    .filter(p => p.isHighRisk)
                    .filter(p => 
                      p.policyName.toLowerCase().includes(searchTerm.toLowerCase()) ||
                      p.flags.some(flag => flag.title.toLowerCase().includes(searchTerm.toLowerCase()))
                    )
                    .map((analysis) => (
                      <Card key={analysis.policyId} className="border-red-200">
                        <CardHeader className="pb-3">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-2">
                              <FileText className="h-4 w-4" />
                              <span className="font-medium">{analysis.policyName}</span>
                              
                            </div>
                            <Button 
                              variant="outline" 
                              size="sm"
                              onClick={() => router.push(`/policy/${analysis.policyId}`)}
                            >
                              View Details
                            </Button>
                          </div>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            {analysis.flags.map((flag, index) => (
                              <div key={index} className="flex items-start space-x-2 p-2 bg-red-50 rounded-md">
                                <AlertTriangle className={`h-4 w-4 mt-0.5 ${flag.severity === 'HIGH' ? 'text-red-600' : flag.severity === 'MEDIUM' ? 'text-yellow-600' : 'text-blue-600'}`} />
                                <div className="flex-1">
                                  <div className="flex items-center space-x-2">
                                    <span className="font-medium text-sm">{flag.title}</span>
                                    <Badge variant={flag.severity === 'HIGH' ? 'destructive' : flag.severity === 'MEDIUM' ? 'secondary' : 'outline'}>
                                      {flag.severity}
                                    </Badge>
                                  </div>
                                  <p className="text-sm text-muted-foreground mt-1">{flag.description}</p>
                                  <p className="text-xs text-blue-600 mt-1">
                                    <strong>Recommendation:</strong> {flag.recommendation}
                                  </p>
                                </div>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                </div>
              ) : (
                <div className="text-center py-8">
                  <Shield className="h-12 w-12 mx-auto mb-4 text-green-600" />
                  <p className="text-muted-foreground">
                    {searchTerm ? 'No high-risk policies match your search.' : 'No high-risk policies found. Your IAM configuration looks secure!'}
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* All Security Flags */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <AlertCircle className="h-5 w-5" />
                <span>All Security Flags</span>
                <Badge variant="secondary">
                  {securityAnalysis.reduce((sum, p) => sum + p.flags.length, 0)}
                </Badge>
              </CardTitle>
              <CardDescription>
                Complete list of all security issues found in policies
              </CardDescription>
            </CardHeader>
            <CardContent>
              {securityAnalysis.some(p => p.flags.length > 0) ? (
                <div className="space-y-4">
                  {securityAnalysis
                    .filter(p => p.flags.length > 0)
                    .filter(p => 
                      p.policyName.toLowerCase().includes(searchTerm.toLowerCase()) ||
                      p.flags.some(flag => flag.title.toLowerCase().includes(searchTerm.toLowerCase()))
                    )
                    .map((analysis) => (
                      <Card key={analysis.policyId} className={analysis.isHighRisk ? "border-red-200" : "border-yellow-200"}>
                        <CardHeader className="pb-3">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-2">
                              <FileText className="h-4 w-4" />
                              <span className="font-medium">{analysis.policyName}</span>
                              <Badge variant={analysis.isHighRisk ? "destructive" : "secondary"}>
                                {analysis.flags.length} flags
                              </Badge>
                              
                            </div>
                            <Button 
                              variant="outline" 
                              size="sm"
                              onClick={() => router.push(`/policy/${analysis.policyId}`)}
                            >
                              View Details
                            </Button>
                          </div>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            {analysis.flags.map((flag, index) => (
                              <div key={index} className={`flex items-start space-x-2 p-2 rounded-md ${
                                flag.severity === 'HIGH' ? 'bg-red-50' : 
                                flag.severity === 'MEDIUM' ? 'bg-yellow-50' : 
                                'bg-blue-50'
                              }`}>
                                <AlertCircle className={`h-4 w-4 mt-0.5 ${
                                  flag.severity === 'HIGH' ? 'text-red-600' : 
                                  flag.severity === 'MEDIUM' ? 'text-yellow-600' : 
                                  'text-blue-600'
                                }`} />
                                <div className="flex-1">
                                  <div className="flex items-center space-x-2">
                                    <span className="font-medium text-sm">{flag.title}</span>
                                    <Badge variant={flag.severity === 'HIGH' ? 'destructive' : flag.severity === 'MEDIUM' ? 'secondary' : 'outline'}>
                                      {flag.severity}
                                    </Badge>
                                  </div>
                                  <p className="text-sm text-muted-foreground mt-1">{flag.description}</p>
                                  <p className="text-xs text-blue-600 mt-1">
                                    <strong>Recommendation:</strong> {flag.recommendation}
                                  </p>
                                </div>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                </div>
              ) : (
                <div className="text-center py-8">
                  <Shield className="h-12 w-12 mx-auto mb-4 text-green-600" />
                  <p className="text-muted-foreground">
                    {searchTerm ? 'No security flags match your search.' : 'No security flags found. Your policies are secure!'}
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
} 