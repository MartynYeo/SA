import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { AlertTriangle, Shield, Download, FileText } from 'lucide-react';
import { PolicyAnalysisResult } from '@/lib/policy-analysis';

interface SecurityReportProps {
  analysisResults: PolicyAnalysisResult[];
  totalPolicies: number;
  onExport?: () => void;
}

export function SecurityReport({ analysisResults, totalPolicies, onExport }: SecurityReportProps) {
  const highRiskPolicies = analysisResults.filter(p => p.isHighRisk);
  const totalFlags = analysisResults.reduce((sum, p) => sum + p.flags.length, 0);
  const highSeverityFlags = analysisResults.reduce((sum, p) => 
    sum + p.flags.filter(f => f.severity === 'HIGH').length, 0);
  const mediumSeverityFlags = analysisResults.reduce((sum, p) => 
    sum + p.flags.filter(f => f.severity === 'MEDIUM').length, 0);
  const lowSeverityFlags = analysisResults.reduce((sum, p) => 
    sum + p.flags.filter(f => f.severity === 'LOW').length, 0);

  // Risk score removed; focusing on counts and severity

  const generateReportText = () => {
    const report = [
      'IAM Security Analysis Report',
      '============================',
      '',
      `Generated: ${new Date().toLocaleString()}`,
      `Total Policies Analyzed: ${totalPolicies}`,
      '',
      'SUMMARY',
      '-------',
      `High Risk Policies: ${highRiskPolicies.length}`,
      `Total Security Flags: ${totalFlags}`,
      `  - High Severity: ${highSeverityFlags}`,
      `  - Medium Severity: ${mediumSeverityFlags}`,
      `  - Low Severity: ${lowSeverityFlags}`,
      // risk score removed from report summary
      '',
      'HIGH RISK POLICIES',
      '------------------',
    ];

    if (highRiskPolicies.length > 0) {
      highRiskPolicies.forEach(policy => {
        report.push(`Policy: ${policy.policyName}`);
        // risk score removed per request
        report.push(`Flags: ${policy.flags.length}`);
        policy.flags.forEach(flag => {
          report.push(`  - ${flag.severity}: ${flag.title}`);
          report.push(`    Description: ${flag.description}`);
          report.push(`    Recommendation: ${flag.recommendation}`);
        });
        report.push('');
      });
    } else {
      report.push('No high-risk policies found.');
      report.push('');
    }

    report.push('RECOMMENDATIONS');
    report.push('---------------');
    report.push('1. Review all high-risk policies immediately');
    report.push('2. Implement principle of least privilege');
    report.push('3. Remove wildcard permissions where possible');
    report.push('4. Restrict PassRole permissions to specific roles');
    report.push('5. Regularly audit IAM policies for security issues');

    return report.join('\n');
  };

  const handleExport = () => {
    const reportText = generateReportText();
    const blob = new Blob([reportText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `iam-security-report-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    if (onExport) {
      onExport();
    }
  };

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className={highRiskPolicies.length > 0 ? "border-red-200 bg-red-50" : ""}>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">High Risk Policies</CardTitle>
            <AlertTriangle className={`h-4 w-4 ${highRiskPolicies.length > 0 ? "text-red-600" : "text-muted-foreground"}`} />
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${highRiskPolicies.length > 0 ? "text-red-600" : ""}`}>
              {highRiskPolicies.length}
            </div>
            <p className="text-xs text-muted-foreground">
              of {totalPolicies} policies
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Flags</CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalFlags}</div>
            <p className="text-xs text-muted-foreground">
              Security issues found
            </p>
          </CardContent>
        </Card>

        

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Security Status</CardTitle>
            <Shield className={`h-4 w-4 ${highRiskPolicies.length > 0 ? "text-red-600" : "text-green-600"}`} />
          </CardHeader>
          <CardContent>
            <div className={`text-lg font-bold ${highRiskPolicies.length > 0 ? "text-red-600" : "text-green-600"}`}>
              {highRiskPolicies.length > 0 ? "⚠️ At Risk" : "✅ Secure"}
            </div>
            <p className="text-xs text-muted-foreground">
              Overall assessment
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Flag Breakdown */}
      <Card>
        <CardHeader>
          <CardTitle>Security Flag Breakdown</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="text-center p-4 bg-red-50 rounded-lg">
              <div className="text-2xl font-bold text-red-600">{highSeverityFlags}</div>
              <div className="text-sm text-red-700">High Severity</div>
            </div>
            <div className="text-center p-4 bg-yellow-50 rounded-lg">
              <div className="text-2xl font-bold text-yellow-600">{mediumSeverityFlags}</div>
              <div className="text-sm text-yellow-700">Medium Severity</div>
            </div>
            <div className="text-center p-4 bg-blue-50 rounded-lg">
              <div className="text-2xl font-bold text-blue-600">{lowSeverityFlags}</div>
              <div className="text-sm text-blue-700">Low Severity</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Export Report */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Download className="h-5 w-5" />
            <span>Export Security Report</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground mb-4">
            Download a comprehensive security analysis report in text format for offline review and compliance documentation.
          </p>
          <Button onClick={handleExport} className="w-full md:w-auto">
            <Download className="h-4 w-4 mr-2" />
            Download Report
          </Button>
        </CardContent>
      </Card>

      {/* Top Risk Policies */}
      {highRiskPolicies.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <AlertTriangle className="h-5 w-5 text-red-600" />
              <span>High Risk Policies</span>
              <Badge variant="destructive">{highRiskPolicies.length}</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {highRiskPolicies.map((policy) => (
                <div key={policy.policyId} className="border border-red-200 rounded-lg p-4 bg-red-50">
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="font-semibold text-red-800">{policy.policyName}</h3>
                  </div>
                  <div className="space-y-2">
                    {policy.flags.map((flag, index) => (
                      <div key={index} className="text-sm">
                        <span className="font-medium text-red-700">{flag.title}:</span>
                        <span className="text-red-600 ml-2">{flag.description}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
