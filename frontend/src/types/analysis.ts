export interface SecurityOverview {
  title: string;
  total_vulnerabilities: number;
  missing_packages_count: number;
  recommended_updates_count: number;
  affected_packages_count: number;
}

export interface SeverityDistribution {
  level: string;
  count: number;
}

export interface TopVulnerability {
  cve_id: string;
  package: string;
  severity: string;
  description: string;
  fix_version: string;
  ai_priority_score?: number;
  ai_reasoning?: string;
}

export interface MaliciousCodeEntry {
  file: string;
  dangerous_functions: string[];
  obfuscation_detected: boolean;
  hardcoded_api_keys: boolean;
  ai_analysis?: {
    malicious: boolean;
    confidence: number;
  };
}

export interface YaraEntry {
  file: string;
  yara_matches: string[];
}

export interface TyposquattingResult {
  file: string;
  line: number | string;
  pkg_line: string;
  similarity: number;
  typo_pkg: string;
  official_pkg: string;
  message?: string;
}

export interface DependencyConfusionResult {
  file: string;
  line: number | string;
  dependency: string;
  distributor: string;
  risk: string;
  message?: string;
}

export interface PackageInfo {
  package_name: string;
  version: string;
  license: string;
  download_link: string;
}

export interface Vulnerability {
  cve_id: string;
  package: string;
  installed_version: string;
  severity: string;
}

export interface UpdateRecommendation {
  package_name: string;
  installed_version: string;
  recommended_versions: string[];
  severities: string[];
  cve_list: string[];
}

export interface RiskScore {
  total_score: number;
  level: string;
  breakdown: {
    cve_score: number;
    typosquatting_score: number;
    dependency_confusion_score: number;
    malware_score: number;
  };
}

export interface AiPrioritizedVulnerability extends TopVulnerability {
  priority_score: number;
  ai_reason: string;
}

export interface AiCodeReview {
  repository: string;
  total_files_analyzed: number;
  flagged_files: number;
  high_risk_files: number;
  detected_patterns: string[];
  details: {
    file: string;
    combined_score: number;
    flags: string[];
    entropy: number;
  }[];
}

export interface AiInsights {
  repository: string;
  analysis_date: string;
  risk_score: RiskScore;
  ai_summary: string;
  prioritized_vulnerabilities: AiPrioritizedVulnerability[];
  code_review?: AiCodeReview;
  security_overview?: SecurityOverview;
}

export interface AnalysisData {
  repository: string;
  repository_url: string;
  analysis_date: string;
  security_overview: SecurityOverview;
  severity_distribution: SeverityDistribution[];
  top_vulnerabilities: TopVulnerability[];
  malicious_code_analysis: MaliciousCodeEntry[];
  yara_analysis: YaraEntry[];
  // 백엔드 키: typosquatting_analysis / dependency_confusion_analysis
  typosquatting_results: TyposquattingResult[];
  typosquatting_analysis: TyposquattingResult[];
  dependency_confusion_results: DependencyConfusionResult[];
  dependency_confusion_analysis: DependencyConfusionResult[];
  package_count: number;
  packages: PackageInfo[];
  vulnerability_count: number;
  vulnerabilities: Vulnerability[];
  update_recommendations_count: number;
  updates: UpdateRecommendation[];
  // 백엔드 키: update_recommendations (dict 형태)
  update_recommendations: Record<string, unknown>;
}
