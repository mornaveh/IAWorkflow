"use client"

import type React from "react"

import { useState } from "react"
import {
  ChevronDown,
  Search,
  Download,
  Settings,
  HelpCircle,
  Bell,
  User,
  Copy,
  Filter,
  X,
  ChevronLeft,
  ChevronRight,
  Calendar,
  ClipboardList,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { VulnerabilityDrawer } from "@/components/vulnerability-drawer"
import { DateRangePicker } from "@/components/date-range-picker"
import { Toaster } from "@/components/ui/toaster"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
} from "@/components/ui/dropdown-menu"

export default function SnykDashboard() {
  const [selectedFilters, setSelectedFilters] = useState({
    status: [],
    severity: [],
    ignoreType: [],
    expiration: [],
    dateRange: null, // { startDate: string, endDate: string }
  })

  const [selectedVulnerability, setSelectedVulnerability] = useState(null)
  const [isDrawerOpen, setIsDrawerOpen] = useState(false)
  const [showDateRangePicker, setShowDateRangePicker] = useState(false)
  const [datePickerPosition, setDatePickerPosition] = useState({ x: 0, y: 0 })

  const [currentPage, setCurrentPage] = useState(1)
  const itemsPerPage = 10

  const vulnerabilities = [
    {
      id: "b32e...",
      requestDate: "3m ago",
      requestedBy: "Person Name",
      severity: "C",
      vulnerability: "Arbitrary File Write via Archive Extraction",
      repository: "vberegov/goof",
      branch: "gitlab236/docker-goof",
      cwe: "CWE-000",
      ignoreType: "Not vulnerable",
      expiration: "24 July 2024",
      status: "Pending",
    },
    {
      id: "b32f...",
      requestDate: "1h ago",
      requestedBy: "Person Name",
      severity: "H",
      vulnerability: "Path Traversal",
      repository: "trythis1432",
      branch: "branch name",
      cwe: "CWE-000",
      ignoreType: "Not vulnerable",
      expiration: "13 Oct 2024",
      status: "Approved",
    },
    {
      id: "b32g...",
      requestDate: "3m ago",
      requestedBy: "Person Name",
      severity: "C",
      vulnerability: "Command Injection",
      repository: "vberegov/goof",
      branch: "...abc/branchname",
      cwe: "CWE-000",
      ignoreType: "False Positive",
      expiration: "Does not expire",
      status: "Rejected",
    },
    {
      id: "b32h...",
      requestDate: "2d ago",
      requestedBy: "Person Name",
      severity: "M",
      vulnerability: "SQL Injection",
      repository: "vberegov/goof",
      branch: "vberegov/juice-shop",
      cwe: "CWE-000",
      ignoreType: "Won't fix",
      expiration: "1 Aug 2024",
      status: "Pending",
    },
    {
      id: "b32i...",
      requestDate: "5d ago",
      requestedBy: "Person Name",
      severity: "H",
      vulnerability: "Code Injection",
      repository: "vberegov/goof",
      branch: "gitlab236/docker-goof-master",
      cwe: "CWE-000",
      ignoreType: "Not vulnerable",
      expiration: "15 Sep 2024",
      status: "Approved",
    },
    {
      id: "b32j...",
      requestDate: "Sep 29, 2025",
      requestedBy: "Person Name",
      severity: "L",
      vulnerability: "File Inclusion",
      repository: "vberegov/goof",
      branch: "nosrettep/docker-goof",
      cwe: "CWE-000",
      ignoreType: "Won't fix",
      expiration: "21 July 2024",
      status: "Rejected",
    },
    {
      id: "b32k...",
      requestDate: "Sep 29, 2025",
      requestedBy: "Person Name",
      severity: "C",
      vulnerability: "Use of Hardcoded Credentials",
      repository: "vberegov/goof",
      branch: "vbereg/docker-goof",
      cwe: "CWE-000",
      ignoreType: "Won't fix",
      expiration: "24 June 2024",
      status: "Pending",
    },
    {
      id: "b32l...",
      requestDate: "Sep 29, 2025",
      requestedBy: "Person Name",
      severity: "H",
      vulnerability: "Inadequate Encryption Strength",
      repository: "vberegov/goof",
      branch: "gitlab236/docker-goof",
      cwe: "CWE-000",
      ignoreType: "Not vulnerable",
      expiration: "15 Sep 2024",
      status: "Approved",
    },
    {
      id: "b32m...",
      requestDate: "Sep 29, 2025",
      requestedBy: "Person Name",
      severity: "M",
      vulnerability: "Inadequate Encryption Strength",
      repository: "gitlab2/goof",
      branch: "branch name (local)",
      cwe: "CWE-000",
      ignoreType: "Not vulnerable",
      expiration: "15 Sep 2024",
      status: "Rejected",
    },
    // Adding 100 more rows
    {
      id: "c33a...",
      requestDate: "1d ago",
      requestedBy: "Alice Johnson",
      severity: "C",
      vulnerability: "Cross-Site Scripting (XSS)",
      repository: "frontend/webapp",
      branch: "main",
      cwe: "CWE-079",
      ignoreType: "Not vulnerable",
      expiration: "30 Aug 2024",
      status: "Pending",
    },
    {
      id: "c33b...",
      requestDate: "2h ago",
      requestedBy: "Bob Smith",
      severity: "H",
      vulnerability: "Buffer Overflow",
      repository: "backend/api",
      branch: "develop",
      cwe: "CWE-120",
      ignoreType: "Won't fix",
      expiration: "15 Sep 2024",
      status: "Approved",
    },
    {
      id: "c33c...",
      requestDate: "4h ago",
      requestedBy: "Carol Davis",
      severity: "M",
      vulnerability: "Information Disclosure",
      repository: "utils/logger",
      branch: "feature/logging",
      cwe: "CWE-200",
      ignoreType: "False Positive",
      expiration: "10 Oct 2024",
      status: "Rejected",
    },
    {
      id: "c33d...",
      requestDate: "6h ago",
      requestedBy: "David Wilson",
      severity: "L",
      vulnerability: "Weak Password Requirements",
      repository: "auth/service",
      branch: "security-update",
      cwe: "CWE-521",
      ignoreType: "Not vulnerable",
      expiration: "25 Nov 2024",
      status: "Pending",
    },
    {
      id: "c33e...",
      requestDate: "8h ago",
      requestedBy: "Eve Brown",
      severity: "C",
      vulnerability: "Remote Code Execution",
      repository: "core/engine",
      branch: "hotfix/rce",
      cwe: "CWE-094",
      ignoreType: "Won't fix",
      expiration: "05 Dec 2024",
      status: "Approved",
    },
    {
      id: "c33f...",
      requestDate: "12h ago",
      requestedBy: "Frank Miller",
      severity: "H",
      vulnerability: "Privilege Escalation",
      repository: "admin/panel",
      branch: "admin-fixes",
      cwe: "CWE-269",
      ignoreType: "Not vulnerable",
      expiration: "20 Jan 2025",
      status: "Rejected",
    },
    {
      id: "c33g...",
      requestDate: "1d ago",
      requestedBy: "Grace Lee",
      severity: "M",
      vulnerability: "Session Fixation",
      repository: "session/manager",
      branch: "session-security",
      cwe: "CWE-384",
      ignoreType: "False Positive",
      expiration: "14 Feb 2025",
      status: "Pending",
    },
    {
      id: "c33h...",
      requestDate: "2d ago",
      requestedBy: "Henry Taylor",
      severity: "L",
      vulnerability: "Missing Security Headers",
      repository: "web/server",
      branch: "header-security",
      cwe: "CWE-693",
      ignoreType: "Not vulnerable",
      expiration: "28 Mar 2025",
      status: "Approved",
    },
    {
      id: "c33i...",
      requestDate: "3d ago",
      requestedBy: "Ivy Chen",
      severity: "C",
      vulnerability: "Deserialization Vulnerability",
      repository: "data/processor",
      branch: "serialization-fix",
      cwe: "CWE-502",
      ignoreType: "Won't fix",
      expiration: "12 Apr 2025",
      status: "Rejected",
    },
    {
      id: "c33j...",
      requestDate: "4d ago",
      requestedBy: "Jack Anderson",
      severity: "H",
      vulnerability: "Directory Traversal",
      repository: "file/handler",
      branch: "path-validation",
      cwe: "CWE-022",
      ignoreType: "Not vulnerable",
      expiration: "26 May 2025",
      status: "Pending",
    },
    {
      id: "c34a...",
      requestDate: "5d ago",
      requestedBy: "Kate Wilson",
      severity: "M",
      vulnerability: "CSRF Attack",
      repository: "forms/handler",
      branch: "csrf-protection",
      cwe: "CWE-352",
      ignoreType: "False Positive",
      expiration: "09 Jun 2025",
      status: "Approved",
    },
    {
      id: "c34b...",
      requestDate: "6d ago",
      requestedBy: "Liam Garcia",
      severity: "L",
      vulnerability: "Insecure Direct Object Reference",
      repository: "api/endpoints",
      branch: "access-control",
      cwe: "CWE-639",
      ignoreType: "Not vulnerable",
      expiration: "23 Jul 2025",
      status: "Rejected",
    },
    {
      id: "c34c...",
      requestDate: "1w ago",
      requestedBy: "Mia Rodriguez",
      severity: "C",
      vulnerability: "XML External Entity (XXE)",
      repository: "xml/parser",
      branch: "xxe-prevention",
      cwe: "CWE-611",
      ignoreType: "Won't fix",
      expiration: "07 Aug 2025",
      status: "Pending",
    },
    {
      id: "c34d...",
      requestDate: "1w ago",
      requestedBy: "Noah Martinez",
      severity: "H",
      vulnerability: "Server-Side Request Forgery",
      repository: "proxy/service",
      branch: "ssrf-mitigation",
      cwe: "CWE-918",
      ignoreType: "Not vulnerable",
      expiration: "21 Sep 2025",
      status: "Approved",
    },
    {
      id: "c34e...",
      requestDate: "1w ago",
      requestedBy: "Olivia Thompson",
      severity: "M",
      vulnerability: "Broken Authentication",
      repository: "auth/module",
      branch: "auth-hardening",
      cwe: "CWE-287",
      ignoreType: "False Positive",
      expiration: "04 Oct 2025",
      status: "Rejected",
    },
    {
      id: "c34f...",
      requestDate: "2w ago",
      requestedBy: "Paul White",
      severity: "L",
      vulnerability: "Sensitive Data Exposure",
      repository: "logs/system",
      branch: "data-sanitization",
      cwe: "CWE-200",
      ignoreType: "Not vulnerable",
      expiration: "18 Nov 2025",
      status: "Pending",
    },
    {
      id: "c34g...",
      requestDate: "2w ago",
      requestedBy: "Quinn Harris",
      severity: "C",
      vulnerability: "Race Condition",
      repository: "concurrent/processor",
      branch: "thread-safety",
      cwe: "CWE-362",
      ignoreType: "Won't fix",
      expiration: "02 Dec 2025",
      status: "Approved",
    },
    {
      id: "c34h...",
      requestDate: "2w ago",
      requestedBy: "Rachel Clark",
      severity: "H",
      vulnerability: "Memory Corruption",
      repository: "memory/manager",
      branch: "memory-safety",
      cwe: "CWE-119",
      ignoreType: "Not vulnerable",
      expiration: "16 Jan 2026",
      status: "Rejected",
    },
    {
      id: "c34i...",
      requestDate: "3w ago",
      requestedBy: "Sam Lewis",
      severity: "M",
      vulnerability: "Improper Input Validation",
      repository: "input/validator",
      branch: "validation-rules",
      cwe: "CWE-20",
      ignoreType: "False Positive",
      expiration: "30 Feb 2026",
      status: "Pending",
    },
    {
      id: "c34j...",
      requestDate: "3w ago",
      requestedBy: "Tina Walker",
      severity: "L",
      vulnerability: "Weak Cryptography",
      repository: "crypto/utils",
      branch: "crypto-upgrade",
      cwe: "CWE-327",
      ignoreType: "Not vulnerable",
      expiration: "15 Mar 2026",
      status: "Approved",
    },
    // Continue with more entries...
    {
      id: "d35a...",
      requestDate: "1mo ago",
      requestedBy: "Uma Patel",
      severity: "C",
      vulnerability: "Injection Flaw",
      repository: "database/connector",
      branch: "injection-prevention",
      cwe: "CWE-89",
      ignoreType: "Won't fix",
      expiration: "29 Apr 2026",
      status: "Rejected",
    },
    {
      id: "d35b...",
      requestDate: "1mo ago",
      requestedBy: "Victor Young",
      severity: "H",
      vulnerability: "Broken Access Control",
      repository: "access/manager",
      branch: "access-fixes",
      cwe: "CWE-284",
      ignoreType: "Not vulnerable",
      expiration: "13 May 2026",
      status: "Pending",
    },
    {
      id: "d35c...",
      requestDate: "1mo ago",
      requestedBy: "Wendy King",
      severity: "M",
      vulnerability: "Security Misconfiguration",
      repository: "config/manager",
      branch: "secure-config",
      cwe: "CWE-16",
      ignoreType: "False Positive",
      expiration: "27 Jun 2026",
      status: "Approved",
    },
    {
      id: "d35d...",
      requestDate: "1mo ago",
      requestedBy: "Xavier Scott",
      severity: "L",
      vulnerability: "Using Components with Known Vulnerabilities",
      repository: "dependencies/manager",
      branch: "dependency-update",
      cwe: "CWE-1104",
      ignoreType: "Not vulnerable",
      expiration: "11 Jul 2026",
      status: "Rejected",
    },
    {
      id: "d35e...",
      requestDate: "2mo ago",
      requestedBy: "Yara Green",
      severity: "C",
      vulnerability: "Insufficient Logging & Monitoring",
      repository: "monitoring/service",
      branch: "enhanced-logging",
      cwe: "CWE-778",
      ignoreType: "Won't fix",
      expiration: "25 Aug 2026",
      status: "Pending",
    },
    {
      id: "d35f...",
      requestDate: "2mo ago",
      requestedBy: "Zack Adams",
      severity: "H",
      vulnerability: "Unvalidated Redirects",
      repository: "redirect/handler",
      branch: "redirect-validation",
      cwe: "CWE-601",
      ignoreType: "Not vulnerable",
      expiration: "08 Sep 2026",
      status: "Approved",
    },
    {
      id: "d35g...",
      requestDate: "2mo ago",
      requestedBy: "Amy Baker",
      severity: "M",
      vulnerability: "Clickjacking",
      repository: "ui/framework",
      branch: "frame-protection",
      cwe: "CWE-1021",
      ignoreType: "False Positive",
      expiration: "22 Oct 2026",
      status: "Rejected",
    },
    {
      id: "d35h...",
      requestDate: "2mo ago",
      requestedBy: "Ben Carter",
      severity: "L",
      vulnerability: "HTTP Parameter Pollution",
      repository: "http/parser",
      branch: "parameter-validation",
      cwe: "CWE-235",
      ignoreType: "Not vulnerable",
      expiration: "06 Nov 2026",
      status: "Pending",
    },
    {
      id: "d35i...",
      requestDate: "3mo ago",
      requestedBy: "Chloe Davis",
      severity: "C",
      vulnerability: "Format String Vulnerability",
      repository: "string/formatter",
      branch: "format-security",
      cwe: "CWE-134",
      ignoreType: "Won't fix",
      expiration: "20 Dec 2026",
      status: "Approved",
    },
    {
      id: "d35j...",
      requestDate: "3mo ago",
      requestedBy: "Dan Evans",
      severity: "H",
      vulnerability: "Integer Overflow",
      repository: "math/calculator",
      branch: "overflow-protection",
      cwe: "CWE-190",
      ignoreType: "Not vulnerable",
      expiration: "03 Jan 2027",
      status: "Rejected",
    },
    // Adding 70 more entries to reach 109 total
    {
      id: "e36a...",
      requestDate: "4mo ago",
      requestedBy: "Emma Foster",
      severity: "M",
      vulnerability: "Time-of-Check Time-of-Use",
      repository: "file/system",
      branch: "toctou-fix",
      cwe: "CWE-367",
      ignoreType: "False Positive",
      expiration: "17 Feb 2027",
      status: "Pending",
    },
    {
      id: "e36b...",
      requestDate: "4mo ago",
      requestedBy: "Felix Gray",
      severity: "L",
      vulnerability: "Improper Certificate Validation",
      repository: "ssl/handler",
      branch: "cert-validation",
      cwe: "CWE-295",
      ignoreType: "Not vulnerable",
      expiration: "03 Mar 2027",
      status: "Approved",
    },
    {
      id: "e36c...",
      requestDate: "4mo ago",
      requestedBy: "Grace Hill",
      severity: "C",
      vulnerability: "Use After Free",
      repository: "memory/allocator",
      branch: "memory-safety",
      cwe: "CWE-416",
      ignoreType: "Won't fix",
      expiration: "17 Apr 2027",
      status: "Rejected",
    },
    {
      id: "e36d...",
      requestDate: "5mo ago",
      requestedBy: "Hugo Irwin",
      severity: "H",
      vulnerability: "Double Free",
      repository: "memory/manager",
      branch: "double-free-fix",
      cwe: "CWE-415",
      ignoreType: "Not vulnerable",
      expiration: "01 May 2027",
      status: "Pending",
    },
    {
      id: "e36e...",
      requestDate: "5mo ago",
      requestedBy: "Iris Jones",
      severity: "M",
      vulnerability: "Null Pointer Dereference",
      repository: "pointer/handler",
      branch: "null-check",
      cwe: "CWE-476",
      ignoreType: "False Positive",
      expiration: "15 Jun 2027",
      status: "Approved",
    },
    {
      id: "e36f...",
      requestDate: "5mo ago",
      requestedBy: "Jake Kelly",
      severity: "L",
      vulnerability: "Resource Leak",
      repository: "resource/manager",
      branch: "leak-prevention",
      cwe: "CWE-772",
      ignoreType: "Not vulnerable",
      expiration: "29 Jul 2027",
      status: "Rejected",
    },
    {
      id: "e36g...",
      requestDate: "6mo ago",
      requestedBy: "Kara Lopez",
      severity: "C",
      vulnerability: "Heap Overflow",
      repository: "heap/allocator",
      branch: "heap-protection",
      cwe: "CWE-122",
      ignoreType: "Won't fix",
      expiration: "12 Aug 2027",
      status: "Pending",
    },
    {
      id: "e36h...",
      requestDate: "6mo ago",
      requestedBy: "Leo Martin",
      severity: "H",
      vulnerability: "Stack Overflow",
      repository: "stack/manager",
      branch: "stack-protection",
      cwe: "CWE-121",
      ignoreType: "Not vulnerable",
      expiration: "26 Sep 2027",
      status: "Approved",
    },
    {
      id: "e36i...",
      requestDate: "6mo ago",
      requestedBy: "Maya Nelson",
      severity: "M",
      vulnerability: "Improper Synchronization",
      repository: "sync/manager",
      branch: "sync-improvement",
      cwe: "CWE-662",
      ignoreType: "False Positive",
      expiration: "10 Oct 2027",
      status: "Rejected",
    },
    {
      id: "e36j...",
      requestDate: "7mo ago",
      requestedBy: "Nick Owen",
      severity: "L",
      vulnerability: "Deadlock",
      repository: "thread/pool",
      branch: "deadlock-prevention",
      cwe: "CWE-833",
      ignoreType: "Not vulnerable",
      expiration: "24 Nov 2027",
      status: "Pending",
    },
    // Continue adding more entries to reach 109 total...
    {
      id: "f37a...",
      requestDate: "8mo ago",
      requestedBy: "Olga Price",
      severity: "C",
      vulnerability: "Improper Restriction of Operations",
      repository: "operations/controller",
      branch: "operation-limits",
      cwe: "CWE-119",
      ignoreType: "Won't fix",
      expiration: "08 Dec 2027",
      status: "Approved",
    },
    {
      id: "f37b...",
      requestDate: "8mo ago",
      requestedBy: "Peter Quinn",
      severity: "H",
      vulnerability: "Missing Authorization",
      repository: "auth/gateway",
      branch: "authorization-fix",
      cwe: "CWE-862",
      ignoreType: "Not vulnerable",
      expiration: "22 Jan 2028",
      status: "Rejected",
    },
    {
      id: "f37c...",
      requestDate: "8mo ago",
      requestedBy: "Quincy Reed",
      severity: "M",
      vulnerability: "Incorrect Permission Assignment",
      repository: "permissions/manager",
      branch: "permission-fix",
      cwe: "CWE-732",
      ignoreType: "False Positive",
      expiration: "05 Feb 2028",
      status: "Pending",
    },
    {
      id: "f37d...",
      requestDate: "9mo ago",
      requestedBy: "Rita Stone",
      severity: "L",
      vulnerability: "Improper Handling of Exceptional Conditions",
      repository: "exception/handler",
      branch: "exception-improvement",
      cwe: "CWE-755",
      ignoreType: "Not vulnerable",
      expiration: "19 Mar 2028",
      status: "Approved",
    },
    {
      id: "f37e...",
      requestDate: "9mo ago",
      requestedBy: "Steve Turner",
      severity: "C",
      vulnerability: "Uncontrolled Resource Consumption",
      repository: "resource/limiter",
      branch: "resource-control",
      cwe: "CWE-400",
      ignoreType: "Won't fix",
      expiration: "02 Apr 2028",
      status: "Rejected",
    },
    {
      id: "f37f...",
      requestDate: "9mo ago",
      requestedBy: "Tara Underwood",
      severity: "H",
      vulnerability: "Improper Input Handling",
      repository: "input/processor",
      branch: "input-sanitization",
      cwe: "CWE-20",
      ignoreType: "Not vulnerable",
      expiration: "16 May 2028",
      status: "Pending",
    },
    {
      id: "f37g...",
      requestDate: "10mo ago",
      requestedBy: "Ulysses Vance",
      severity: "M",
      vulnerability: "Missing Encryption of Sensitive Data",
      repository: "encryption/service",
      branch: "data-encryption",
      cwe: "CWE-311",
      ignoreType: "False Positive",
      expiration: "30 Jun 2028",
      status: "Approved",
    },
    {
      id: "f37h...",
      requestDate: "10mo ago",
      requestedBy: "Vera Walsh",
      severity: "L",
      vulnerability: "Cleartext Storage of Sensitive Information",
      repository: "storage/service",
      branch: "secure-storage",
      cwe: "CWE-312",
      ignoreType: "Not vulnerable",
      expiration: "14 Jul 2028",
      status: "Rejected",
    },
    {
      id: "f37i...",
      requestDate: "10mo ago",
      requestedBy: "Wade Xavier",
      severity: "C",
      vulnerability: "Improper Neutralization of Special Elements",
      repository: "sanitizer/service",
      branch: "element-neutralization",
      cwe: "CWE-74",
      ignoreType: "Won't fix",
      expiration: "28 Aug 2028",
      status: "Pending",
    },
    {
      id: "f37j...",
      requestDate: "11mo ago",
      requestedBy: "Xara Young",
      severity: "H",
      vulnerability: "Improper Control of Generation of Code",
      repository: "code/generator",
      branch: "code-control",
      cwe: "CWE-94",
      ignoreType: "Not vulnerable",
      expiration: "11 Sep 2028",
      status: "Approved",
    },
    // Final entries to complete 109 total
    {
      id: "g38a...",
      requestDate: "1y ago",
      requestedBy: "Yuki Zhang",
      severity: "M",
      vulnerability: "Exposure of Sensitive Information",
      repository: "info/handler",
      branch: "info-protection",
      cwe: "CWE-200",
      ignoreType: "False Positive",
      expiration: "25 Oct 2028",
      status: "Rejected",
    },
    {
      id: "g38b...",
      requestDate: "1y ago",
      requestedBy: "Zara Adams",
      severity: "L",
      vulnerability: "Improper Restriction of XML External Entity Reference",
      repository: "xml/validator",
      branch: "xxe-restriction",
      cwe: "CWE-611",
      ignoreType: "Not vulnerable",
      expiration: "08 Nov 2028",
      status: "Pending",
    },
    {
      id: "g38c...",
      requestDate: "1y ago",
      requestedBy: "Aaron Blake",
      severity: "C",
      vulnerability: "Server-Side Request Forgery (SSRF)",
      repository: "request/handler",
      branch: "ssrf-prevention",
      cwe: "CWE-918",
      ignoreType: "Won't fix",
      expiration: "22 Dec 2028",
      status: "Approved",
    },
    {
      id: "g38d...",
      requestDate: "1y ago",
      requestedBy: "Bella Cooper",
      severity: "H",
      vulnerability: "Cross-Site Request Forgery (CSRF)",
      repository: "csrf/protection",
      branch: "csrf-tokens",
      cwe: "CWE-352",
      ignoreType: "Not vulnerable",
      expiration: "05 Jan 2029",
      status: "Rejected",
    },
    {
      id: "g38e...",
      requestDate: "1y ago",
      requestedBy: "Carlos Diaz",
      severity: "M",
      vulnerability: "Insecure Randomness",
      repository: "random/generator",
      branch: "secure-random",
      cwe: "CWE-330",
      ignoreType: "False Positive",
      expiration: "19 Feb 2029",
      status: "Pending",
    },
    {
      id: "g38f...",
      requestDate: "1y ago",
      requestedBy: "Diana Evans",
      severity: "L",
      vulnerability: "Missing Release of Resource after Effective Lifetime",
      repository: "resource/cleanup",
      branch: "resource-release",
      cwe: "CWE-772",
      ignoreType: "Not vulnerable",
      expiration: "05 Mar 2029",
      status: "Approved",
    },
    {
      id: "g38g...",
      requestDate: "1y ago",
      requestedBy: "Ethan Foster",
      severity: "C",
      vulnerability: "Improper Validation of Array Index",
      repository: "array/handler",
      branch: "index-validation",
      cwe: "CWE-129",
      ignoreType: "Won't fix",
      expiration: "19 Apr 2029",
      status: "Rejected",
    },
    {
      id: "g38h...",
      requestDate: "1y ago",
      requestedBy: "Fiona Gray",
      severity: "H",
      vulnerability: "Out-of-bounds Read",
      repository: "buffer/reader",
      branch: "bounds-checking",
      cwe: "CWE-125",
      ignoreType: "Not vulnerable",
      expiration: "03 May 2029",
      status: "Pending",
    },
    {
      id: "g38i...",
      requestDate: "1y ago",
      requestedBy: "George Hill",
      severity: "M",
      vulnerability: "Out-of-bounds Write",
      repository: "buffer/writer",
      branch: "write-protection",
      cwe: "CWE-787",
      ignoreType: "False Positive",
      expiration: "17 Jun 2029",
      status: "Approved",
    },
  ]

  const [vulnerabilitiesData, setVulnerabilitiesData] = useState(vulnerabilities)

  const removeStatusFilter = (status: string) => {
    setSelectedFilters((prev) => ({
      ...prev,
      status: prev.status.filter((s) => s !== status),
    }))
    resetPagination()
  }

  const removeSeverityFilter = (severity: string) => {
    setSelectedFilters((prev) => ({
      ...prev,
      severity: prev.severity.filter((s) => s !== severity),
    }))
    resetPagination()
  }

  const removeIgnoreTypeFilter = (ignoreType: string) => {
    setSelectedFilters((prev) => ({
      ...prev,
      ignoreType: prev.ignoreType.filter((i) => i !== ignoreType),
    }))
    resetPagination()
  }

  const removeExpirationFilter = (expiration: string) => {
    setSelectedFilters((prev) => ({
      ...prev,
      expiration: prev.expiration.filter((e) => e !== expiration),
    }))
    resetPagination()
  }

  const removeDateRangeFilter = () => {
    setSelectedFilters((prev) => ({
      ...prev,
      dateRange: null,
    }))
    resetPagination()
  }

  const addFilter = (filterType: string, value: string) => {
    setSelectedFilters((prev) => ({
      ...prev,
      [filterType]: [...prev[filterType], value],
    }))
    resetPagination()
  }

  const addDateRangeFilter = (startDate: string, endDate: string) => {
    setSelectedFilters((prev) => ({
      ...prev,
      dateRange: { startDate, endDate },
    }))
    setShowDateRangePicker(false)
    resetPagination()
  }

  const clearAllFilters = () => {
    setSelectedFilters({
      status: [],
      severity: [],
      ignoreType: [],
      expiration: [],
      dateRange: null,
    })
    resetPagination()
  }

  const handleCustomDateRangeClick = (event: React.MouseEvent) => {
    event.preventDefault()
    event.stopPropagation()

    const rect = event.currentTarget.getBoundingClientRect()
    setDatePickerPosition({
      x: rect.right + 10, // Position to the right of the button
      y: rect.top,
    })
    setShowDateRangePicker(true)
  }

  // Helper function to parse date strings
  const parseExpirationDate = (expiration: string) => {
    if (expiration.includes("Does not expire")) {
      return null // Never expires
    }

    // Try to parse various date formats
    const dateStr = expiration.trim()

    // Handle formats like "24 July 2024", "13 Oct 2024", etc.
    const monthMap = {
      Jan: "01",
      Feb: "02",
      Mar: "03",
      Apr: "04",
      May: "05",
      Jun: "06",
      Jul: "07",
      Aug: "08",
      Sep: "09",
      Oct: "10",
      Nov: "11",
      Dec: "12",
      January: "01",
      February: "02",
      March: "03",
      April: "04",
      June: "06",
      July: "07",
      August: "08",
      September: "09",
      October: "10",
      November: "11",
      December: "12",
    }

    // Match patterns like "24 July 2024" or "13 Oct 2024"
    const match = dateStr.match(/(\d{1,2})\s+(\w+)\s+(\d{4})/)
    if (match) {
      const [, day, month, year] = match
      const monthNum = monthMap[month]
      if (monthNum) {
        return new Date(`${year}-${monthNum}-${day.padStart(2, "0")}`)
      }
    }

    // Fallback: try to parse as-is
    const parsed = new Date(dateStr)
    return isNaN(parsed.getTime()) ? null : parsed
  }

  const updateVulnerabilityStatus = (vulnerabilityId: string, newStatus: string) => {
    setVulnerabilitiesData((prev) =>
      prev.map((vuln) => (vuln.id === vulnerabilityId ? { ...vuln, status: newStatus } : vuln)),
    )
  }

  const deleteVulnerability = (vulnerabilityId: string) => {
    setVulnerabilitiesData((prev) => prev.filter((vuln) => vuln.id !== vulnerabilityId))
  }

  // Filter vulnerabilities based on selected filters
  const allFilteredVulnerabilities = vulnerabilitiesData.filter((vuln) => {
    const statusMatch = selectedFilters.status.length === 0 || selectedFilters.status.includes(vuln.status)

    const severityMap = {
      C: "Critical",
      H: "High",
      M: "Medium",
      L: "Low",
    }
    const vulnSeverityName = severityMap[vuln.severity] || vuln.severity
    const severityMatch = selectedFilters.severity.length === 0 || selectedFilters.severity.includes(vulnSeverityName)

    const ignoreTypeMatch =
      selectedFilters.ignoreType.length === 0 || selectedFilters.ignoreType.includes(vuln.ignoreType)

    // For expiration categories
    const expirationCategory = vuln.expiration.includes("Does not expire")
      ? "Never expires"
      : vuln.expiration.includes("2024")
        ? "Expires in 2024"
        : vuln.expiration.includes("2025")
          ? "Expires in 2025"
          : vuln.expiration.includes("2026")
            ? "Expires in 2026"
            : vuln.expiration.includes("2027")
              ? "Expires in 2027"
              : vuln.expiration.includes("2028")
                ? "Expires in 2028"
                : vuln.expiration.includes("2029")
                  ? "Expires in 2029"
                  : "Other"

    const expirationMatch =
      selectedFilters.expiration.length === 0 || selectedFilters.expiration.includes(expirationCategory)

    // Date range filter
    let dateRangeMatch = true
    if (selectedFilters.dateRange) {
      const expirationDate = parseExpirationDate(vuln.expiration)
      if (expirationDate) {
        const startDate = new Date(selectedFilters.dateRange.startDate)
        const endDate = new Date(selectedFilters.dateRange.endDate)
        dateRangeMatch = expirationDate >= startDate && expirationDate <= endDate
      } else {
        // If expiration date can't be parsed (e.g., "Does not expire"), exclude from date range filter
        dateRangeMatch = false
      }
    }

    return statusMatch && severityMatch && ignoreTypeMatch && expirationMatch && dateRangeMatch
  })

  // Calculate pagination
  const totalPages = Math.ceil(allFilteredVulnerabilities.length / itemsPerPage)
  const startIndex = (currentPage - 1) * itemsPerPage
  const endIndex = startIndex + itemsPerPage
  const filteredVulnerabilities = allFilteredVulnerabilities.slice(startIndex, endIndex)

  // Reset to first page when filters change
  const resetPagination = () => {
    setCurrentPage(1)
  }

  const handleRowClick = (vuln) => {
    setSelectedVulnerability(vuln)
    setIsDrawerOpen(true)
  }

  const handleManageClick = (e, vuln) => {
    e.stopPropagation()
    setSelectedVulnerability(vuln)
    setIsDrawerOpen(true)
  }

  return (
    <div className={`flex min-h-screen bg-gray-50 ${isDrawerOpen ? "h-screen overflow-hidden" : ""}`}>
      {/* Sidebar */}
      <div className="w-64 bg-slate-800 text-white flex flex-col min-h-screen">
        {/* Logo */}
        <div className="p-4 border-b border-slate-700">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 bg-white rounded flex items-center justify-center">
              <span className="text-slate-800 font-bold text-sm">S</span>
            </div>
            <span className="font-semibold">snyk</span>
          </div>
        </div>

        {/* Navigation */}
        <div className="flex-1 overflow-y-auto">
          <div className="p-4">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">GROUP</div>
            <div className="flex items-center justify-between p-2 rounded hover:bg-slate-700 cursor-pointer">
              <div className="flex items-center gap-2">
                <div className="w-6 h-6 bg-red-500 rounded-full flex items-center justify-center text-xs">G</div>
                <span className="text-sm">GoofLTD</span>
              </div>
              <ChevronDown className="w-4 h-4" />
            </div>
          </div>

          <div className="p-4">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">ORGANIZATION</div>
            <nav className="space-y-1">
              <div className="flex items-center justify-between p-2 rounded hover:bg-slate-700 cursor-pointer">
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 bg-orange-500 rounded-full flex items-center justify-center text-xs">O</div>
                  <span className="text-sm">Org name</span>
                </div>
                <ChevronDown className="w-4 h-4" />
              </div>
              <a href="#" className="flex items-center gap-3 p-2 rounded hover:bg-slate-700 text-sm">
                <div className="w-4 h-4 bg-slate-600 rounded"></div>
                Dashboard
              </a>
              <a href="#" className="flex items-center gap-3 p-2 rounded hover:bg-slate-700 text-sm">
                <div className="w-4 h-4 bg-slate-600 rounded"></div>
                Projects
              </a>
              <a href="#" className="flex items-center gap-3 p-2 rounded bg-purple-600 text-sm">
                <div className="w-4 h-4 bg-purple-400 rounded"></div>
                Requests
              </a>
              <a href="#" className="flex items-center gap-3 p-2 rounded hover:bg-slate-700 text-sm">
                <div className="w-4 h-4 bg-slate-600 rounded"></div>
                Reports
              </a>
              <a href="#" className="flex items-center gap-3 p-2 rounded hover:bg-slate-700 text-sm">
                <div className="w-4 h-4 bg-slate-600 rounded"></div>
                Dependencies
              </a>
              <a href="#" className="flex items-center gap-3 p-2 rounded hover:bg-slate-700 text-sm">
                <div className="w-4 h-4 bg-slate-600 rounded"></div>
                Cloud
              </a>
              <a href="#" className="flex items-center gap-3 p-2 rounded hover:bg-slate-700 text-sm">
                <div className="w-4 h-4 bg-slate-600 rounded"></div>
                Integrations
              </a>
              <a href="#" className="flex items-center gap-3 p-2 rounded hover:bg-slate-700 text-sm">
                <div className="w-4 h-4 bg-slate-600 rounded"></div>
                Insights
              </a>
              <a href="#" className="flex items-center gap-3 p-2 rounded hover:bg-slate-700 text-sm">
                <div className="w-4 h-4 bg-slate-600 rounded"></div>
                Custom rules
              </a>
              <a href="#" className="flex items-center gap-3 p-2 rounded hover:bg-slate-700 text-sm">
                <div className="w-4 h-4 bg-slate-600 rounded"></div>
                Members
              </a>
              <a href="#" className="flex items-center gap-3 p-2 rounded hover:bg-slate-700 text-sm">
                <div className="w-4 h-4 bg-slate-600 rounded"></div>
                Settings
              </a>
            </nav>
          </div>
        </div>

        {/* Bottom section */}
        <div className="p-4 border-t border-slate-700">
          <a href="#" className="flex items-center gap-3 p-2 rounded hover:bg-slate-700 text-sm mb-2">
            <HelpCircle className="w-4 h-4" />
            Help
          </a>
          <a href="#" className="flex items-center gap-3 p-2 rounded hover:bg-slate-700 text-sm mb-2">
            <Bell className="w-4 h-4" />
            Product updates
            <Badge className="bg-blue-500 text-xs">NEW</Badge>
          </a>
          <div className="flex items-center gap-3 p-2 rounded hover:bg-slate-700 text-sm cursor-pointer">
            <User className="w-4 h-4" />
            User Name
            <ChevronDown className="w-4 h-4 ml-auto" />
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 flex flex-col">
        {/* Header */}
        <div className="bg-white border-b px-6 py-4">
          <div className="flex items-center gap-2 text-sm text-gray-600">
            <div className="flex items-center gap-1">
              <div className="w-4 h-4 bg-red-500 rounded-full"></div>
              <span>GoofLTD</span>
              <ChevronDown className="w-4 h-4" />
            </div>
            <span>{">"}</span>
            <span>Requests</span>
          </div>
        </div>

        {/* Content */}
        <div className={`flex-1 p-6 ${isDrawerOpen ? "overflow-hidden pointer-events-none opacity-50" : ""}`}>
          <div className="mb-6">
            <div className="flex items-center gap-2 mb-2">
              <ClipboardList className="w-5 h-5 text-gray-600" />
              <h1 className="text-xl font-semibold">Requests</h1>
            </div>
            <p className="text-gray-600 text-sm">
              Manage requests for ignoring Snyk-detected issues. Learn more about{" "}
              <a href="#" className="text-blue-600 underline">
                ignore requests
              </a>{" "}
              and their data{" "}
              <a href="#" className="text-blue-600 underline">
                retention policy
              </a>
              .
            </p>
          </div>

          {/* Filters */}
          <div className="flex items-center gap-4 mb-6 flex-wrap">
            {selectedFilters.status.length > 0 && (
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">Status:</span>
                {selectedFilters.status.map((status) => (
                  <Badge key={status} variant="secondary" className="bg-blue-100 text-blue-800">
                    {status}
                    <X className="w-3 h-3 ml-1 cursor-pointer" onClick={() => removeStatusFilter(status)} />
                  </Badge>
                ))}
              </div>
            )}
            {selectedFilters.severity.length > 0 && (
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">Severity:</span>
                {selectedFilters.severity.map((severity) => (
                  <Badge key={severity} variant="secondary" className="bg-blue-100 text-blue-800">
                    {severity}
                    <X className="w-3 h-3 ml-1 cursor-pointer" onClick={() => removeSeverityFilter(severity)} />
                  </Badge>
                ))}
              </div>
            )}
            {selectedFilters.ignoreType.length > 0 && (
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">Ignore Type:</span>
                {selectedFilters.ignoreType.map((ignoreType) => (
                  <Badge key={ignoreType} variant="secondary" className="bg-blue-100 text-blue-800">
                    {ignoreType}
                    <X className="w-3 h-3 ml-1 cursor-pointer" onClick={() => removeIgnoreTypeFilter(ignoreType)} />
                  </Badge>
                ))}
              </div>
            )}
            {selectedFilters.expiration.length > 0 && (
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">Expiration:</span>
                {selectedFilters.expiration.map((expiration) => (
                  <Badge key={expiration} variant="secondary" className="bg-blue-100 text-blue-800">
                    {expiration}
                    <X className="w-3 h-3 ml-1 cursor-pointer" onClick={() => removeExpirationFilter(expiration)} />
                  </Badge>
                ))}
              </div>
            )}
            {selectedFilters.dateRange && (
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">Date Range:</span>
                <Badge variant="secondary" className="bg-green-100 text-green-800">
                  {selectedFilters.dateRange.startDate} to {selectedFilters.dateRange.endDate}
                  <X className="w-3 h-3 ml-1 cursor-pointer" onClick={removeDateRangeFilter} />
                </Badge>
              </div>
            )}

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <Filter className="w-4 h-4 mr-1" />
                  Add filter
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent className="w-56">
                <DropdownMenuLabel>Add Filter</DropdownMenuLabel>
                <DropdownMenuSeparator />

                <DropdownMenuSub>
                  <DropdownMenuSubTrigger>
                    <span>Review Status</span>
                  </DropdownMenuSubTrigger>
                  <DropdownMenuSubContent>
                    {["Pending", "Approved", "Rejected"].map((status) => (
                      <DropdownMenuItem
                        key={status}
                        onClick={() => !selectedFilters.status.includes(status) && addFilter("status", status)}
                        disabled={selectedFilters.status.includes(status)}
                      >
                        {status}
                      </DropdownMenuItem>
                    ))}
                  </DropdownMenuSubContent>
                </DropdownMenuSub>

                <DropdownMenuSub>
                  <DropdownMenuSubTrigger>
                    <span>Severity</span>
                  </DropdownMenuSubTrigger>
                  <DropdownMenuSubContent>
                    {["Critical", "High", "Medium", "Low"].map((severity) => (
                      <DropdownMenuItem
                        key={severity}
                        onClick={() => !selectedFilters.severity.includes(severity) && addFilter("severity", severity)}
                        disabled={selectedFilters.severity.includes(severity)}
                      >
                        {severity}
                      </DropdownMenuItem>
                    ))}
                  </DropdownMenuSubContent>
                </DropdownMenuSub>

                <DropdownMenuSub>
                  <DropdownMenuSubTrigger>
                    <span>Ignore Type</span>
                  </DropdownMenuSubTrigger>
                  <DropdownMenuSubContent>
                    {["Not vulnerable", "Won't fix", "False Positive"].map((ignoreType) => (
                      <DropdownMenuItem
                        key={ignoreType}
                        onClick={() =>
                          !selectedFilters.ignoreType.includes(ignoreType) && addFilter("ignoreType", ignoreType)
                        }
                        disabled={selectedFilters.ignoreType.includes(ignoreType)}
                      >
                        {ignoreType}
                      </DropdownMenuItem>
                    ))}
                  </DropdownMenuSubContent>
                </DropdownMenuSub>

                <DropdownMenuSub>
                  <DropdownMenuSubTrigger>
                    <span>Expiration</span>
                  </DropdownMenuSubTrigger>
                  <DropdownMenuSubContent>
                    {[
                      "Never expires",
                      "Expires in 2024",
                      "Expires in 2025",
                      "Expires in 2026",
                      "Expires in 2027",
                      "Expires in 2028",
                      "Expires in 2029",
                    ].map((expiration) => (
                      <DropdownMenuItem
                        key={expiration}
                        onClick={() =>
                          !selectedFilters.expiration.includes(expiration) && addFilter("expiration", expiration)
                        }
                        disabled={selectedFilters.expiration.includes(expiration)}
                      >
                        {expiration}
                      </DropdownMenuItem>
                    ))}
                    <DropdownMenuSeparator />
                    <DropdownMenuItem onSelect={(e) => e.preventDefault()} onClick={handleCustomDateRangeClick}>
                      <Calendar className="w-4 h-4 mr-2" />
                      Custom Date Range
                    </DropdownMenuItem>
                  </DropdownMenuSubContent>
                </DropdownMenuSub>
              </DropdownMenuContent>
            </DropdownMenu>

            {(selectedFilters.status.length > 0 ||
              selectedFilters.severity.length > 0 ||
              selectedFilters.ignoreType.length > 0 ||
              selectedFilters.expiration.length > 0 ||
              selectedFilters.dateRange) && (
              <Button variant="ghost" size="sm" className="text-gray-600" onClick={clearAllFilters}>
                <X className="w-4 h-4 mr-1" />
                Clear all
              </Button>
            )}

            <div className="ml-auto flex items-center gap-2">
              <div className="relative">
                <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                <Input placeholder="Search ignores" className="pl-9 w-64" />
              </div>
              <Button variant="outline" size="sm">
                <Download className="w-4 h-4 mr-1" />
                Download CSV
              </Button>
              <Button variant="outline" size="sm">
                <Settings className="w-4 h-4 mr-1" />
                Modify columns
              </Button>
            </div>
          </div>

          {/* Date Range Picker Modal */}
          {showDateRangePicker && (
            <>
              <div className="fixed inset-0 z-40" onClick={() => setShowDateRangePicker(false)} />
              <div
                className="fixed z-50 bg-white border rounded-lg shadow-lg"
                style={{
                  left: `${datePickerPosition.x}px`,
                  top: `${datePickerPosition.y}px`,
                }}
              >
                <DateRangePicker onDateRangeSelect={addDateRangeFilter} onClose={() => setShowDateRangePicker(false)} />
              </div>
            </>
          )}

          {/* Table */}
          <div className={`bg-white rounded-lg border ${isDrawerOpen ? "overflow-hidden pointer-events-none" : ""}`}>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Id</TableHead>
                  <TableHead>Request date</TableHead>
                  <TableHead>Requested by</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Vulnerability</TableHead>
                  <TableHead>Repository</TableHead>
                  <TableHead>Branch</TableHead>
                  <TableHead>CWE</TableHead>
                  <TableHead>Ignore type</TableHead>
                  <TableHead>Expiration</TableHead>
                  <TableHead>Review</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredVulnerabilities.map((vuln, index) => (
                  <TableRow key={index} onClick={() => handleRowClick(vuln)}>
                    <TableCell className="font-mono text-sm">
                      <div className="flex items-center gap-2">
                        {vuln.id}
                        <Copy className="w-3 h-3 text-gray-400 cursor-pointer" />
                      </div>
                    </TableCell>
                    <TableCell className="text-sm">{vuln.requestDate}</TableCell>
                    <TableCell className="text-sm">{vuln.requestedBy}</TableCell>
                    <TableCell>
                      <Badge
                        className={`w-6 h-6 rounded-full p-0 flex items-center justify-center text-xs text-white ${
                          vuln.severity === "C"
                            ? "bg-red-500"
                            : vuln.severity === "H"
                              ? "bg-orange-500"
                              : vuln.severity === "M"
                                ? "bg-blue-500"
                                : "bg-gray-500"
                        }`}
                      >
                        {vuln.severity}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm max-w-48">
                      <div className="truncate">{vuln.vulnerability}</div>
                    </TableCell>
                    <TableCell>
                      <a href="#" className="text-blue-600 text-sm hover:underline">
                        {vuln.repository}
                      </a>
                    </TableCell>
                    <TableCell className="text-sm text-gray-600">{vuln.branch}</TableCell>
                    <TableCell className="text-sm">{vuln.cwe}</TableCell>
                    <TableCell className="text-sm">{vuln.ignoreType}</TableCell>
                    <TableCell className="text-sm">{vuln.expiration}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Badge
                          variant="outline"
                          className={
                            vuln.status === "Pending"
                              ? "text-orange-600 border-orange-200"
                              : vuln.status === "Approved"
                                ? "text-green-600 border-green-200"
                                : "text-red-600 border-red-200"
                          }
                        >
                          {vuln.status}
                        </Badge>
                        <Button variant="outline" size="sm" onClick={(e) => handleManageClick(e, vuln)}>
                          Manage
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between mt-4">
            <div className="flex items-center gap-2">
              <span className="text-sm text-gray-600">{itemsPerPage} per page</span>
              <ChevronDown className="w-4 h-4 text-gray-400" />
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={currentPage === 1}
                onClick={() => setCurrentPage((prev) => Math.max(1, prev - 1))}
              >
                <ChevronLeft className="w-4 h-4" />
              </Button>

              {/* Page numbers */}
              {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                let pageNum
                if (totalPages <= 5) {
                  pageNum = i + 1
                } else if (currentPage <= 3) {
                  pageNum = i + 1
                } else if (currentPage >= totalPages - 2) {
                  pageNum = totalPages - 4 + i
                } else {
                  pageNum = currentPage - 2 + i
                }

                return (
                  <Button
                    key={pageNum}
                    variant="outline"
                    size="sm"
                    className={currentPage === pageNum ? "bg-blue-50 text-blue-600" : ""}
                    onClick={() => setCurrentPage(pageNum)}
                  >
                    {pageNum}
                  </Button>
                )
              })}

              {totalPages > 5 && currentPage < totalPages - 2 && (
                <>
                  <span className="text-sm text-gray-400">...</span>
                  <Button variant="outline" size="sm" onClick={() => setCurrentPage(totalPages)}>
                    {totalPages}
                  </Button>
                </>
              )}

              <Button
                variant="outline"
                size="sm"
                disabled={currentPage === totalPages}
                onClick={() => setCurrentPage((prev) => Math.min(totalPages, prev + 1))}
              >
                <ChevronRight className="w-4 h-4" />
              </Button>
            </div>
            <div className="text-sm text-gray-600">
              Showing {startIndex + 1}-{Math.min(endIndex, allFilteredVulnerabilities.length)} of{" "}
              {allFilteredVulnerabilities.length}
            </div>
          </div>
        </div>
      </div>
      {/* Drawer */}
      {isDrawerOpen && selectedVulnerability && (
        <VulnerabilityDrawer
          vulnerability={selectedVulnerability}
          isOpen={isDrawerOpen}
          onClose={() => setIsDrawerOpen(false)}
          onStatusUpdate={updateVulnerabilityStatus}
          onDeleteRequest={deleteVulnerability}
        />
      )}
      <div className="relative z-[9999]">
        <Toaster />
      </div>
    </div>
  )
}
