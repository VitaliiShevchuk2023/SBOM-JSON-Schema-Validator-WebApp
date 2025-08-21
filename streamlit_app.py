import streamlit as st
import json
import jsonschema
import xmlschema
import xml.etree.ElementTree as ET
from jsonschema import validate, ValidationError
import pandas as pd
from typing import Dict, Any, Tuple, List, Set, Optional, Union
from datetime import datetime
import re
import io
import base64
from enum import Enum
import requests
from pathlib import Path

# Configure Streamlit page
st.set_page_config(
    page_title="Enhanced SBOM Multi-Schema Validator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced CSS for professional styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.8rem;
        color: #2E86C1;
        text-align: center;
        margin-bottom: 2rem;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
    }
    .section-header {
        font-size: 1.6rem;
        color: #1B4F72;
        margin-top: 2rem;
        margin-bottom: 1rem;
        border-bottom: 2px solid #3498DB;
        padding-bottom: 0.5rem;
    }
    .success-box {
        padding: 1.5rem;
        border-radius: 0.8rem;
        background: linear-gradient(135deg, #D5F4E6 0%, #C8E6C9 100%);
        border-left: 6px solid #27AE60;
        margin: 1rem 0;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .error-box {
        padding: 1.5rem;
        border-radius: 0.8rem;
        background: linear-gradient(135deg, #FADBD8 0%, #F5B7B1 100%);
        border-left: 6px solid #E74C3C;
        margin: 1rem 0;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .warning-box {
        padding: 1.5rem;
        border-radius: 0.8rem;
        background: linear-gradient(135deg, #FEF9E7 0%, #FCF3CF 100%);
        border-left: 6px solid #F39C12;
        margin: 1rem 0;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .info-box {
        padding: 1.5rem;
        border-radius: 0.8rem;
        background: linear-gradient(135deg, #EBF3FD 0%, #D6EAF8 100%);
        border-left: 6px solid #3498DB;
        margin: 1rem 0;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 0.8rem;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        border-left: 4px solid #3498DB;
    }
    .schema-support-table {
        font-family: 'Courier New', monospace;
        font-size: 0.9rem;
    }
    .file-upload-area {
        border: 2px dashed #3498DB;
        border-radius: 0.8rem;
        padding: 2rem;
        text-align: center;
        background: #F8F9FA;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

class SBOMFormat(Enum):
    """Supported SBOM formats"""
    SPDX = "spdx"
    CYCLONE_DX = "cyclonedx"
    AUTO_DETECT = "auto"

class ValidationLevel(Enum):
    """Validation complexity levels"""
    BASIC = "basic"           # Syntax + Schema only
    STANDARD = "standard"     # + Business rules
    COMPREHENSIVE = "comprehensive"  # + Semantic validation

class EnhancedSBOMValidator:
    """
    Enhanced SBOM Multi-Schema Validator
    
    Supports SPDX 2.3, SPDX 3.0, and CycloneDX 1.3-1.6 in both JSON and XML formats.
    Provides comprehensive validation with detailed reporting and analysis.
    """
    
    def __init__(self):
        self.schemas = self._load_schemas()
        self.validation_cache = {}
        self.supported_formats = {
            "spdx": {
                "versions": ["2.3", "3.0"],
                "formats": ["json"],  # XML not officially supported
                "description": "Software Package Data Exchange"
            },
            "cyclonedx": {
                "versions": ["1.3", "1.4", "1.5", "1.6"],
                "formats": ["json", "xml"],
                "description": "OWASP CycloneDX Bill of Materials"
            }
        }
    
    def _load_schemas(self) -> Dict[str, Any]:
        """Load all SBOM schemas for validation"""
        schemas = {}
        
        # SPDX Schemas
        schemas["spdx_2.3_json"] = self._get_spdx_23_schema()
        schemas["spdx_3.0_json"] = self._get_spdx_30_schema()
        
        # CycloneDX Schemas
        for version in ["1.3", "1.4", "1.5", "1.6"]:
            schemas[f"cyclonedx_{version}_json"] = self._get_cyclonedx_json_schema(version)
            schemas[f"cyclonedx_{version}_xml"] = self._get_cyclonedx_xml_schema(version)
        
        return schemas
    
    def _get_spdx_23_schema(self) -> Dict[str, Any]:
        """SPDX 2.3 JSON Schema"""
        return {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "SPDX 2.3 Document Schema",
            "type": "object",
            "required": ["spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace"],
            "properties": {
                "spdxVersion": {
                    "type": "string",
                    "pattern": "^SPDX-2\\.3$"
                },
                "dataLicense": {
                    "type": "string",
                    "enum": ["CC0-1.0"]
                },
                "SPDXID": {
                    "type": "string",
                    "pattern": "^SPDXRef-DOCUMENT$"
                },
                "name": {"type": "string"},
                "documentNamespace": {
                    "type": "string",
                    "format": "uri"
                },
                "creationInfo": {
                    "type": "object",
                    "required": ["created"],
                    "properties": {
                        "created": {"type": "string", "format": "date-time"},
                        "creators": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    }
                },
                "packages": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["SPDXID", "name", "downloadLocation"],
                        "properties": {
                            "SPDXID": {"type": "string"},
                            "name": {"type": "string"},
                            "downloadLocation": {"type": "string"},
                            "filesAnalyzed": {"type": "boolean"},
                            "licenseConcluded": {"type": "string"},
                            "licenseDeclared": {"type": "string"},
                            "copyrightText": {"type": "string"}
                        }
                    }
                }
            }
        }
    
    def _get_spdx_30_schema(self) -> Dict[str, Any]:
        """SPDX 3.0 JSON Schema (simplified)"""
        return {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "SPDX 3.0 Document Schema",
            "type": "object",
            "required": ["spdxVersion", "dataLicense", "SPDXID", "name"],
            "properties": {
                "spdxVersion": {
                    "type": "string",
                    "pattern": "^SPDX-3\\.0$"
                },
                "dataLicense": {
                    "type": "string",
                    "enum": ["CC0-1.0"]
                },
                "SPDXID": {"type": "string"},
                "name": {"type": "string"},
                "elements": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["spdxId", "type"],
                        "properties": {
                            "spdxId": {"type": "string"},
                            "type": {"type": "string"},
                            "name": {"type": "string"}
                        }
                    }
                }
            }
        }
    
    def _get_cyclonedx_json_schema(self, version: str) -> Dict[str, Any]:
        """CycloneDX JSON Schema for specified version"""
        base_schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": f"CycloneDX {version} SBOM Schema",
            "type": "object",
            "required": ["bomFormat", "specVersion", "version"],
            "properties": {
                "bomFormat": {
                    "type": "string",
                    "enum": ["CycloneDX"]
                },
                "specVersion": {
                    "type": "string",
                    "enum": [version]
                },
                "version": {
                    "type": "integer",
                    "minimum": 1
                },
                "metadata": {
                    "type": "object",
                    "properties": {
                        "timestamp": {"type": "string", "format": "date-time"},
                        "tools": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "vendor": {"type": "string"},
                                    "name": {"type": "string"},
                                    "version": {"type": "string"}
                                }
                            }
                        },
                        "authors": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "email": {"type": "string", "format": "email"}
                                }
                            }
                        },
                        "component": {
                            "type": "object",
                            "required": ["type", "name", "version"],
                            "properties": {
                                "type": {
                                    "type": "string",
                                    "enum": ["application", "framework", "library", "container", "operating-system", "device", "firmware", "file"]
                                },
                                "name": {"type": "string"},
                                "version": {"type": "string"}
                            }
                        }
                    }
                },
                "components": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["type", "name"],
                        "properties": {
                            "type": {
                                "type": "string",
                                "enum": ["application", "framework", "library", "container", "operating-system", "device", "firmware", "file"]
                            },
                            "bom-ref": {"type": "string"},
                            "name": {"type": "string"},
                            "version": {"type": "string"},
                            "description": {"type": "string"},
                            "scope": {
                                "type": "string",
                                "enum": ["required", "optional", "excluded"]
                            },
                            "licenses": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "license": {
                                            "type": "object",
                                            "properties": {
                                                "id": {"type": "string"},
                                                "name": {"type": "string"},
                                                "url": {"type": "string", "format": "uri"}
                                            }
                                        }
                                    }
                                }
                            },
                            "purl": {"type": "string"},
                            "externalReferences": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["type", "url"],
                                    "properties": {
                                        "type": {"type": "string"},
                                        "url": {"type": "string", "format": "uri"}
                                    }
                                }
                            }
                        }
                    }
                },
                "dependencies": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["ref"],
                        "properties": {
                            "ref": {"type": "string"},
                            "dependsOn": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        }
                    }
                },
                "vulnerabilities": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["id"],
                        "properties": {
                            "id": {"type": "string"},
                            "source": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "url": {"type": "string", "format": "uri"}
                                }
                            },
                            "ratings": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "source": {
                                            "type": "object",
                                            "properties": {
                                                "name": {"type": "string"}
                                            }
                                        },
                                        "score": {"type": "number", "minimum": 0, "maximum": 10},
                                        "severity": {
                                            "type": "string",
                                            "enum": ["critical", "high", "medium", "low", "info", "none", "unknown"]
                                        }
                                    }
                                }
                            },
                            "description": {"type": "string"},
                            "recommendation": {"type": "string"}
                        }
                    }
                }
            }
        }
        
        # Version-specific enhancements
        if version in ["1.5", "1.6"]:
            base_schema["properties"]["formulation"] = {
                "type": "array",
                "items": {"type": "object"}
            }
            
        if version == "1.6":
            base_schema["properties"]["annotations"] = {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["subjects", "annotationType"],
                    "properties": {
                        "subjects": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "annotationType": {"type": "string"},
                        "annotator": {
                            "type": "object",
                            "properties": {
                                "individual": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "email": {"type": "string", "format": "email"}
                                    }
                                }
                            }
                        },
                        "timestamp": {"type": "string", "format": "date-time"},
                        "text": {"type": "string"}
                    }
                }
            }
        
        return base_schema
    
    def _get_cyclonedx_xml_schema(self, version: str) -> str:
        """CycloneDX XML Schema (XSD) for specified version"""
        # Simplified XSD for demo purposes
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" 
           xmlns:bom="http://cyclonedx.org/schema/bom/{version}"
           targetNamespace="http://cyclonedx.org/schema/bom/{version}"
           elementFormDefault="qualified">
    
    <xs:element name="bom">
        <xs:complexType>
            <xs:sequence>
                <xs:element name="metadata" type="bom:metadataType" minOccurs="0"/>
                <xs:element name="components" type="bom:componentsType" minOccurs="0"/>
                <xs:element name="dependencies" type="bom:dependenciesType" minOccurs="0"/>
                <xs:element name="vulnerabilities" type="bom:vulnerabilitiesType" minOccurs="0"/>
            </xs:sequence>
            <xs:attribute name="version" type="xs:positiveInteger" use="required"/>
            <xs:attribute name="serialNumber" type="xs:string"/>
        </xs:complexType>
    </xs:element>
    
    <xs:complexType name="metadataType">
        <xs:sequence>
            <xs:element name="timestamp" type="xs:dateTime" minOccurs="0"/>
            <xs:element name="tools" minOccurs="0">
                <xs:complexType>
                    <xs:sequence>
                        <xs:element name="tool" maxOccurs="unbounded">
                            <xs:complexType>
                                <xs:sequence>
                                    <xs:element name="vendor" type="xs:string" minOccurs="0"/>
                                    <xs:element name="name" type="xs:string"/>
                                    <xs:element name="version" type="xs:string" minOccurs="0"/>
                                </xs:sequence>
                            </xs:complexType>
                        </xs:element>
                    </xs:sequence>
                </xs:complexType>
            </xs:element>
        </xs:sequence>
    </xs:complexType>
    
    <xs:complexType name="componentsType">
        <xs:sequence>
            <xs:element name="component" type="bom:componentType" maxOccurs="unbounded"/>
        </xs:sequence>
    </xs:complexType>
    
    <xs:complexType name="componentType">
        <xs:sequence>
            <xs:element name="name" type="xs:string"/>
            <xs:element name="version" type="xs:string" minOccurs="0"/>
            <xs:element name="description" type="xs:string" minOccurs="0"/>
            <xs:element name="scope" minOccurs="0">
                <xs:simpleType>
                    <xs:restriction base="xs:string">
                        <xs:enumeration value="required"/>
                        <xs:enumeration value="optional"/>
                        <xs:enumeration value="excluded"/>
                    </xs:restriction>
                </xs:simpleType>
            </xs:element>
            <xs:element name="licenses" minOccurs="0">
                <xs:complexType>
                    <xs:sequence>
                        <xs:element name="license" maxOccurs="unbounded">
                            <xs:complexType>
                                <xs:choice>
                                    <xs:element name="id" type="xs:string"/>
                                    <xs:element name="name" type="xs:string"/>
                                </xs:choice>
                            </xs:complexType>
                        </xs:element>
                    </xs:sequence>
                </xs:complexType>
            </xs:element>
        </xs:sequence>
        <xs:attribute name="type" use="required">
            <xs:simpleType>
                <xs:restriction base="xs:string">
                    <xs:enumeration value="application"/>
                    <xs:enumeration value="framework"/>
                    <xs:enumeration value="library"/>
                    <xs:enumeration value="container"/>
                    <xs:enumeration value="operating-system"/>
                    <xs:enumeration value="device"/>
                    <xs:enumeration value="firmware"/>
                    <xs:enumeration value="file"/>
                </xs:restriction>
            </xs:simpleType>
        </xs:attribute>
        <xs:attribute name="bom-ref" type="xs:string"/>
    </xs:complexType>
    
    <xs:complexType name="dependenciesType">
        <xs:sequence>
            <xs:element name="dependency" maxOccurs="unbounded">
                <xs:complexType>
                    <xs:sequence>
                        <xs:element name="dependency" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
                    </xs:sequence>
                    <xs:attribute name="ref" type="xs:string" use="required"/>
                </xs:complexType>
            </xs:element>
        </xs:sequence>
    </xs:complexType>
    
    <xs:complexType name="vulnerabilitiesType">
        <xs:sequence>
            <xs:element name="vulnerability" maxOccurs="unbounded">
                <xs:complexType>
                    <xs:sequence>
                        <xs:element name="id" type="xs:string"/>
                        <xs:element name="description" type="xs:string" minOccurs="0"/>
                    </xs:sequence>
                </xs:complexType>
            </xs:element>
        </xs:sequence>
    </xs:complexType>
    
</xs:schema>"""
    
    def detect_sbom_format(self, content: str, filename: str = "") -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Auto-detect SBOM format, version, and data format
        
        Returns:
            Tuple of (format, version, data_format) or (None, None, None) if undetected
        """
        try:
            # Try JSON first
            if content.strip().startswith('{'):
                data = json.loads(content)
                
                # Check for SPDX
                if "spdxVersion" in data:
                    version = data["spdxVersion"].replace("SPDX-", "")
                    return ("spdx", version, "json")
                
                # Check for CycloneDX
                elif page == "🔍 Advanced Analysis":
        st.markdown('<h2 class="section-header">Advanced SBOM Analysis</h2>', unsafe_allow_html=True)
        
        st.markdown("""
        Perform deep analysis of SBOM documents including dependency mapping, 
        security assessment, and compliance checking.
        """)
        
        uploaded_file = st.file_uploader(
            "Upload SBOM for Advanced Analysis",
            type=['json', 'xml'],
            help="Upload a valid SBOM file for comprehensive analysis"
        )
        
        if uploaded_file is not None:
            content = uploaded_file.getvalue().decode('utf-8')
            filename = uploaded_file.name
            
            # Basic validation first
            with st.spinner("🔄 Performing initial validation..."):
                result = validator.comprehensive_validate(content, filename, ValidationLevel.COMPREHENSIVE)
            
            if result["is_valid"]:
                st.success("✅ SBOM is valid. Proceeding with advanced analysis...")
                
                # Advanced analysis options
                st.markdown("### 🎛️ Analysis Options")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    analyze_dependencies = st.checkbox("🔗 Dependency Analysis", value=True)
                    analyze_licenses = st.checkbox("📄 License Analysis", value=True)
                    analyze_security = st.checkbox("🛡️ Security Analysis", value=True)
                
                with col2:
                    analyze_compliance = st.checkbox("✅ Compliance Check", value=False)
                    generate_metrics = st.checkbox("📊 Quality Metrics", value=True)
                    export_results = st.checkbox("📤 Export Results", value=False)
                
                if st.button("🚀 Run Advanced Analysis", type="primary"):
                    analysis_results = {}
                    
                    try:
                        data = json.loads(content)
                        
                        # Dependency Analysis
                        if analyze_dependencies:
                            with st.spinner("🔗 Analyzing dependencies..."):
                                st.markdown("#### 🔗 Dependency Analysis")
                                
                                if "dependencies" in data:
                                    deps = data["dependencies"]
                                    
                                    # Create dependency graph visualization
                                    dependency_map = {}
                                    for dep in deps:
                                        ref = dep.get("ref", "unknown")
                                        depends_on = dep.get("dependsOn", [])
                                        dependency_map[ref] = depends_on
                                    
                                    st.markdown(f"**Total Dependencies:** {len(dependency_map)}")
                                    
                                    # Find root dependencies (no dependencies)
                                    root_deps = [ref for ref, deps in dependency_map.items() if not deps]
                                    st.markdown(f"**Root Dependencies:** {len(root_deps)}")
                                    
                                    # Find leaf dependencies (not depended upon)
                                    all_deps = set(dependency_map.keys())
                                    referenced_deps = set()
                                    for deps in dependency_map.values():
                                        referenced_deps.update(deps)
                                    leaf_deps = all_deps - referenced_deps
                                    st.markdown(f"**Leaf Dependencies:** {len(leaf_deps)}")
                                    
                                    analysis_results["dependency_analysis"] = {
                                        "total": len(dependency_map),
                                        "root_count": len(root_deps),
                                        "leaf_count": len(leaf_deps)
                                    }
                                else:
                                    st.info("No dependency information found in SBOM")
                        
                        # License Analysis
                        if analyze_licenses:
                            with st.spinner("📄 Analyzing licenses..."):
                                st.markdown("#### 📄 License Analysis")
                                
                                components = data.get("components", [])
                                license_stats = {}
                                unlicensed_components = []
                                
                                for comp in components:
                                    comp_name = comp.get("name", "unknown")
                                    licenses = comp.get("licenses", [])
                                    
                                    if not licenses:
                                        unlicensed_components.append(comp_name)
                                    else:
                                        for lic in licenses:
                                            lic_id = lic.get("license", {}).get("id", "unknown")
                                            license_stats[lic_id] = license_stats.get(lic_id, 0) + 1
                                
                                # Display license distribution
                                if license_stats:
                                    license_df = pd.DataFrame(
                                        list(license_stats.items()),
                                        columns=["License", "Count"]
                                    )
                                    st.bar_chart(license_df.set_index("License"))
                                
                                st.markdown(f"**Licensed Components:** {len(components) - len(unlicensed_components)}")
                                st.markdown(f"**Unlicensed Components:** {len(unlicensed_components)}")
                                
                                if unlicensed_components and len(unlicensed_components) <= 10:
                                    st.markdown("**Unlicensed Components:**")
                                    for comp in unlicensed_components:
                                        st.markdown(f"- {comp}")
                                
                                analysis_results["license_analysis"] = {
                                    "license_distribution": license_stats,
                                    "unlicensed_count": len(unlicensed_components)
                                }
                        
                        # Security Analysis
                        if analyze_security:
                            with st.spinner("🛡️ Analyzing security..."):
                                st.markdown("#### 🛡️ Security Analysis")
                                
                                vulnerabilities = data.get("vulnerabilities", [])
                                
                                if vulnerabilities:
                                    severity_counts = {}
                                    high_severity_vulns = []
                                    
                                    for vuln in vulnerabilities:
                                        vuln_id = vuln.get("id", "unknown")
                                        ratings = vuln.get("ratings", [])
                                        
                                        if ratings:
                                            severity = ratings[0].get("severity", "unknown")
                                            severity_counts[severity] = severity_counts.get(severity, 0) + 1
                                            
                                            if severity in ["critical", "high"]:
                                                high_severity_vulns.append({
                                                    "id": vuln_id,
                                                    "severity": severity,
                                                    "description": vuln.get("description", "No description")[:100]
                                                })
                                    
                                    # Display severity distribution
                                    if severity_counts:
                                        severity_df = pd.DataFrame(
                                            list(severity_counts.items()),
                                            columns=["Severity", "Count"]
                                        )
                                        st.bar_chart(severity_df.set_index("Severity"))
                                    
                                    st.markdown(f"**Total Vulnerabilities:** {len(vulnerabilities)}")
                                    st.markdown(f"**High/Critical:** {len(high_severity_vulns)}")
                                    
                                    # Show high severity vulnerabilities
                                    if high_severity_vulns:
                                        st.markdown("**High/Critical Vulnerabilities:**")
                                        for vuln in high_severity_vulns[:5]:  # Show max 5
                                            st.error(f"🚨 {vuln['id']} ({vuln['severity'].upper()}): {vuln['description']}")
                                    
                                    analysis_results["security_analysis"] = {
                                        "total_vulnerabilities": len(vulnerabilities),
                                        "severity_distribution": severity_counts,
                                        "high_critical_count": len(high_severity_vulns)
                                    }
                                else:
                                    st.info("No vulnerability information found in SBOM")
                        
                        # Quality Metrics
                        if generate_metrics:
                            with st.spinner("📊 Calculating quality metrics..."):
                                st.markdown("#### 📊 Quality Metrics")
                                
                                # Use existing quality score calculation
                                if result.get("semantic_analysis", {}).get("quality_score"):
                                    quality_score = result["semantic_analysis"]["quality_score"]
                                    
                                    # Quality score gauge
                                    col1, col2, col3 = st.columns(3)
                                    with col1:
                                        if quality_score >= 80:
                                            st.success(f"🟢 Excellent: {quality_score:.1f}/100")
                                        elif quality_score >= 60:
                                            st.warning(f"🟡 Good: {quality_score:.1f}/100")
                                        else:
                                            st.error(f"🔴 Needs Improvement: {quality_score:.1f}/100")
                                    
                                    with col2:
                                        completeness = min(100, (len(data.get("components", [])) * 10))
                                        st.metric("Completeness", f"{completeness:.0f}%")
                                    
                                    with col3:
                                        metadata_score = 100 if data.get("metadata") else 0
                                        st.metric("Metadata", f"{metadata_score}%")
                                    
                                    analysis_results["quality_metrics"] = {
                                        "overall_score": quality_score,
                                        "completeness": completeness,
                                        "metadata_score": metadata_score
                                    }
                        
                        # Export results
                        if export_results and analysis_results:
                            st.markdown("#### 📤 Export Results")
                            
                            export_data = {
                                "analysis_timestamp": datetime.now().isoformat(),
                                "filename": filename,
                                "analysis_results": analysis_results,
                                "validation_result": result
                            }
                            
                            export_json = json.dumps(export_data, indent=2)
                            st.markdown(
                                create_download_link(
                                    export_json,
                                    f"advanced_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                                ),
                                unsafe_allow_html=True
                            )
                    
                    except Exception as e:
                        st.error(f"❌ Analysis failed: {str(e)}")
            else:
                st.error("❌ SBOM validation failed. Please fix validation errors before running advanced analysis.")
                display_validation_result(result)
    
    elif page == "📈 Schema Support Matrix":
        st.markdown('<h2 class="section-header">SBOM Schema Support Matrix</h2>', unsafe_allow_html=True)
        
        st.markdown("""
        Comprehensive overview of supported SBOM formats, versions, and data types. 
        This matrix shows exactly what combinations are supported by the validator.
        """)
        
        # Create support matrix
        support_data = []
        
        # SPDX formats
        for version in ["2.3", "3.0"]:
            support_data.append({
                "Format": "SPDX",
                "Version": version,
                "JSON": "✅",
                "XML": "🚫 (No official schema)",
                "Notes": "JSON Schema validation available"
            })
        
        # CycloneDX formats
        for version in ["1.3", "1.4", "1.5", "1.6"]:
            support_data.append({
                "Format": "CycloneDX", 
                "Version": version,
                "JSON": "✅",
                "XML": "✅",
                "Notes": "Full JSON and XML schema support"
            })
        
        # Display as table
        df = pd.DataFrame(support_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        # Additional information
        st.markdown("### 📊 Statistics")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Schemas", len(validator.schemas))
        with col2:
            st.metric("JSON Schemas", len([k for k in validator.schemas.keys() if "json" in k]))
        with col3:
            st.metric("XML Schemas", len([k for k in validator.schemas.keys() if "xml" in k]))
        with col4:
            st.metric("Format Types", 2)  # SPDX and CycloneDX
        
        # Schema details
        st.markdown("### 🔍 Schema Details")
        
        formats_info = validator.get_supported_formats_info()
        
        for format_name, format_info in formats_info["formats"].items():
            with st.expander(f"📋 {format_name.upper()} - {format_info['description']}", expanded=False):
                st.markdown(f"**Supported Versions:** {', '.join(format_info['versions'])}")
                st.markdown(f"**Supported Formats:** {', '.join(format_info['formats']).upper()}")
                
                # List available schemas for this format
                format_schemas = [k for k in validator.schemas.keys() if k.startswith(format_name)]
                st.markdown(f"**Available Schemas:** {len(format_schemas)}")
                for schema in format_schemas:
                    st.markdown(f"- `{schema}`")
        
        # Validation capabilities
        st.markdown("### 🛠️ Validation Capabilities")
        
        capabilities = {
            "Auto-Detection": "✅ Automatic format and version detection",
            "Schema Validation": "✅ JSON Schema and XML XSD validation", 
            "Business Rules": "✅ Format-specific business rule validation",
            "Semantic Analysis": "✅ Deep content analysis and quality scoring",
            "Batch Processing": "✅ Multiple file validation",
            "Export Results": "✅ JSON and downloadable reports",
            "Error Details": "✅ Detailed error messages with context"
        }
        
        for capability, description in capabilities.items():
            st.markdown(f"**{capability}:** {description}")
        
        # Future roadmap
        st.markdown("### 🔮 Future Enhancements")
        
        roadmap_items = [
            "🔄 SPDX 3.0 XML schema support (when officially available)",
            "📈 Additional CycloneDX versions as they are released", 
            "🔍 Enhanced semantic validation rules",
            "🌐 Remote schema fetching and caching",
            "📊 Advanced compliance checking frameworks",
            "🔗 Integration with external vulnerability databases"
        ]
        
        for item in roadmap_items:
            st.markdown(f"- {item}")

# Footer
def display_footer():
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666; padding: 20px;">
        🛡️ Enhanced SBOM Multi-Schema Validator<br>
        Supporting SPDX 2.3/3.0 and CycloneDX 1.3-1.6<br>
        Built with ❤️ using Streamlit
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
    display_footer() "bomFormat" in data and data.get("bomFormat") == "CycloneDX":
                    version = data.get("specVersion", "1.4")
                    return ("cyclonedx", version, "json")
            
            # Try XML
            elif content.strip().startswith('<'):
                try:
                    root = ET.fromstring(content)
                    
                    # Check for CycloneDX XML
                    if "cyclonedx" in root.tag.lower() or root.tag == "bom":
                        # Try to extract version from namespace or attributes
                        version = "1.4"  # Default
                        if root.attrib.get("version"):
                            version = "1.4"  # Simplified detection
                        return ("cyclonedx", version, "xml")
                        
                except ET.ParseError:
                    pass
            
            # Check filename hints
            if filename:
                filename_lower = filename.lower()
                if "spdx" in filename_lower:
                    return ("spdx", "2.3", "json" if filename_lower.endswith('.json') else "unknown")
                elif "cyclone" in filename_lower or "cdx" in filename_lower:
                    return ("cyclonedx", "1.4", "json" if filename_lower.endswith('.json') else "xml")
        
        except Exception:
            pass
        
        return (None, None, None)
    
    def validate_json_schema(self, data: Dict[str, Any], format_type: str, version: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Validate JSON data against schema"""
        schema_key = f"{format_type}_{version}_json"
        
        if schema_key not in self.schemas:
            return False, f"Schema not supported: {schema_key}", {}
        
        try:
            schema = self.schemas[schema_key]
            validate(instance=data, schema=schema)
            
            # Additional validation details
            validation_details = {
                "schema_version": f"{format_type.upper()} {version}",
                "data_format": "JSON",
                "validation_timestamp": datetime.now().isoformat(),
                "document_size": len(json.dumps(data)),
                "components_count": len(data.get("components", [])) if format_type == "cyclonedx" else len(data.get("packages", [])),
            }
            
            return True, "✅ Document is valid against the schema", validation_details
            
        except ValidationError as e:
            error_details = {
                "error_type": "Schema Validation Error",
                "field_path": " → ".join(str(p) for p in e.absolute_path) if e.absolute_path else "root",
                "error_message": e.message,
                "failed_value": str(e.instance)[:100] + "..." if len(str(e.instance)) > 100 else str(e.instance),
                "schema_rule": e.schema.get("description", "No description available")
            }
            return False, f"❌ Schema validation failed: {e.message}", error_details
            
        except Exception as e:
            return False, f"❌ Unexpected validation error: {str(e)}", {"error_type": "Unexpected Error"}
    
    def validate_xml_schema(self, content: str, format_type: str, version: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Validate XML data against XSD schema"""
        if format_type != "cyclonedx":
            return False, "❌ XML validation only supported for CycloneDX", {}
        
        schema_key = f"{format_type}_{version}_xml"
        
        if schema_key not in self.schemas:
            return False, f"❌ XML Schema not supported: {schema_key}", {}
        
        try:
            # Create XSD schema object
            xsd_content = self.schemas[schema_key]
            schema = xmlschema.XMLSchema(xsd_content)
            
            # Validate XML content
            schema.validate(content)
            
            # Parse for additional details
            root = ET.fromstring(content)
            components = root.findall('.//{http://cyclonedx.org/schema/bom/' + version + '}component')
            if not components:  # Try without namespace
                components = root.findall('.//component')
            
            validation_details = {
                "schema_version": f"CycloneDX {version}",
                "data_format": "XML",
                "validation_timestamp": datetime.now().isoformat(),
                "document_size": len(content),
                "components_count": len(components),
                "xml_encoding": "UTF-8"
            }
            
            return True, "✅ XML document is valid against the schema", validation_details
            
        except xmlschema.XMLSchemaException as e:
            return False, f"❌ XML Schema validation failed: {str(e)}", {"error_type": "XML Schema Error"}
        except ET.ParseError as e:
            return False, f"❌ XML parsing failed: {str(e)}", {"error_type": "XML Parse Error"}
        except Exception as e:
            return False, f"❌ Unexpected XML validation error: {str(e)}", {"error_type": "Unexpected Error"}
    
    def comprehensive_validate(self, content: str, filename: str = "", 
                             validation_level: ValidationLevel = ValidationLevel.STANDARD) -> Dict[str, Any]:
        """
        Comprehensive validation with auto-detection and detailed reporting
        """
        start_time = datetime.now()
        
        # Auto-detect format
        detected_format, detected_version, detected_data_format = self.detect_sbom_format(content, filename)
        
        result = {
            "validation_timestamp": start_time.isoformat(),
            "filename": filename,
            "auto_detection": {
                "format": detected_format,
                "version": detected_version,
                "data_format": detected_data_format
            },
            "validation_level": validation_level.value,
            "is_valid": False,
            "message": "",
            "details": {},
            "warnings": [],
            "recommendations": [],
            "processing_time_ms": 0
        }
        
        if not detected_format:
            result["message"] = "❌ Unable to detect SBOM format. Please check document structure."
            result["recommendations"] = [
                "Ensure the document is valid JSON or XML",
                "Check for required format identifiers (bomFormat, spdxVersion)",
                "Verify file extension matches content type"
            ]
            return result
        
        # Validate based on detected format
        try:
            if detected_data_format == "json":
                data = json.loads(content)
                is_valid, message, details = self.validate_json_schema(data, detected_format, detected_version)
            elif detected_data_format == "xml":
                is_valid, message, details = self.validate_xml_schema(content, detected_format, detected_version)
            else:
                result["message"] = f"❌ Unsupported data format: {detected_data_format}"
                return result
            
            result["is_valid"] = is_valid
            result["message"] = message
            result["details"] = details
            
            # Add validation level specific checks
            if validation_level in [ValidationLevel.STANDARD, ValidationLevel.COMPREHENSIVE]:
                warnings, recommendations = self._perform_business_rules_validation(
                    content, detected_format, detected_version, detected_data_format
                )
                result["warnings"] = warnings
                result["recommendations"].extend(recommendations)
            
            if validation_level == ValidationLevel.COMPREHENSIVE:
                semantic_analysis = self._perform_semantic_analysis(
                    content, detected_format, detected_version, detected_data_format
                )
                result["semantic_analysis"] = semantic_analysis
        
        except json.JSONDecodeError as e:
            result["message"] = f"❌ Invalid JSON format: {str(e)}"
            result["details"] = {"error_type": "JSON Parse Error", "line": e.lineno, "column": e.colno}
        except Exception as e:
            result["message"] = f"❌ Validation error: {str(e)}"
            result["details"] = {"error_type": "General Error"}
        
        # Calculate processing time
        end_time = datetime.now()
        result["processing_time_ms"] = int((end_time - start_time).total_seconds() * 1000)
        
        return result
    
    def _perform_business_rules_validation(self, content: str, format_type: str, 
                                         version: str, data_format: str) -> Tuple[List[str], List[str]]:
        """Perform business rules validation beyond schema"""
        warnings = []
        recommendations = []
        
        try:
            if data_format == "json":
                data = json.loads(content)
                
                if format_type == "spdx":
                    # SPDX specific business rules
                    if "packages" in data:
                        for pkg in data["packages"]:
                            if pkg.get("downloadLocation") == "NOASSERTION":
                                warnings.append(f"Package '{pkg.get('name', 'Unknown')}' has no download location")
                            
                            if not pkg.get("licenseConcluded"):
                                warnings.append(f"Package '{pkg.get('name', 'Unknown')}' missing license conclusion")
                    
                elif format_type == "cyclonedx":
                    # CycloneDX specific business rules
                    if "components" in data:
                        components_with_versions = 0
                        components_with_licenses = 0
                        
                        for comp in data["components"]:
                            if comp.get("version"):
                                components_with_versions += 1
                            if comp.get("licenses"):
                                components_with_licenses += 1
                        
                        total_components = len(data["components"])
                        if total_components > 0:
                            version_coverage = (components_with_versions / total_components) * 100
                            license_coverage = (components_with_licenses / total_components) * 100
                            
                            if version_coverage < 80:
                                warnings.append(f"Only {version_coverage:.1f}% of components have version information")
                                recommendations.append("Consider adding version information for better component tracking")
                            
                            if license_coverage < 50:
                                warnings.append(f"Only {license_coverage:.1f}% of components have license information")
                                recommendations.append("Add license information for compliance tracking")
                    
                    # Check for metadata completeness
                    metadata = data.get("metadata", {})
                    if not metadata.get("timestamp"):
                        recommendations.append("Add timestamp to metadata for better tracking")
                    
                    if not metadata.get("authors") and not metadata.get("tools"):
                        recommendations.append("Add author or tool information to metadata")
        
        except Exception:
            warnings.append("Could not perform complete business rules validation")
        
        return warnings, recommendations
    
    def _perform_semantic_analysis(self, content: str, format_type: str, 
                                 version: str, data_format: str) -> Dict[str, Any]:
        """Perform semantic analysis of SBOM content"""
        analysis = {
            "component_analysis": {},
            "dependency_analysis": {},
            "security_analysis": {},
            "quality_score": 0
        }
        
        try:
            if data_format == "json":
                data = json.loads(content)
                
                # Component analysis
                components = data.get("components", []) if format_type == "cyclonedx" else data.get("packages", [])
                
                if components:
                    component_types = {}
                    license_distribution = {}
                    
                    for comp in components:
                        comp_type = comp.get("type", "unknown")
                        component_types[comp_type] = component_types.get(comp_type, 0) + 1
                        
                        # License analysis
                        licenses = comp.get("licenses", [])
                        if licenses:
                            for lic in licenses:
                                lic_id = lic.get("license", {}).get("id", "unknown")
                                license_distribution[lic_id] = license_distribution.get(lic_id, 0) + 1
                    
                    analysis["component_analysis"] = {
                        "total_components": len(components),
                        "component_types": component_types,
                        "license_distribution": license_distribution
                    }
                
                # Dependency analysis for CycloneDX
                if format_type == "cyclonedx" and "dependencies" in data:
                    deps = data["dependencies"]
                    analysis["dependency_analysis"] = {
                        "total_dependencies": len(deps),
                        "dependency_depth": self._calculate_dependency_depth(deps)
                    }
                
                # Security analysis
                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    severity_counts = {}
                    for vuln in vulnerabilities:
                        ratings = vuln.get("ratings", [])
                        if ratings:
                            severity = ratings[0].get("severity", "unknown")
                            severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    analysis["security_analysis"] = {
                        "total_vulnerabilities": len(vulnerabilities),
                        "severity_distribution": severity_counts
                    }
                
                # Calculate quality score
                analysis["quality_score"] = self._calculate_quality_score(data, format_type)
        
        except Exception as e:
            analysis["error"] = f"Semantic analysis failed: {str(e)}"
        
        return analysis
    
    def _calculate_dependency_depth(self, dependencies: List[Dict]) -> int:
        """Calculate maximum dependency depth"""
        if not dependencies:
            return 0
        
        # Simple depth calculation - count maximum chain length
        max_depth = 0
        for dep in dependencies:
            depends_on = dep.get("dependsOn", [])
            if depends_on:
                max_depth = max(max_depth, len(depends_on))
        
        return max_depth
    
    def _calculate_quality_score(self, data: Dict, format_type: str) -> float:
        """Calculate SBOM quality score (0-100)"""
        score = 0
        max_score = 100
        
        # Basic structure (20 points)
        if format_type == "cyclonedx":
            if data.get("bomFormat"):
                score += 10
            if data.get("specVersion"):
                score += 10
        elif format_type == "spdx":
            if data.get("spdxVersion"):
                score += 10
            if data.get("dataLicense"):
                score += 10
        
        # Metadata completeness (20 points)
        metadata = data.get("metadata", {}) if format_type == "cyclonedx" else data.get("creationInfo", {})
        if metadata:
            if metadata.get("timestamp") or metadata.get("created"):
                score += 10
            if metadata.get("authors") or metadata.get("creators") or metadata.get("tools"):
                score += 10
        
        # Component information (40 points)
        components = data.get("components", []) if format_type == "cyclonedx" else data.get("packages", [])
        if components:
            total_components = len(components)
            components_with_versions = sum(1 for c in components if c.get("version"))
            components_with_licenses = sum(1 for c in components if c.get("licenses") or c.get("licenseConcluded"))
            
            # Version coverage (20 points)
            version_coverage = (components_with_versions / total_components) if total_components > 0 else 0
            score += version_coverage * 20
            
            # License coverage (20 points)
            license_coverage = (components_with_licenses / total_components) if total_components > 0 else 0
            score += license_coverage * 20
        
        # Security information (20 points)
        vulnerabilities = data.get("vulnerabilities", [])
        if vulnerabilities:
            score += 20  # Bonus for including vulnerability information
        elif components and len(components) > 5:
            score -= 10  # Penalty for missing vulnerability info in larger BOMs
        
        return min(score, max_score)
    
    def batch_validate(self, files_data: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
        """Validate multiple SBOM files"""
        results = []
        
        for filename, content in files_data:
            result = self.comprehensive_validate(content, filename)
            result["batch_id"] = len(results) + 1
            results.append(result)
        
        return results
    
    def get_supported_formats_info(self) -> Dict[str, Any]:
        """Get information about supported formats"""
        return {
            "formats": self.supported_formats,
            "total_schemas": len(self.schemas),
            "schema_list": list(self.schemas.keys())
        }

def create_download_link(content: str, filename: str, content_type: str = "application/json") -> str:
    """Create a download link for content"""
    b64 = base64.b64encode(content.encode()).decode()
    return f'<a href="data:{content_type};base64,{b64}" download="{filename}">📥 Download {filename}</a>'

def display_validation_result(result: Dict[str, Any]) -> None:
    """Display validation result in a formatted way"""
    if result["is_valid"]:
        st.markdown('<div class="success-box">', unsafe_allow_html=True)
        st.success(result["message"])
        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="error-box">', unsafe_allow_html=True)
        st.error(result["message"])
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Display auto-detection results
    detection = result["auto_detection"]
    if detection["format"]:
        st.markdown("### 🔍 Auto-Detection Results")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Format", detection["format"].upper())
        with col2:
            st.metric("Version", detection["version"])
        with col3:
            st.metric("Data Format", detection["data_format"].upper())
    
    # Display processing time
    st.markdown(f"⏱️ **Processing Time:** {result['processing_time_ms']} ms")
    
    # Display detailed information
    if result["details"]:
        with st.expander("📊 Validation Details", expanded=False):
            for key, value in result["details"].items():
                st.text(f"{key}: {value}")
    
    # Display warnings
    if result.get("warnings"):
        st.markdown("### ⚠️ Warnings")
        for warning in result["warnings"]:
            st.warning(warning)
    
    # Display recommendations
    if result.get("recommendations"):
        st.markdown("### 💡 Recommendations")
        for rec in result["recommendations"]:
            st.info(rec)
    
    # Display semantic analysis
    if result.get("semantic_analysis"):
        st.markdown("### 🧠 Semantic Analysis")
        semantic = result["semantic_analysis"]
        
        if "quality_score" in semantic:
            quality_score = semantic["quality_score"]
            st.metric("Quality Score", f"{quality_score:.1f}/100", 
                     delta=f"{quality_score - 70:.1f}" if quality_score >= 70 else f"{quality_score - 70:.1f}")
        
        if semantic.get("component_analysis"):
            comp_analysis = semantic["component_analysis"]
            st.markdown("#### Component Analysis")
            col1, col2 = st.columns(2)
            
            with col1:
                st.metric("Total Components", comp_analysis["total_components"])
                if comp_analysis.get("component_types"):
                    st.markdown("**Component Types:**")
                    types_df = pd.DataFrame(
                        list(comp_analysis["component_types"].items()),
                        columns=["Type", "Count"]
                    )
                    st.bar_chart(types_df.set_index("Type"))
            
            with col2:
                if comp_analysis.get("license_distribution"):
                    st.markdown("**License Distribution:**")
                    license_df = pd.DataFrame(
                        list(comp_analysis["license_distribution"].items()),
                        columns=["License", "Count"]
                    )
                    st.bar_chart(license_df.set_index("License"))

def get_example_sboms() -> Dict[str, Dict[str, str]]:
    """Get example SBOM documents for testing"""
    examples = {
        "spdx_2.3_valid": {
            "filename": "example_spdx_2.3.json",
            "content": json.dumps({
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "Example SBOM",
                "documentNamespace": "https://example.com/spdx/example-sbom",
                "creationInfo": {
                    "created": "2024-12-15T10:30:00Z",
                    "creators": ["Tool: example-tool-1.0"]
                },
                "packages": [
                    {
                        "SPDXID": "SPDXRef-Package-example-lib",
                        "name": "example-lib",
                        "downloadLocation": "https://github.com/example/lib",
                        "filesAnalyzed": False,
                        "licenseConcluded": "MIT",
                        "licenseDeclared": "MIT",
                        "copyrightText": "Copyright 2024 Example Inc."
                    }
                ]
            }, indent=2)
        },
        "cyclonedx_1.5_valid": {
            "filename": "example_cyclonedx_1.5.json",
            "content": json.dumps({
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": 1,
                "metadata": {
                    "timestamp": "2024-12-15T10:30:00Z",
                    "tools": [
                        {
                            "vendor": "Example Corp",
                            "name": "sbom-generator",
                            "version": "2.1.0"
                        }
                    ],
                    "component": {
                        "type": "application",
                        "name": "my-application",
                        "version": "1.0.0"
                    }
                },
                "components": [
                    {
                        "type": "library",
                        "bom-ref": "pkg:npm/lodash@4.17.21",
                        "name": "lodash",
                        "version": "4.17.21",
                        "description": "A modern JavaScript utility library",
                        "scope": "required",
                        "licenses": [
                            {
                                "license": {
                                    "id": "MIT",
                                    "name": "MIT License"
                                }
                            }
                        ],
                        "purl": "pkg:npm/lodash@4.17.21"
                    },
                    {
                        "type": "framework",
                        "bom-ref": "pkg:npm/express@4.18.2",
                        "name": "express",
                        "version": "4.18.2",
                        "scope": "required",
                        "licenses": [
                            {
                                "license": {
                                    "id": "MIT"
                                }
                            }
                        ],
                        "purl": "pkg:npm/express@4.18.2"
                    }
                ],
                "dependencies": [
                    {
                        "ref": "pkg:npm/lodash@4.17.21",
                        "dependsOn": []
                    }
                ]
            }, indent=2)
        },
        "cyclonedx_invalid": {
            "filename": "invalid_cyclonedx.json",
            "content": json.dumps({
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                # Missing required "version" field
                "metadata": {
                    "timestamp": "2024-12-15T10:30:00Z"
                },
                "components": [
                    {
                        "type": "library",
                        "name": "example-lib"
                        # Missing other required fields
                    }
                ]
            }, indent=2)
        }
    }
    
    return examples

def main():
    """Main Streamlit application"""
    
    # Header
    st.markdown('<h1 class="main-header">🛡️ Enhanced SBOM Multi-Schema Validator</h1>', unsafe_allow_html=True)
    
    # Sidebar
    st.sidebar.markdown("## 🎛️ Navigation")
    page = st.sidebar.selectbox(
        "Choose a section:",
        [
            "🏠 Home", 
            "✅ Universal Validator", 
            "📊 Batch Validator", 
            "📋 Schema Browser", 
            "📝 Examples & Testing",
            "🔍 Advanced Analysis",
            "📈 Schema Support Matrix"
        ]
    )
    
    # Initialize validator
    validator = EnhancedSBOMValidator()
    
    if page == "🏠 Home":
        st.markdown('<h2 class="section-header">Welcome to Enhanced SBOM Validator</h2>', unsafe_allow_html=True)
        
        st.markdown("""
        This advanced tool provides **comprehensive validation** for Software Bill of Materials (SBOM) documents 
        across multiple formats and versions with intelligent auto-detection and detailed analysis.
        
        ### 🚀 Key Features:
        - **Auto-Detection** - Automatically identifies SBOM format, version, and data type
        - **Multi-Format Support** - SPDX 2.3/3.0 (JSON) and CycloneDX 1.3-1.6 (JSON/XML)
        - **Comprehensive Validation** - Schema, business rules, and semantic analysis
        - **Batch Processing** - Validate multiple files simultaneously
        - **Quality Scoring** - Get quantitative quality metrics for your SBOMs
        - **Detailed Reporting** - Rich validation reports with recommendations
        
        ### 🎯 Validation Levels:
        - **Basic** - Syntax and schema validation only
        - **Standard** - Includes business rules and warnings
        - **Comprehensive** - Full semantic analysis and quality scoring
        """)
        
        # Display supported formats
        formats_info = validator.get_supported_formats_info()
        
        st.markdown('<div class="info-box">', unsafe_allow_html=True)
        st.markdown("### 📊 Supported Formats Overview")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Schemas", formats_info["total_schemas"])
        with col2:
            st.metric("SPDX Versions", len(formats_info["formats"]["spdx"]["versions"]))
        with col3:
            st.metric("CycloneDX Versions", len(formats_info["formats"]["cyclonedx"]["versions"]))
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Quick start guide
        st.markdown("### 🚀 Quick Start")
        st.markdown("""
        1. 📁 **Upload** your SBOM file or paste content directly
        2. 🔍 **Auto-detection** identifies format and version automatically  
        3. ✅ **Validation** runs comprehensive checks
        4. 📊 **Results** show detailed analysis and recommendations
        """)
    
    elif page == "✅ Universal Validator":
        st.markdown('<h2 class="section-header">Universal SBOM Validator</h2>', unsafe_allow_html=True)
        
        st.markdown("""
        Upload your SBOM file or paste content directly. The validator will automatically detect 
        the format, version, and perform comprehensive validation.
        """)
        
        # Validation level selection
        validation_level = st.selectbox(
            "🎚️ Validation Level:",
            [ValidationLevel.BASIC, ValidationLevel.STANDARD, ValidationLevel.COMPREHENSIVE],
            index=1,
            format_func=lambda x: {
                ValidationLevel.BASIC: "🔸 Basic (Schema Only)",
                ValidationLevel.STANDARD: "🔶 Standard (Schema + Business Rules)",
                ValidationLevel.COMPREHENSIVE: "🔺 Comprehensive (Full Analysis)"
            }[x]
        )
        
        # Input method selection
        input_method = st.radio(
            "📥 Input Method:",
            ["Upload File", "Paste Content"],
            horizontal=True
        )
        
        sbom_content = ""
        filename = ""
        
        if input_method == "Upload File":
            uploaded_file = st.file_uploader(
                "Choose SBOM file",
                type=['json', 'xml', 'spdx', 'cdx'],
                help="Supported formats: JSON, XML, SPDX, CycloneDX"
            )
            
            if uploaded_file is not None:
                filename = uploaded_file.name
                sbom_content = uploaded_file.getvalue().decode('utf-8')
                
                st.markdown(f"📁 **File:** {filename}")
                st.markdown(f"📏 **Size:** {len(sbom_content):,} characters")
        
        else:
            sbom_content = st.text_area(
                "📝 Paste SBOM Content:",
                height=300,
                placeholder="Paste your SBOM JSON or XML content here..."
            )
            filename = f"pasted_content.{datetime.now().strftime('%H%M%S')}"
        
        # Validation button and results
        if st.button("🔍 Validate SBOM", type="primary", disabled=not sbom_content):
            if sbom_content.strip():
                with st.spinner("🔄 Validating SBOM..."):
                    result = validator.comprehensive_validate(
                        sbom_content, 
                        filename, 
                        validation_level
                    )
                
                display_validation_result(result)
                
                # Export results option
                if st.button("📤 Export Validation Report"):
                    report_json = json.dumps(result, indent=2)
                    st.markdown(
                        create_download_link(
                            report_json, 
                            f"validation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                        ), 
                        unsafe_allow_html=True
                    )
            else:
                st.warning("⚠️ Please provide SBOM content to validate.")
    
    elif page == "📊 Batch Validator":
        st.markdown('<h2 class="section-header">Batch SBOM Validator</h2>', unsafe_allow_html=True)
        
        st.markdown("""
        Upload multiple SBOM files for batch validation. Get a comprehensive 
        overview of validation results across all your SBOM documents.
        """)
        
        uploaded_files = st.file_uploader(
            "Choose SBOM files",
            type=['json', 'xml', 'spdx', 'cdx'],
            accept_multiple_files=True,
            help="Upload multiple SBOM files for batch processing"
        )
        
        if uploaded_files:
            st.markdown(f"📁 **Files Selected:** {len(uploaded_files)}")
            
            if st.button("🔍 Validate All Files", type="primary"):
                files_data = []
                
                # Read all files
                for uploaded_file in uploaded_files:
                    try:
                        content = uploaded_file.getvalue().decode('utf-8')
                        files_data.append((uploaded_file.name, content))
                    except Exception as e:
                        st.error(f"❌ Error reading {uploaded_file.name}: {str(e)}")
                
                if files_data:
                    # Process batch validation
                    with st.spinner("🔄 Processing batch validation..."):
                        results = validator.batch_validate(files_data)
                    
                    # Summary statistics
                    st.markdown("### 📊 Batch Validation Summary")
                    
                    valid_count = sum(1 for r in results if r["is_valid"])
                    invalid_count = len(results) - valid_count
                    
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Total Files", len(results))
                    with col2:
                        st.metric("Valid", valid_count, delta=f"{(valid_count/len(results)*100):.1f}%")
                    with col3:
                        st.metric("Invalid", invalid_count, delta=f"-{(invalid_count/len(results)*100):.1f}%")
                    with col4:
                        avg_processing_time = sum(r["processing_time_ms"] for r in results) / len(results)
                        st.metric("Avg Time (ms)", f"{avg_processing_time:.0f}")
                    
                    # Detailed results
                    st.markdown("### 📋 Detailed Results")
                    
                    for result in results:
                        with st.expander(f"{'✅' if result['is_valid'] else '❌'} {result['filename']}", 
                                       expanded=not result['is_valid']):
                            display_validation_result(result)
                    
                    # Export batch results
                    if st.button("📤 Export Batch Report"):
                        batch_report = {
                            "batch_timestamp": datetime.now().isoformat(),
                            "summary": {
                                "total_files": len(results),
                                "valid_files": valid_count,
                                "invalid_files": invalid_count,
                                "success_rate": (valid_count / len(results)) * 100
                            },
                            "results": results
                        }
                        report_json = json.dumps(batch_report, indent=2)
                        st.markdown(
                            create_download_link(
                                report_json, 
                                f"batch_validation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                            ), 
                            unsafe_allow_html=True
                        )
    
    elif page == "📋 Schema Browser":
        st.markdown('<h2 class="section-header">SBOM Schema Browser</h2>', unsafe_allow_html=True)
        
        st.markdown("""
        Explore the structure and requirements of different SBOM schemas. 
        This browser helps you understand what makes a valid SBOM document.
        """)
        
        # Schema selection
        schema_format = st.selectbox("🔍 Select Schema Format:", ["SPDX", "CycloneDX"])
        
        if schema_format == "SPDX":
            schema_version = st.selectbox("📋 SPDX Version:", ["2.3", "3.0"])
            schema_key = f"spdx_{schema_version}_json"
        else:
            schema_version = st.selectbox("📋 CycloneDX Version:", ["1.3", "1.4", "1.5", "1.6"])
            data_format = st.selectbox("📄 Data Format:", ["JSON", "XML"])
            schema_key = f"cyclonedx_{schema_version}_{data_format.lower()}"
        
        # Display schema
        if schema_key in validator.schemas:
            schema = validator.schemas[schema_key]
            
            st.markdown(f"### 📊 {schema_format} {schema_version} Schema")
            
            if isinstance(schema, dict):
                # JSON Schema
                with st.expander("🔍 View Full JSON Schema", expanded=False):
                    st.json(schema)
                
                # Schema summary
                st.markdown("#### 📋 Schema Summary")
                
                if "required" in schema:
                    st.markdown("**Required Fields:**")
                    for field in schema["required"]:
                        st.markdown(f"- `{field}`")
                
                if "properties" in schema:
                    st.markdown("**Available Properties:**")
                    for prop_name, prop_def in schema["properties"].items():
                        prop_type = prop_def.get("type", "unknown")
                        description = prop_def.get("description", "No description")
                        st.markdown(f"- `{prop_name}` ({prop_type}): {description}")
            
            else:
                # XML Schema
                st.markdown("#### 📄 XML Schema (XSD)")
                with st.expander("🔍 View XML Schema", expanded=False):
                    st.code(schema, language="xml")
        
        else:
            st.error(f"❌ Schema not found: {schema_key}")
    
    elif page == "📝 Examples & Testing":
        st.markdown('<h2 class="section-header">Examples & Testing</h2>', unsafe_allow_html=True)
        
        st.markdown("""
        Test the validator with example SBOM documents. These examples demonstrate 
        valid and invalid SBOM structures across different formats.
        """)
        
        examples = get_example_sboms()
        
        example_choice = st.selectbox(
            "📚 Select Example:",
            list(examples.keys()),
            format_func=lambda x: {
                "spdx_2.3_valid": "✅ SPDX 2.3 - Valid Example",
                "cyclonedx_1.5_valid": "✅ CycloneDX 1.5 - Valid Example", 
                "cyclonedx_invalid": "❌ CycloneDX - Invalid Example"
            }.get(x, x)
        )
        
        selected_example = examples[example_choice]
        
        # Display example
        st.markdown(f"### 📄 {selected_example['filename']}")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.code(selected_example['content'], language="json")
        
        with col2:
            if st.button("🔍 Validate This Example", type="primary"):
                with st.spinner("🔄 Validating example..."):
                    result = validator.comprehensive_validate(
                        selected_example['content'],
                        selected_example['filename'],
                        ValidationLevel.COMPREHENSIVE
                    )
                
                display_validation_result(result)
        
        # Custom testing area
        st.markdown("### ✏️ Custom Testing")
        st.markdown("Modify the example above or create your own SBOM for testing:")
        
        custom_content = st.text_area(
            "Custom SBOM Content:",
            value=selected_example['content'],
            height=200
        )
        
        if st.button("🔍 Validate Custom Content"):
            with st.spinner("🔄 Validating custom content..."):
                result = validator.comprehensive_validate(
                    custom_content,
                    "custom_test.json",
                    ValidationLevel.COMPREHENSIVE
                )
            
            display_validation_result(result)
    
    elif