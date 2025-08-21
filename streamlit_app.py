import streamlit as st
import json
import jsonschema
from jsonschema import validate, ValidationError
import pandas as pd
from typing import Dict, Any, Tuple, List, Set
from datetime import datetime
import re

# Configure Streamlit page
st.set_page_config(
    page_title="SBOM JSON Schema Validator",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #2E86C1;
        text-align: center;
        margin-bottom: 2rem;
    }
    .section-header {
        font-size: 1.5rem;
        color: #1B4F72;
        margin-top: 2rem;
        margin-bottom: 1rem;
    }
    .success-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #D5F4E6;
        border-left: 5px solid #27AE60;
        margin: 1rem 0;
    }
    .error-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #FADBD8;
        border-left: 5px solid #E74C3C;
        margin: 1rem 0;
    }
    .info-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #EBF3FD;
        border-left: 5px solid #3498DB;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

class SBOMValidator:
    """
    SBOM (Software Bill of Materials) JSON Schema Validator
    
    This class handles validation of JSON documents against a predefined schema
    and calculates similarity coefficients between valid JSON documents.
    """
    
    def __init__(self):
        self.schema = self._get_sbom_schema()
    
    def _get_sbom_schema(self) -> Dict[str, Any]:
        """
        Define a comprehensive SBOM JSON schema with nested objects
        and varying complexity levels.
        """
        return {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "SBOM Component Schema",
            "type": "object",
            "required": ["bomFormat", "specVersion", "components"],
            "properties": {
                "bomFormat": {
                    "type": "string",
                    "enum": ["CycloneDX", "SPDX"],
                    "description": "Format of the SBOM"
                },
                "specVersion": {
                    "type": "string",
                    "pattern": "^[0-9]+\\.[0-9]+$",
                    "description": "Version of the SBOM specification"
                },
                "metadata": {
                    "type": "object",
                    "properties": {
                        "timestamp": {
                            "type": "string",
                            "format": "date-time",
                            "description": "Creation timestamp"
                        },
                        "author": {
                            "type": "string",
                            "minLength": 1,
                            "description": "SBOM author"
                        },
                        "supplier": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "url": {"type": "string", "format": "uri"},
                                "contact": {
                                    "type": "object",
                                    "properties": {
                                        "email": {"type": "string", "format": "email"},
                                        "phone": {"type": "string"}
                                    }
                                }
                            }
                        }
                    }
                },
                "components": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "required": ["type", "name", "version"],
                        "properties": {
                            "type": {
                                "type": "string",
                                "enum": ["library", "framework", "application", "container", "file"]
                            },
                            "name": {
                                "type": "string",
                                "minLength": 1
                            },
                            "version": {
                                "type": "string",
                                "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+.*$"
                            },
                            "description": {
                                "type": "string"
                            },
                            "licenses": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["license"],
                                    "properties": {
                                        "license": {
                                            "type": "object",
                                            "required": ["id"],
                                            "properties": {
                                                "id": {"type": "string"},
                                                "name": {"type": "string"},
                                                "url": {"type": "string", "format": "uri"}
                                            }
                                        }
                                    }
                                }
                            },
                            "vulnerabilities": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["id", "severity"],
                                    "properties": {
                                        "id": {"type": "string"},
                                        "severity": {
                                            "type": "string",
                                            "enum": ["low", "medium", "high", "critical"]
                                        },
                                        "description": {"type": "string"},
                                        "cvss": {
                                            "type": "object",
                                            "properties": {
                                                "version": {"type": "string"},
                                                "score": {
                                                    "type": "number",
                                                    "minimum": 0,
                                                    "maximum": 10
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "dependencies": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        }
                    }
                }
            }
        }
    
    def validate_json(self, json_data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validate JSON data against the SBOM schema.
        
        Args:
            json_data: JSON data to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            validate(instance=json_data, schema=self.schema)
            return True, "✅ JSON is valid against the schema"
        except ValidationError as e:
            return False, f"❌ Validation error: {e.message}"
        except Exception as e:
            return False, f"❌ Unexpected error: {str(e)}"
    
    def _extract_all_paths(self, obj: Any, prefix: str = "") -> Set[str]:
        """
        Recursively extract all JSON paths from an object.
        """
        paths = set()
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{prefix}.{key}" if prefix else key
                paths.add(current_path)
                paths.update(self._extract_all_paths(value, current_path))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                current_path = f"{prefix}[{i}]"
                paths.update(self._extract_all_paths(item, current_path))
                
        return paths
    
    def _extract_values_by_path(self, obj: Any, prefix: str = "") -> Dict[str, Any]:
        """
        Extract all values with their JSON paths.
        """
        values = {}
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{prefix}.{key}" if prefix else key
                if not isinstance(value, (dict, list)):
                    values[current_path] = value
                values.update(self._extract_values_by_path(value, current_path))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                current_path = f"{prefix}[{i}]"
                if not isinstance(item, (dict, list)):
                    values[current_path] = item
                values.update(self._extract_values_by_path(item, current_path))
                
        return values
    
    def calculate_similarity(self, json1: Dict[str, Any], json2: Dict[str, Any]) -> Dict[str, float]:
        """
        Calculate similarity coefficient between two JSON objects.
        
        The algorithm considers:
        1. Structural similarity (shared paths)
        2. Value similarity (shared values)
        3. Type similarity (compatible types)
        
        Args:
            json1, json2: JSON objects to compare
            
        Returns:
            Dictionary with similarity metrics
        """
        # Extract paths and values
        paths1 = self._extract_all_paths(json1)
        paths2 = self._extract_all_paths(json2)
        values1 = self._extract_values_by_path(json1)
        values2 = self._extract_values_by_path(json2)
        
        # 1. Structural similarity (Jaccard index)
        common_paths = paths1 & paths2
        total_paths = paths1 | paths2
        structural_similarity = len(common_paths) / len(total_paths) if total_paths else 0
        
        # 2. Value similarity
        common_value_paths = set(values1.keys()) & set(values2.keys())
        matching_values = 0
        for path in common_value_paths:
            if values1[path] == values2[path]:
                matching_values += 1
        
        value_similarity = matching_values / len(common_value_paths) if common_value_paths else 0
        
        # 3. Type similarity
        type_matches = 0
        for path in common_value_paths:
            if type(values1[path]) == type(values2[path]):
                type_matches += 1
        
        type_similarity = type_matches / len(common_value_paths) if common_value_paths else 0
        
        # Combined similarity with weights
        combined_similarity = (
            0.4 * structural_similarity +
            0.4 * value_similarity +
            0.2 * type_similarity
        )
        
        return {
            "structural": round(structural_similarity, 3),
            "value": round(value_similarity, 3),
            "type": round(type_similarity, 3),
            "combined": round(combined_similarity, 3)
        }
    
    def analyze_structure(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze the structure of a JSON object.
        """
        paths = self._extract_all_paths(json_data)
        values = self._extract_values_by_path(json_data)
        
        # Count different data types
        type_counts = {}
        for value in values.values():
            type_name = type(value).__name__
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
        
        return {
            "total_paths": len(paths),
            "total_values": len(values),
            "type_distribution": type_counts,
            "max_depth": max([path.count('.') + path.count('[') for path in paths]) if paths else 0
        }

def get_sample_jsons():
    """
    Generate three sample JSON objects:
    - Two valid examples demonstrating schema flexibility
    - One invalid example with a subtle error
    """
    
    # Valid JSON 1: Full-featured SBOM
    valid_json_1 = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "timestamp": "2024-12-15T10:30:00Z",
            "author": "Security Team",
            "supplier": {
                "name": "TechCorp Inc.",
                "url": "https://techcorp.com",
                "contact": {
                    "email": "security@techcorp.com",
                    "phone": "+1-555-0123"
                }
            }
        },
        "components": [
            {
                "type": "library",
                "name": "lodash",
                "version": "4.17.21",
                "description": "A modern JavaScript utility library",
                "licenses": [
                    {
                        "license": {
                            "id": "MIT",
                            "name": "MIT License",
                            "url": "https://opensource.org/licenses/MIT"
                        }
                    }
                ],
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-23337",
                        "severity": "high",
                        "description": "Command injection vulnerability",
                        "cvss": {
                            "version": "3.1",
                            "score": 7.2
                        }
                    }
                ],
                "dependencies": ["es6-promise"]
            },
            {
                "type": "framework",
                "name": "express",
                "version": "4.18.2",
                "licenses": [
                    {
                        "license": {
                            "id": "MIT"
                        }
                    }
                ]
            }
        ]
    }
    
    # Valid JSON 2: Minimal valid SBOM (demonstrates optional fields)
    valid_json_2 = {
        "bomFormat": "SPDX",
        "specVersion": "2.3",
        "components": [
            {
                "type": "application",
                "name": "my-web-app",
                "version": "1.0.0",
                "description": "Main web application",
                "dependencies": ["react", "axios"]
            },
            {
                "type": "library",
                "name": "react",
                "version": "18.2.0",
                "vulnerabilities": [
                    {
                        "id": "CVE-2022-24958",
                        "severity": "medium"
                    }
                ]
            }
        ]
    }
    
    # Invalid JSON: Subtle error - CVSS score as string instead of number
    invalid_json = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "timestamp": "2024-12-15T10:30:00Z",
            "author": "Dev Team"
        },
        "components": [
            {
                "type": "library",
                "name": "vulnerable-lib",
                "version": "1.2.3",
                "vulnerabilities": [
                    {
                        "id": "CVE-2024-12345",
                        "severity": "critical",
                        "cvss": {
                            "version": "3.1",
                            "score": "9.8"  # ERROR: Should be number, not string
                        }
                    }
                ]
            }
        ]
    }
    
    return valid_json_1, valid_json_2, invalid_json

def main():
    """
    Main Streamlit application function
    """
    
    # Header
    st.markdown('<h1 class="main-header">🔍 SBOM JSON Schema Validator</h1>', unsafe_allow_html=True)
    
    # Sidebar with information
    st.sidebar.markdown("## About This Tool")
    st.sidebar.info("""
    This application validates JSON documents against an SBOM (Software Bill of Materials) schema
    and calculates similarity coefficients between valid documents.
    
    **Features:**
    - JSON Schema Validation
    - Similarity Analysis
    - Structure Analysis
    - Interactive Examples
    """)
    
    st.sidebar.markdown("## Navigation")
    page = st.sidebar.selectbox(
        "Choose a section:",
        ["🏠 Home", "📋 Schema Viewer", "✅ Validation", "📊 Similarity Analysis", "📝 Examples"]
    )
    
    # Initialize validator
    validator = SBOMValidator()
    
    if page == "🏠 Home":
        st.markdown('<h2 class="section-header">Welcome to SBOM Validator</h2>', unsafe_allow_html=True)
        
        st.markdown("""
        This tool is designed for **SBOM (Software Bill of Materials)** validation and analysis.
        
        ### What you can do:
        - **Validate** JSON documents against SBOM schema
        - **Compare** similarity between valid JSON documents  
        - **Analyze** structure and properties of JSON data
        - **Explore** example JSON documents
        
        ### Getting Started:
        1. Use the sidebar to navigate between sections
        2. Check out the **Examples** page for sample JSON documents
        3. Use **Validation** to test your own JSON
        4. Analyze **Similarity** between valid documents
        """)
        
        # Quick stats about the schema
        schema = validator.schema
        st.markdown('<div class="info-box">', unsafe_allow_html=True)
        st.markdown("### Schema Information")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Required Fields", len(schema.get("required", [])))
        with col2:
            st.metric("Total Properties", len(schema.get("properties", {})))
        with col3:
            st.metric("Schema Version", schema.get("$schema", "N/A").split("/")[-1])
        st.markdown('</div>', unsafe_allow_html=True)
    
    elif page == "📋 Schema Viewer":
        st.markdown('<h2 class="section-header">JSON Schema</h2>', unsafe_allow_html=True)
        
        st.markdown("""
        This is the SBOM JSON Schema used for validation. It defines the structure,
        required fields, and data types for valid SBOM documents.
        """)
        
        # Display schema in expandable section
        with st.expander("View Full Schema", expanded=False):
            st.json(validator.schema)
        
        # Schema summary
        st.markdown("### Schema Summary")
        schema_info = {
            "Title": validator.schema.get("title", "N/A"),
            "Type": validator.schema.get("type", "N/A"),
            "Required Fields": ", ".join(validator.schema.get("required", [])),
            "Optional Fields": ", ".join([
                key for key in validator.schema.get("properties", {}).keys()
                if key not in validator.schema.get("required", [])
            ])
        }
        
        for key, value in schema_info.items():
            st.text(f"{key}: {value}")
    
    elif page == "✅ Validation":
        st.markdown('<h2 class="section-header">JSON Validation</h2>', unsafe_allow_html=True)
        
        st.markdown("Paste your JSON document below to validate against the SBOM schema:")
        
        # Text area for JSON input
        json_input = st.text_area(
            "JSON Document:",
            height=400,
            placeholder="Paste your JSON here..."
        )
        
        if st.button("Validate JSON", type="primary"):
            if json_input.strip():
                try:
                    # Parse JSON
                    json_data = json.loads(json_input)
                    
                    # Validate
                    is_valid, message = validator.validate_json(json_data)
                    
                    if is_valid:
                        st.markdown('<div class="success-box">', unsafe_allow_html=True)
                        st.success(message)
                        st.markdown('</div>', unsafe_allow_html=True)
                        
                        # Show structure analysis
                        analysis = validator.analyze_structure(json_data)
                        st.markdown("### Structure Analysis")
                        
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("Total Paths", analysis["total_paths"])
                        with col2:
                            st.metric("Total Values", analysis["total_values"])
                        with col3:
                            st.metric("Max Depth", analysis["max_depth"])
                        with col4:
                            st.metric("Data Types", len(analysis["type_distribution"]))
                        
                        # Type distribution
                        if analysis["type_distribution"]:
                            st.markdown("### Data Type Distribution")
                            type_df = pd.DataFrame(
                                list(analysis["type_distribution"].items()),
                                columns=["Type", "Count"]
                            )
                            st.bar_chart(type_df.set_index("Type"))
                    else:
                        st.markdown('<div class="error-box">', unsafe_allow_html=True)
                        st.error(message)
                        st.markdown('</div>', unsafe_allow_html=True)
                        
                except json.JSONDecodeError as e:
                    st.error(f"Invalid JSON format: {e}")
            else:
                st.warning("Please enter a JSON document to validate.")
    
    elif page == "📊 Similarity Analysis":
        st.markdown('<h2 class="section-header">Similarity Analysis</h2>', unsafe_allow_html=True)
        
        st.markdown("""
        Compare two valid JSON documents to calculate their similarity coefficient.
        The algorithm considers structural, value, and type similarities.
        """)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### JSON Document 1")
            json1_input = st.text_area("First JSON:", height=300, key="json1")
        
        with col2:
            st.markdown("#### JSON Document 2")
            json2_input = st.text_area("Second JSON:", height=300, key="json2")
        
        if st.button("Calculate Similarity", type="primary"):
            if json1_input.strip() and json2_input.strip():
                try:
                    json1 = json.loads(json1_input)
                    json2 = json.loads(json2_input)
                    
                    # Validate both JSONs
                    valid1, msg1 = validator.validate_json(json1)
                    valid2, msg2 = validator.validate_json(json2)
                    
                    if valid1 and valid2:
                        # Calculate similarity
                        similarity = validator.calculate_similarity(json1, json2)
                        
                        st.markdown('<div class="success-box">', unsafe_allow_html=True)
                        st.success("Both JSON documents are valid!")
                        st.markdown('</div>', unsafe_allow_html=True)
                        
                        st.markdown("### Similarity Metrics")
                        
                        # Display metrics
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("Structural", f"{similarity['structural']:.3f}")
                        with col2:
                            st.metric("Value", f"{similarity['value']:.3f}")
                        with col3:
                            st.metric("Type", f"{similarity['type']:.3f}")
                        with col4:
                            st.metric("Combined", f"{similarity['combined']:.3f}", 
                                    delta=f"{similarity['combined'] - 0.5:.3f}")
                        
                        # Similarity chart
                        similarity_df = pd.DataFrame({
                            "Metric": ["Structural", "Value", "Type", "Combined"],
                            "Score": [similarity['structural'], similarity['value'], 
                                    similarity['type'], similarity['combined']]
                        })
                        
                        st.markdown("### Similarity Breakdown")
                        st.bar_chart(similarity_df.set_index("Metric"))
                        
                        # Interpretation
                        combined_score = similarity['combined']
                        if combined_score >= 0.8:
                            interpretation = "🟢 Very High Similarity"
                        elif combined_score >= 0.6:
                            interpretation = "🟡 High Similarity"
                        elif combined_score >= 0.4:
                            interpretation = "🟠 Moderate Similarity"
                        elif combined_score >= 0.2:
                            interpretation = "🔴 Low Similarity"
                        else:
                            interpretation = "⚫ Very Low Similarity"
                        
                        st.markdown(f"### Interpretation: {interpretation}")
                        
                    else:
                        if not valid1:
                            st.error(f"JSON 1 validation failed: {msg1}")
                        if not valid2:
                            st.error(f"JSON 2 validation failed: {msg2}")
                        
                except json.JSONDecodeError as e:
                    st.error(f"Invalid JSON format: {e}")
            else:
                st.warning("Please enter both JSON documents.")
    
    elif page == "📝 Examples":
        st.markdown('<h2 class="section-header">Example JSON Documents</h2>', unsafe_allow_html=True)
        
        st.markdown("""
        Here are three example JSON documents:
        - **Two valid** examples showing different optional field combinations
        - **One invalid** example with a subtle error for testing
        """)
        
        # Get sample JSONs
        valid1, valid2, invalid = get_sample_jsons()
        
        # Tabs for different examples
        tab1, tab2, tab3 = st.tabs(["✅ Valid Example 1", "✅ Valid Example 2", "❌ Invalid Example"])
        
        with tab1:
            st.markdown("#### Full-Featured SBOM")
            st.markdown("This example includes all optional fields and demonstrates complex nested structures.")
            
            if st.button("Validate Example 1", key="validate1"):
                is_valid, message = validator.validate_json(valid1)
                if is_valid:
                    st.success(message)
                else:
                    st.error(message)
            
            st.json(valid1)
        
        with tab2:
            st.markdown("#### Minimal Valid SBOM")
            st.markdown("This example shows a minimal valid document with only required fields and some optionals.")
            
            if st.button("Validate Example 2", key="validate2"):
                is_valid, message = validator.validate_json(valid2)
                if is_valid:
                    st.success(message)
                else:
                    st.error(message)
            
            st.json(valid2)
        
        with tab3:
            st.markdown("#### Invalid Example with Subtle Error")
            st.markdown("""
            This example contains a **subtle error**: the CVSS score is provided as a string `"9.8"` 
            instead of a number `9.8`. This type of error is common in real-world scenarios where 
            data is serialized incorrectly.
            """)
            
            if st.button("Validate Invalid Example", key="validate3"):
                is_valid, message = validator.validate_json(invalid)
                if is_valid:
                    st.success(message)
                else:
                    st.error(message)
            
            st.json(invalid)
        
        # Quick comparison button
        st.markdown("### Quick Similarity Test")
        if st.button("Compare Valid Examples", type="secondary"):
            similarity = validator.calculate_similarity(valid1, valid2)
            st.markdown("#### Similarity between Valid Examples:")
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Structural", f"{similarity['structural']:.3f}")
            with col2:
                st.metric("Value", f"{similarity['value']:.3f}")
            with col3:
                st.metric("Type", f"{similarity['type']:.3f}")
            with col4:
                st.metric("Combined", f"{similarity['combined']:.3f}")

if __name__ == "__main__":
    main()
