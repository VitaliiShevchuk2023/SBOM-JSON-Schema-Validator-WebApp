import streamlit as st
import json
import xml.etree.ElementTree as ET
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import jsonschema
import xmlschema
from datetime import datetime
import hashlib
import time
import re
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from pathlib import Path
import networkx as nx

# Конфігурація сторінки
st.set_page_config(
    page_title="SBOM Validator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS стилі
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    
    .metric-card {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        padding: 1rem;
        border-radius: 10px;
        border: 1px solid #e0e0e0;
        margin-bottom: 1rem;
    }
    
    .quality-score {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
    }
    
    .quality-excellent { color: #28a745; }
    .quality-good { color: #17a2b8; }
    .quality-warning { color: #ffc107; }
    .quality-poor { color: #dc3545; }
    
    .error-box {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        border-radius: 5px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    
    .warning-box {
        background-color: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 5px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    
    .success-box {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        border-radius: 5px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

@dataclass
class ValidationResult:
    is_valid: bool
    format_type: str
    version: str
    data_type: str
    errors: List[str]
    warnings: List[str]
    quality_score: int
    analysis: Dict[str, Any]
    processing_time: float

class EnhancedSBOMValidator:
    """Покращений SBOM валідатор з auto-detection та семантичним аналізом"""
    
    def __init__(self):
        self.supported_formats = {
            'spdx': {
                '2.3': {'json': True, 'xml': False},
                '3.0': {'json': True, 'xml': False}
            },
            'cyclonedx': {
                '1.3': {'json': True, 'xml': True},
                '1.4': {'json': True, 'xml': True},
                '1.5': {'json': True, 'xml': True},
                '1.6': {'json': True, 'xml': True}
            }
        }
        
        # SPDX схеми (спрощені для демонстрації)
        self.spdx_schema_2_3 = {
            "type": "object",
            "required": ["spdxVersion", "SPDXID", "name", "dataLicense"],
            "properties": {
                "spdxVersion": {"type": "string", "pattern": "^SPDX-2\\.3$"},
                "SPDXID": {"type": "string", "pattern": "^SPDXRef-DOCUMENT$"},
                "name": {"type": "string"},
                "dataLicense": {"type": "string"},
                "packages": {"type": "array"}
            }
        }
        
        self.spdx_schema_3_0 = {
            "type": "object",
            "required": ["spdxVersion", "SPDXID", "name", "dataLicense"],
            "properties": {
                "spdxVersion": {"type": "string", "pattern": "^SPDX-3\\.0$"},
                "SPDXID": {"type": "string"},
                "name": {"type": "string"},
                "dataLicense": {"type": "string"},
                "packages": {"type": "array"}
            }
        }
        
        # CycloneDX схеми
        self.cyclonedx_schema = {
            "type": "object",
            "required": ["bomFormat", "specVersion"],
            "properties": {
                "bomFormat": {"type": "string", "const": "CycloneDX"},
                "specVersion": {"type": "string"},
                "version": {"type": "integer"},
                "components": {"type": "array"},
                "metadata": {"type": "object"}
            }
        }
    
    def detect_sbom_format(self, content: str, filename: str = "") -> Tuple[str, str, str]:
        """Автоматичне визначення формату SBOM"""
        try:
            # Спочатку перевіряємо JSON
            if content.strip().startswith('{'):
                data = json.loads(content)
                
                # Перевіряємо SPDX
                if "spdxVersion" in data:
                    version = data.get("spdxVersion", "").replace("SPDX-", "")
                    return "spdx", version, "json"
                
                # Перевіряємо CycloneDX
                elif "bomFormat" in data and data["bomFormat"] == "CycloneDX":
                    version = data.get("specVersion", "1.4")
                    return "cyclonedx", version, "json"
            
            # Перевіряємо XML
            elif content.strip().startswith('<'):
                root = ET.fromstring(content)
                
                # CycloneDX XML
                if 'cyclonedx' in root.tag.lower() or 'bom' in root.tag.lower():
                    version = root.get('version', '1.4')
                    return "cyclonedx", version, "xml"
                
                # SPDX XML (рідко використовується)
                elif 'spdx' in root.tag.lower():
                    return "spdx", "2.3", "xml"
            
            # Перевіряємо за назвою файлу
            if filename:
                if 'spdx' in filename.lower():
                    return "spdx", "2.3", "json"
                elif 'cyclone' in filename.lower() or 'sbom' in filename.lower():
                    return "cyclonedx", "1.4", "json"
        
        except Exception:
            pass
        
        return "unknown", "unknown", "unknown"
    
    def validate_schema(self, data: Any, format_type: str, version: str, data_type: str) -> Tuple[bool, List[str]]:
        """Валідація схеми"""
        errors = []
        
        try:
            if format_type == "spdx":
                if version == "2.3":
                    jsonschema.validate(data, self.spdx_schema_2_3)
                elif version == "3.0":
                    jsonschema.validate(data, self.spdx_schema_3_0)
                else:
                    errors.append(f"Непідтримувана версія SPDX: {version}")
            
            elif format_type == "cyclonedx":
                if data_type == "json":
                    jsonschema.validate(data, self.cyclonedx_schema)
                elif data_type == "xml":
                    # Для XML використовуємо базову перевірку
                    if not isinstance(data, ET.Element):
                        errors.append("Неправильний XML формат")
            
            else:
                errors.append(f"Непідтримуваний формат: {format_type}")
        
        except jsonschema.ValidationError as e:
            errors.append(f"Помилка схеми: {e.message}")
        except Exception as e:
            errors.append(f"Помилка валідації: {str(e)}")
        
        return len(errors) == 0, errors
    
    def business_rules_validation(self, data: Any, format_type: str) -> Tuple[List[str], List[str]]:
        """Перевірка бізнес-правил"""
        errors = []
        warnings = []
        
        try:
            if format_type == "spdx":
                # Перевірка обов'язкових полів
                if not data.get("name"):
                    errors.append("Відсутня назва документа")
                
                if not data.get("packages"):
                    warnings.append("Документ не містить пакетів")
                
                # Перевірка ліцензій
                packages = data.get("packages", [])
                unlicensed_packages = [p.get("name", "unknown") for p in packages 
                                     if not p.get("licenseConcluded")]
                if unlicensed_packages:
                    warnings.append(f"Пакети без ліцензій: {', '.join(unlicensed_packages[:3])}")
            
            elif format_type == "cyclonedx":
                # Перевірка метаданих
                metadata = data.get("metadata", {})
                if not metadata.get("timestamp"):
                    warnings.append("Відсутня мітка часу")
                
                if not metadata.get("authors"):
                    warnings.append("Відсутня інформація про авторів")
                
                # Перевірка компонентів
                components = data.get("components", [])
                if not components:
                    errors.append("SBOM не містить компонентів")
                
                # Перевірка версій компонентів
                unversioned_components = [c.get("name", "unknown") for c in components 
                                        if not c.get("version")]
                if unversioned_components:
                    warnings.append(f"Компоненти без версій: {', '.join(unversioned_components[:3])}")
        
        except Exception as e:
            errors.append(f"Помилка бізнес-правил: {str(e)}")
        
        return errors, warnings
    
    def semantic_analysis(self, data: Any, format_type: str) -> Dict[str, Any]:
        """Семантичний аналіз SBOM"""
        analysis = {
            "component_stats": {},
            "dependency_analysis": {},
            "license_analysis": {},
            "security_analysis": {},
            "quality_metrics": {}
        }
        
        try:
            if format_type == "spdx":
                packages = data.get("packages", [])
                
                # Статистика компонентів
                analysis["component_stats"] = {
                    "total_packages": len(packages),
                    "with_versions": len([p for p in packages if p.get("versionInfo")]),
                    "with_licenses": len([p for p in packages if p.get("licenseConcluded")]),
                    "package_types": {}
                }
                
                # Аналіз ліцензій
                licenses = [p.get("licenseConcluded", "Unknown") for p in packages]
                license_counts = pd.Series(licenses).value_counts().to_dict()
                analysis["license_analysis"] = {
                    "distribution": license_counts,
                    "unique_licenses": len(set(licenses)),
                    "unlicensed_count": licenses.count("NOASSERTION") + licenses.count("Unknown")
                }
            
            elif format_type == "cyclonedx":
                components = data.get("components", [])
                
                # Статистика компонентів
                component_types = [c.get("type", "unknown") for c in components]
                analysis["component_stats"] = {
                    "total_components": len(components),
                    "with_versions": len([c for c in components if c.get("version")]),
                    "with_licenses": len([c for c in components if c.get("licenses")]),
                    "component_types": pd.Series(component_types).value_counts().to_dict()
                }
                
                # Аналіз залежностей
                dependencies = data.get("dependencies", [])
                analysis["dependency_analysis"] = {
                    "total_dependencies": len(dependencies),
                    "dependency_graph_depth": self._calculate_dependency_depth(dependencies),
                    "root_components": self._find_root_components(dependencies),
                    "leaf_components": self._find_leaf_components(dependencies)
                }
                
                # Аналіз ліцензій
                all_licenses = []
                for component in components:
                    licenses = component.get("licenses", [])
                    for license_info in licenses:
                        if isinstance(license_info, dict):
                            license_id = license_info.get("license", {}).get("id", "Unknown")
                            all_licenses.append(license_id)
                
                license_counts = pd.Series(all_licenses).value_counts().to_dict()
                analysis["license_analysis"] = {
                    "distribution": license_counts,
                    "unique_licenses": len(set(all_licenses)),
                    "unlicensed_count": all_licenses.count("Unknown")
                }
                
                # Аналіз безпеки (якщо є вразливості)
                vulnerabilities = []
                for component in components:
                    if "vulnerabilities" in component:
                        vulnerabilities.extend(component["vulnerabilities"])
                
                if vulnerabilities:
                    severity_counts = {}
                    for vuln in vulnerabilities:
                        severity = vuln.get("severity", "unknown")
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    analysis["security_analysis"] = {
                        "total_vulnerabilities": len(vulnerabilities),
                        "severity_distribution": severity_counts,
                        "critical_count": severity_counts.get("critical", 0),
                        "high_count": severity_counts.get("high", 0)
                    }
        
        except Exception as e:
            analysis["error"] = f"Помилка аналізу: {str(e)}"
        
        return analysis
    
    def _calculate_dependency_depth(self, dependencies: List[Dict]) -> int:
        """Розрахунок глибини графа залежностей"""
        if not dependencies:
            return 0
        
        try:
            G = nx.DiGraph()
            for dep in dependencies:
                ref = dep.get("ref", "")
                depends_on = dep.get("dependsOn", [])
                for target in depends_on:
                    G.add_edge(ref, target)
            
            if G.nodes():
                try:
                    return max(nx.shortest_path_length(G, source).values() 
                             for source in G.nodes() if G.out_degree(source) > 0)
                except:
                    return len(G.nodes())
            return 0
        except:
            return 0
    
    def _find_root_components(self, dependencies: List[Dict]) -> List[str]:
        """Пошук кореневих компонентів"""
        all_refs = set()
        dependent_refs = set()
        
        for dep in dependencies:
            ref = dep.get("ref", "")
            all_refs.add(ref)
            dependent_refs.update(dep.get("dependsOn", []))
        
        return list(all_refs - dependent_refs)
    
    def _find_leaf_components(self, dependencies: List[Dict]) -> List[str]:
        """Пошук листових компонентів"""
        return [dep.get("ref", "") for dep in dependencies 
                if not dep.get("dependsOn")]
    
    def calculate_quality_score(self, data: Any, format_type: str, errors: List[str], 
                              warnings: List[str], analysis: Dict[str, Any]) -> int:
        """Розрахунок оцінки якості (0-100)"""
        score = 100
        
        # Штрафи за помилки
        score -= len(errors) * 20
        score -= len(warnings) * 5
        
        try:
            if format_type == "cyclonedx":
                # Структура (20%)
                if "bomFormat" not in data or "specVersion" not in data:
                    score -= 20
                
                # Метадані (20%)
                metadata = data.get("metadata", {})
                metadata_score = 0
                if metadata.get("timestamp"):
                    metadata_score += 5
                if metadata.get("authors"):
                    metadata_score += 5
                if metadata.get("tools"):
                    metadata_score += 5
                if metadata.get("component"):
                    metadata_score += 5
                score += metadata_score - 20
                
                # Компоненти (40%)
                components = data.get("components", [])
                if components:
                    with_versions = len([c for c in components if c.get("version")])
                    with_licenses = len([c for c in components if c.get("licenses")])
                    
                    version_ratio = with_versions / len(components)
                    license_ratio = with_licenses / len(components)
                    
                    component_score = (version_ratio * 20) + (license_ratio * 20)
                    score += component_score - 40
                else:
                    score -= 40
                
                # Безпека (20%)
                security_score = 0
                if analysis.get("security_analysis"):
                    # Якщо є аналіз вразливостей, це добре
                    security_score += 10
                    sec_analysis = analysis["security_analysis"]
                    if sec_analysis.get("critical_count", 0) == 0:
                        security_score += 5
                    if sec_analysis.get("high_count", 0) == 0:
                        security_score += 5
                else:
                    # Відсутність інформації про безпеку
                    security_score += 10
                
                score += security_score - 20
            
            elif format_type == "spdx":
                # Спрощений розрахунок для SPDX
                packages = data.get("packages", [])
                if packages:
                    with_licenses = len([p for p in packages if p.get("licenseConcluded")])
                    license_ratio = with_licenses / len(packages)
                    score += (license_ratio * 40) - 40
                else:
                    score -= 30
        
        except Exception:
            score -= 10
        
        return max(0, min(100, int(score)))
    
    def validate(self, content: str, filename: str = "", 
                validation_level: str = "standard") -> ValidationResult:
        """Головна функція валідації"""
        start_time = time.time()
        
        # Auto-detection
        format_type, version, data_type = self.detect_sbom_format(content, filename)
        
        errors = []
        warnings = []
        analysis = {}
        
        if format_type == "unknown":
            return ValidationResult(
                is_valid=False,
                format_type=format_type,
                version=version,
                data_type=data_type,
                errors=["Не вдалося визначити формат SBOM"],
                warnings=[],
                quality_score=0,
                analysis={},
                processing_time=time.time() - start_time
            )
        
        try:
            # Парсинг даних
            if data_type == "json":
                data = json.loads(content)
            elif data_type == "xml":
                data = ET.fromstring(content)
            else:
                raise ValueError(f"Непідтримуваний тип даних: {data_type}")
            
            # Базова валідація схеми
            is_valid_schema, schema_errors = self.validate_schema(data, format_type, version, data_type)
            errors.extend(schema_errors)
            
            # Розширена валідація
            if validation_level in ["standard", "comprehensive"]:
                business_errors, business_warnings = self.business_rules_validation(data, format_type)
                errors.extend(business_errors)
                warnings.extend(business_warnings)
            
            # Семантичний аналіз
            if validation_level == "comprehensive":
                analysis = self.semantic_analysis(data, format_type)
            
            # Розрахунок оцінки якості
            quality_score = self.calculate_quality_score(data, format_type, errors, warnings, analysis)
            
            is_valid = len(errors) == 0
        
        except json.JSONDecodeError as e:
            errors.append(f"Помилка JSON: {str(e)}")
            is_valid = False
            quality_score = 0
        
        except ET.ParseError as e:
            errors.append(f"Помилка XML: {str(e)}")
            is_valid = False
            quality_score = 0
        
        except Exception as e:
            errors.append(f"Загальна помилка: {str(e)}")
            is_valid = False
            quality_score = 0
        
        processing_time = time.time() - start_time
        
        return ValidationResult(
            is_valid=is_valid,
            format_type=format_type,
            version=version,
            data_type=data_type,
            errors=errors,
            warnings=warnings,
            quality_score=quality_score,
            analysis=analysis,
            processing_time=processing_time
        )

def create_quality_gauge(score: int) -> go.Figure:
    """Створення gauge для оцінки якості"""
    if score >= 80:
        color = "green"
        category = "Відмінна"
    elif score >= 60:
        color = "blue"
        category = "Хороша"
    elif score >= 40:
        color = "yellow"
        category = "Задовільна"
    else:
        color = "red"
        category = "Погана"
    
    fig = go.Figure(go.Indicator(
        mode = "gauge+number+delta",
        value = score,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': f"Якість SBOM<br><span style='font-size:0.8em;color:gray'>{category}</span>"},
        delta = {'reference': 50},
        gauge = {
            'axis': {'range': [None, 100]},
            'bar': {'color': color},
            'steps': [
                {'range': [0, 40], 'color': "lightgray"},
                {'range': [40, 60], 'color': "gray"},
                {'range': [60, 80], 'color': "lightblue"},
                {'range': [80, 100], 'color': "lightgreen"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    
    fig.update_layout(height=400, font={'color': "darkblue", 'family': "Arial"})
    return fig

def main():
    # Заголовок
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ SBOM Validator</h1>
        <p>Універсальний валідатор для SPDX 2.3/3.0 та CycloneDX 1.3-1.6 з автоматичним визначенням формату</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar навігація
    st.sidebar.title("🧭 Навігація")
    page = st.sidebar.selectbox(
        "Виберіть розділ:",
        ["🏠 Головна", "✅ Універсальний валідатор", "📊 Пакетна валідація", 
         "📋 Браузер схем", "📝 Приклади та тести", "🔍 Розширений аналіз", 
         "📈 Матриця підтримки"]
    )
    
    validator = EnhancedSBOMValidator()
    
    if page == "🏠 Головна":
        show_home_page(validator)
    elif page == "✅ Універсальний валідатор":
        show_universal_validator(validator)
    elif page == "📊 Пакетна валідація":
        show_batch_validator(validator)
    elif page == "📋 Браузер схем":
        show_schema_browser(validator)
    elif page == "📝 Приклади та тести":
        show_examples_page(validator)
    elif page == "🔍 Розширений аналіз":
        show_advanced_analysis(validator)
    elif page == "📈 Матриця підтримки":
        show_support_matrix(validator)

def show_home_page(validator):
    st.header("🚀 Огляд можливостей")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="metric-card">
            <h3>🎯 Auto-Detection</h3>
            <p>Автоматичне визначення формату, версії та типу даних SBOM</p>
            <ul>
                <li>SPDX 2.3/3.0 (JSON)</li>
                <li>CycloneDX 1.3-1.6 (JSON/XML)</li>
                <li>Інтелектуальний аналіз структури</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="metric-card">
            <h3>🔍 Трирівнева валідація</h3>
            <p>Вибір рівня деталізації перевірки</p>
            <ul>
                <li><b>Basic:</b> Синтаксис + схема</li>
                <li><b>Standard:</b> + бізнес-правила</li>
                <li><b>Comprehensive:</b> + семантичний аналіз</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="metric-card">
            <h3>📊 Розширена аналітика</h3>
            <p>Глибокий аналіз SBOM документів</p>
            <ul>
                <li>Оцінка якості (0-100)</li>
                <li>Аналіз залежностей</li>
                <li>Розподіл ліцензій</li>
                <li>Аналіз безпеки</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    st.header("🌟 Унікальні особливості")
    
    features_col1, features_col2 = st.columns(2)
    
    with features_col1:
        st.subheader("🧠 Інтелектуальні можливості")
        st.markdown("""
        - **Smart Auto-Detection**: Розпізнавання формату за структурою та метаданими
        - **Quality Scoring**: Алгоритм оцінки якості на основі повноти та правильності
        - **Semantic Analysis**: Глибокий аналіз компонентів, залежностей та ліцензій
        - **Business Rules**: Перевірка відповідності кращим практикам
        """)
    
    with features_col2:
        st.subheader("⚡ Професійні функції")
        st.markdown("""
        - **Batch Processing**: Валідація множини файлів одночасно
        - **Export Results**: JSON звіти для інтеграції в CI/CD
        - **Performance Metrics**: Моніторинг часу обробки
        - **Interactive Visualizations**: Графіки та діаграми для аналізу
        """)

def show_universal_validator(validator):
    st.header("✅ Універсальний SBOM валідатор")
    
    # Налаштування валідації
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("📁 Завантаження файлу")
        uploaded_file = st.file_uploader(
            "Виберіть SBOM файл",
            type=['json', 'xml'],
            help="Підтримуються SPDX (JSON) та CycloneDX (JSON/XML) файли"
        )
    
    with col2:
        st.subheader("⚙️ Налаштування")
        validation_level = st.selectbox(
            "Рівень валідації:",
            ["basic", "standard", "comprehensive"],
            index=1,
            format_func=lambda x: {
                "basic": "🔸 Basic - синтаксис + схема",
                "standard": "🔶 Standard + бізнес-правила",
                "comprehensive": "🔺 Comprehensive + семантика"
            }[x]
        )
        
        auto_detect = st.checkbox("🎯 Auto-detection", value=True)
        show_raw_content = st.checkbox("📝 Показати вміст файлу", value=False)
    
    # Текстове поле для прямого введення
    st.subheader("✏️ Або введіть SBOM безпосередньо:")
    manual_input = st.text_area(
        "SBOM контент:",
        height=200,
        placeholder='{"bomFormat": "CycloneDX", "specVersion": "1.4", ...}'
    )
    
    # Валідація
    if st.button("🚀 Валідувати SBOM", type="primary"):
        content = None
        filename = ""
        
        if uploaded_file is not None:
            content = uploaded_file.read().decode('utf-8')
            filename = uploaded_file.name
        elif manual_input.strip():
            content = manual_input.strip()
            filename = "manual_input"
        
        if content:
            with st.spinner('Виконується валідація...'):
                result = validator.validate(content, filename, validation_level)
            
            # Відображення результатів
            display_validation_results(result, show_raw_content, content)
        else:
            st.warning("⚠️ Будь ласка, завантажте файл або введіть SBOM контент")

def display_validation_results(result: ValidationResult, show_raw_content: bool, content: str):
    """Відображення результатів валідації"""
    
    # Загальний статус
    if result.is_valid:
        st.success("✅ SBOM валідний!")
    else:
        st.error("❌ SBOM містить помилки")
    
    # Метрики
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("📋 Формат", f"{result.format_type.upper()}")
    
    with col2:
        st.metric("🔢 Версія", result.version)
    
    with col3:
        st.metric("📁 Тип", result.data_type.upper())
    
    with col4:
        st.metric("⏱️ Час обробки", f"{result.processing_time:.2f}с")
    
    # Оцінка якості
    st.subheader("📊 Оцінка якості SBOM")
    col1, col2 = st.columns([1, 2])
    
    with col1:
        # Gauge діаграма
        quality_fig = create_quality_gauge(result.quality_score)
        st.plotly_chart(quality_fig, use_container_width=True)
    
    with col2:
        # Детальна оцінка
        quality_class = ""
        if result.quality_score >= 80:
            quality_class = "quality-excellent"
            quality_text = "Відмінна якість"
        elif result.quality_score >= 60:
            quality_class = "quality-good"
            quality_text = "Хороша якість"
        elif result.quality_score >= 40:
            quality_class = "quality-warning"
            quality_text = "Задовільна якість"
        else:
            quality_class = "quality-poor"
            quality_text = "Потребує покращення"
        
        st.markdown(f"""
        <div class="metric-card">
            <div class="quality-score {quality_class}">{result.quality_score}/100</div>
            <h4>{quality_text}</h4>
            <p>Оцінка базується на структурі, метаданих, повноті компонентів та інформації про безпеку</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Помилки та попередження
    if result.errors:
        st.subheader("❌ Помилки")
        for error in result.errors:
            st.markdown(f"""
            <div class="error-box">
                <strong>Помилка:</strong> {error}
            </div>
            """, unsafe_allow_html=True)
    
    if result.warnings:
        st.subheader("⚠️ Попередження")
        for warning in result.warnings:
            st.markdown(f"""
            <div class="warning-box">
                <strong>Попередження:</strong> {warning}
            </div>
            """, unsafe_allow_html=True)
    
    # Семантичний аналіз
    if result.analysis:
        st.subheader("🧠 Семантичний аналіз")
        display_semantic_analysis(result.analysis)
    
    # Експорт результатів
    st.subheader("📤 Експорт результатів")
    export_data = {
        "timestamp": datetime.now().isoformat(),
        "validation_result": {
            "is_valid": result.is_valid,
            "format_type": result.format_type,
            "version": result.version,
            "data_type": result.data_type,
            "quality_score": result.quality_score,
            "processing_time": result.processing_time,
            "errors": result.errors,
            "warnings": result.warnings,
            "analysis": result.analysis
        }
    }
    
    export_json = json.dumps(export_data, indent=2, ensure_ascii=False)
    st.download_button(
        "💾 Завантажити JSON звіт",
        export_json,
        file_name=f"sbom_validation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json"
    )
    
    # Показати вміст файлу
    if show_raw_content:
        st.subheader("📝 Вміст файлу")
        st.code(content, language="json" if result.data_type == "json" else "xml")

def display_semantic_analysis(analysis: Dict[str, Any]):
    """Відображення семантичного аналізу"""
    
    tabs = st.tabs(["📊 Компоненти", "🔗 Залежності", "⚖️ Ліцензії", "🛡️ Безпека"])
    
    with tabs[0]:  # Компоненти
        if "component_stats" in analysis:
            stats = analysis["component_stats"]
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("📦 Всього компонентів", stats.get("total_components", stats.get("total_packages", 0)))
            with col2:
                st.metric("🔢 З версіями", stats.get("with_versions", 0))
            with col3:
                st.metric("⚖️ З ліцензіями", stats.get("with_licenses", 0))
            
            # Діаграма типів компонентів
            if "component_types" in stats and stats["component_types"]:
                types_df = pd.DataFrame(list(stats["component_types"].items()), 
                                      columns=["Тип", "Кількість"])
                fig = px.pie(types_df, values="Кількість", names="Тип", 
                           title="Розподіл типів компонентів")
                st.plotly_chart(fig, use_container_width=True)
    
    with tabs[1]:  # Залежності
        if "dependency_analysis" in analysis:
            deps = analysis["dependency_analysis"]
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("🔗 Всього залежностей", deps.get("total_dependencies", 0))
            with col2:
                st.metric("📏 Глибина графа", deps.get("dependency_graph_depth", 0))
            with col3:
                st.metric("🌳 Кореневих компонентів", len(deps.get("root_components", [])))
            
            # Список кореневих компонентів
            if deps.get("root_components"):
                st.write("**Кореневі компоненти:**")
                for root in deps["root_components"][:10]:  # Показуємо перші 10
                    st.write(f"- {root}")
    
    with tabs[2]:  # Ліцензії
        if "license_analysis" in analysis:
            licenses = analysis["license_analysis"]
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("⚖️ Унікальних ліцензій", licenses.get("unique_licenses", 0))
            with col2:
                st.metric("❓ Без ліцензій", licenses.get("unlicensed_count", 0))
            with col3:
                total_licenses = sum(licenses.get("distribution", {}).values())
                st.metric("📊 Всього записів", total_licenses)
            
            # Діаграма розподілу ліцензій
            if "distribution" in licenses and licenses["distribution"]:
                license_df = pd.DataFrame(list(licenses["distribution"].items()), 
                                        columns=["Ліцензія", "Кількість"])
                license_df = license_df.sort_values("Кількість", ascending=False).head(10)
                
                fig = px.bar(license_df, x="Ліцензія", y="Кількість", 
                           title="Топ-10 ліцензій")
                fig.update_xaxes(tickangle=45)
                st.plotly_chart(fig, use_container_width=True)
    
    with tabs[3]:  # Безпека
        if "security_analysis" in analysis:
            security = analysis["security_analysis"]
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("🚨 Всього вразливостей", security.get("total_vulnerabilities", 0))
            with col2:
                st.metric("💀 Критичних", security.get("critical_count", 0))
            with col3:
                st.metric("🔴 Високого рівня", security.get("high_count", 0))
            
            # Діаграма розподілу за рівнями серйозності
            if "severity_distribution" in security and security["severity_distribution"]:
                sev_df = pd.DataFrame(list(security["severity_distribution"].items()), 
                                    columns=["Рівень", "Кількість"])
                
                color_map = {
                    "critical": "#8B0000",
                    "high": "#DC143C", 
                    "medium": "#FF8C00",
                    "low": "#32CD32",
                    "unknown": "#808080"
                }
                
                fig = px.bar(sev_df, x="Рівень", y="Кількість",
                           title="Розподіл вразливостей за рівнем серйозності",
                           color="Рівень", color_discrete_map=color_map)
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("ℹ️ Інформація про вразливості відсутня в SBOM")

def show_batch_validator(validator):
    st.header("📊 Пакетна валідація SBOM")
    
    st.markdown("""
    Завантажте декілька SBOM файлів для одночасної валідації та порівняльного аналізу.
    """)
    
    # Завантаження файлів
    uploaded_files = st.file_uploader(
        "Виберіть SBOM файли",
        type=['json', 'xml'],
        accept_multiple_files=True,
        help="Можна завантажити до 10 файлів одночасно"
    )
    
    validation_level = st.selectbox(
        "Рівень валідації:",
        ["basic", "standard", "comprehensive"],
        index=1,
        key="batch_validation_level"
    )
    
    if uploaded_files and st.button("🚀 Валідувати всі файли", type="primary"):
        if len(uploaded_files) > 10:
            st.error("❌ Максимальна кількість файлів - 10")
            return
        
        results = []
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        for i, file in enumerate(uploaded_files):
            status_text.text(f"Обробка {file.name}...")
            content = file.read().decode('utf-8')
            result = validator.validate(content, file.name, validation_level)
            results.append((file.name, result))
            progress_bar.progress((i + 1) / len(uploaded_files))
        
        status_text.text("Готово!")
        
        # Відображення результатів
        display_batch_results(results)

def display_batch_results(results: List[Tuple[str, ValidationResult]]):
    """Відображення результатів пакетної валідації"""
    
    # Загальна статистика
    st.subheader("📈 Загальна статистика")
    
    total_files = len(results)
    valid_files = sum(1 for _, result in results if result.is_valid)
    avg_quality = sum(result.quality_score for _, result in results) / total_files
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("📁 Всього файлів", total_files)
    with col2:
        st.metric("✅ Валідних", valid_files)
    with col3:
        st.metric("❌ З помилками", total_files - valid_files)
    with col4:
        st.metric("📊 Середня якість", f"{avg_quality:.1f}")
    
    # Таблиця результатів
    st.subheader("📋 Деталі валідації")
    
    table_data = []
    for filename, result in results:
        status = "✅ Валідний" if result.is_valid else "❌ Помилки"
        table_data.append({
            "Файл": filename,
            "Статус": status,
            "Формат": f"{result.format_type.upper()} {result.version}",
            "Тип": result.data_type.upper(),
            "Якість": result.quality_score,
            "Помилки": len(result.errors),
            "Попередження": len(result.warnings),
            "Час (с)": f"{result.processing_time:.2f}"
        })
    
    df = pd.DataFrame(table_data)
    st.dataframe(df, use_container_width=True)
    
    # Візуалізації
    st.subheader("📊 Візуалізація результатів")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Розподіл оцінок якості
        quality_scores = [result.quality_score for _, result in results]
        fig = px.histogram(x=quality_scores, nbins=10, 
                          title="Розподіл оцінок якості",
                          labels={'x': 'Оцінка якості', 'y': 'Кількість файлів'})
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Розподіл форматів
        formats = [f"{result.format_type.upper()} {result.version}" for _, result in results]
        format_counts = pd.Series(formats).value_counts()
        fig = px.pie(values=format_counts.values, names=format_counts.index,
                    title="Розподіл форматів SBOM")
        st.plotly_chart(fig, use_container_width=True)
    
    # Експорт пакетного звіту
    st.subheader("📤 Експорт пакетного звіту")
    
    batch_report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_files": total_files,
            "valid_files": valid_files,
            "invalid_files": total_files - valid_files,
            "average_quality": avg_quality
        },
        "results": [
            {
                "filename": filename,
                "is_valid": result.is_valid,
                "format_type": result.format_type,
                "version": result.version,
                "quality_score": result.quality_score,
                "errors": result.errors,
                "warnings": result.warnings
            }
            for filename, result in results
        ]
    }
    
    report_json = json.dumps(batch_report, indent=2, ensure_ascii=False)
    st.download_button(
        "💾 Завантажити пакетний звіт",
        report_json,
        file_name=f"batch_validation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json"
    )

def show_schema_browser(validator):
    st.header("📋 Браузер схем SBOM")
    
    st.markdown("""
    Інтерактивний перегляд підтримуваних схем для SPDX та CycloneDX форматів.
    """)
    
    # Вибір формату та версії
    col1, col2 = st.columns(2)
    
    with col1:
        format_type = st.selectbox(
            "Формат:",
            ["spdx", "cyclonedx"],
            format_func=lambda x: x.upper()
        )
    
    with col2:
        versions = list(validator.supported_formats[format_type].keys())
        version = st.selectbox("Версія:", versions)
    
    # Відображення схеми
    st.subheader(f"📄 Схема {format_type.upper()} {version}")
    
    if format_type == "spdx":
        if version == "2.3":
            schema = validator.spdx_schema_2_3
        elif version == "3.0":
            schema = validator.spdx_schema_3_0
        else:
            schema = {"error": "Схема не знайдена"}
    elif format_type == "cyclonedx":
        schema = validator.cyclonedx_schema
    
    # Відображення схеми у форматі JSON
    st.json(schema)
    
    # Приклад структури
    st.subheader("💡 Приклад структури")
    
    if format_type == "spdx" and version == "2.3":
        example = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "Example SBOM",
            "dataLicense": "CC0-1.0",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-1",
                    "name": "example-package",
                    "versionInfo": "1.0.0",
                    "licenseConcluded": "MIT"
                }
            ]
        }
    elif format_type == "cyclonedx":
        example = {
            "bomFormat": "CycloneDX",
            "specVersion": version,
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": [
                    {"name": "enhanced-sbom-validator", "version": "1.0.0"}
                ]
            },
            "components": [
                {
                    "type": "library",
                    "name": "example-library",
                    "version": "2.1.0",
                    "licenses": [
                        {"license": {"id": "Apache-2.0"}}
                    ]
                }
            ]
        }
    
    st.json(example)

def show_examples_page(validator):
    st.header("📝 Приклади та тести")
    
    st.markdown("""
    Готові приклади SBOM файлів для тестування валідатора.
    """)
    
    # Вибір прикладу
    example_type = st.selectbox(
        "Виберіть приклад:",
        [
            "CycloneDX 1.4 - Мінімальний",
            "CycloneDX 1.4 - Повний",
            "SPDX 2.3 - Базовий",
            "CycloneDX 1.4 - З вразливостями",
            "Некоректний JSON",
            "Некоректна структура"
        ]
    )
    
    examples = get_test_examples()
    
    if example_type in examples:
        example_content = examples[example_type]
        
        st.subheader(f"📄 Приклад: {example_type}")
        st.code(example_content, language="json")
        
        # Кнопка для тестування
        if st.button(f"🧪 Тестувати {example_type}"):
            with st.spinner('Тестування...'):
                result = validator.validate(example_content, f"example_{example_type.lower()}.json", "comprehensive")
            
            display_validation_results(result, False, example_content)

def get_test_examples():
    """Повертає словник з тестовими прикладами"""
    return {
        "CycloneDX 1.4 - Мінімальний": json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": []
        }, indent=2),
        
        "CycloneDX 1.4 - Повний": json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T12:00:00Z",
                "tools": [
                    {"name": "enhanced-sbom-validator", "version": "1.0.0"}
                ],
                "authors": [
                    {"name": "SBOM Generator", "email": "sbom@example.com"}
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
                    "name": "lodash",
                    "version": "4.17.21",
                    "licenses": [
                        {"license": {"id": "MIT"}}
                    ],
                    "purl": "pkg:npm/lodash@4.17.21"
                },
                {
                    "type": "library", 
                    "name": "react",
                    "version": "18.2.0",
                    "licenses": [
                        {"license": {"id": "MIT"}}
                    ],
                    "purl": "pkg:npm/react@18.2.0"
                }
            ],
            "dependencies": [
                {
                    "ref": "pkg:npm/my-application@1.0.0",
                    "dependsOn": [
                        "pkg:npm/lodash@4.17.21",
                        "pkg:npm/react@18.2.0"
                    ]
                }
            ]
        }, indent=2),
        
        "SPDX 2.3 - Базовий": json.dumps({
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "Example SBOM Document",
            "dataLicense": "CC0-1.0",
            "creationInfo": {
                "created": "2024-01-01T12:00:00Z",
                "creators": ["Tool: enhanced-sbom-validator"]
            },
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-lodash",
                    "name": "lodash",
                    "versionInfo": "4.17.21",
                    "licenseConcluded": "MIT",
                    "downloadLocation": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                }
            ]
        }, indent=2),
        
        "CycloneDX 1.4 - З вразливостями": json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4", 
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "vulnerable-lib",
                    "version": "1.0.0",
                    "licenses": [
                        {"license": {"id": "MIT"}}
                    ],
                    "vulnerabilities": [
                        {
                            "id": "CVE-2023-12345",
                            "severity": "high",
                            "description": "Example vulnerability"
                        },
                        {
                            "id": "CVE-2023-67890", 
                            "severity": "critical",
                            "description": "Critical security issue"
                        }
                    ]
                }
            ]
        }, indent=2),
        
        "Некоректний JSON": '{"bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1, "components": [}',
        
        "Некоректна структура": json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4"
            # Відсутні обов'язкові поля
        }, indent=2)
    }

def show_advanced_analysis(validator):
    st.header("🔍 Розширений аналіз SBOM")
    
    st.markdown("""
    Глибокий аналіз SBOM документів з фокусом на залежності, ліцензії та безпеку.
    """)
    
    uploaded_file = st.file_uploader(
        "Завантажте SBOM для розширеного аналізу",
        type=['json', 'xml']
    )
    
    if uploaded_file:
        content = uploaded_file.read().decode('utf-8')
        
        with st.spinner('Виконується розширений аналіз...'):
            result = validator.validate(content, uploaded_file.name, "comprehensive")
        
        if result.analysis:
            st.success("✅ Аналіз завершено")
            
            # Детальний аналіз залежностей
            if "dependency_analysis" in result.analysis:
                st.subheader("🕸️ Граф залежностей")
                deps = result.analysis["dependency_analysis"]
                
                # Створення візуалізації графа залежностей
                if deps.get("total_dependencies", 0) > 0:
                    # Тут можна додати більш складну візуалізацію графа
                    st.info("📊 Візуалізація графа залежностей буде додана в наступній версії")
                
                # Аналіз глибини та складності
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("📏 Максимальна глибина", deps.get("dependency_graph_depth", 0))
                with col2:
                    st.metric("🌳 Кореневі вузли", len(deps.get("root_components", [])))
                with col3:
                    st.metric("🍃 Листові вузли", len(deps.get("leaf_components", [])))
            
            # Аналіз ліцензійного ризику
            if "license_analysis" in result.analysis:
                st.subheader("⚖️ Ліцензійний ризик")
                licenses = result.analysis["license_analysis"]
                
                # Класифікація ліцензій за рівнем ризику
                license_risk = classify_license_risk(licenses.get("distribution", {}))
                
                if license_risk:
                    risk_df = pd.DataFrame(list(license_risk.items()), 
                                         columns=["Рівень ризику", "Кількість"])
                    
                    colors = {"Низький": "green", "Середній": "orange", "Високий": "red", "Невідомий": "gray"}
                    fig = px.bar(risk_df, x="Рівень ризику", y="Кількість",
                               color="Рівень ризику", color_discrete_map=colors,
                               title="Розподіл ліцензій за рівнем ризику")
                    st.plotly_chart(fig, use_container_width=True)
            
            # Рекомендації
            st.subheader("💡 Рекомендації")
            generate_recommendations(result)
        else:
            st.warning("⚠️ Розширений аналіз не доступний для цього типу SBOM")

def classify_license_risk(license_distribution: Dict[str, int]) -> Dict[str, int]:
    """Класифікація ліцензій за рівнем ризику"""
    risk_classification = {
        "Низький": ["MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC"],
        "Середній": ["GPL-2.0", "GPL-3.0", "LGPL-2.1", "LGPL-3.0", "MPL-2.0"],
        "Високий": ["AGPL-3.0", "GPL-2.0-only", "GPL-3.0-only"],
        "Невідомий": ["NOASSERTION", "Unknown"]
    }
    
    risk_counts = {"Низький": 0, "Середній": 0, "Високий": 0, "Невідомий": 0}
    
    for license_id, count in license_distribution.items():
        classified = False
        for risk_level, licenses in risk_classification.items():
            if license_id in licenses:
                risk_counts[risk_level] += count
                classified = True
                break
        
        if not classified:
            risk_counts["Невідомий"] += count
    
    return risk_counts

def generate_recommendations(result: ValidationResult):
    """Генерація рекомендацій на основі результатів аналізу"""
    recommendations = []
    
    # Рекомендації на основі помилок
    if result.errors:
        recommendations.append("🔴 **Критично**: Виправте всі помилки валідації перед використанням SBOM")
    
    # Рекомендації на основі якості
    if result.quality_score < 60:
        recommendations.append("🟡 **Покращення якості**: Додайте більше метаданих та інформації про компоненти")
    
    # Рекомендації на основі аналізу
    if result.analysis:
        # Ліцензії
        if "license_analysis" in result.analysis:
            unlicensed = result.analysis["license_analysis"].get("unlicensed_count", 0)
            if unlicensed > 0:
                recommendations.append(f"⚖️ **Ліцензії**: Додайте інформацію про ліцензії для {unlicensed} компонентів")
        
        # Безпека
        if "security_analysis" in result.analysis:
            critical_vulns = result.analysis["security_analysis"].get("critical_count", 0)
            if critical_vulns > 0:
                recommendations.append(f"🚨 **Безпека**: Знайдено {critical_vulns} критичних вразливостей - негайно оновіть компоненти")
        
        # Версії
        if "component_stats" in result.analysis:
            stats = result.analysis["component_stats"]
            total = stats.get("total_components", stats.get("total_packages", 0))
            with_versions = stats.get("with_versions", 0)
            if total > 0 and (with_versions / total) < 0.8:
                recommendations.append("🔢 **Версії**: Додайте номери версій для всіх компонентів")
    
    # Загальні рекомендації
    if result.quality_score >= 80:
        recommendations.append("✅ **Відмінно**: SBOM відповідає високим стандартам якості")
    
    if not recommendations:
        recommendations.append("✅ **Гарна робота**: Основні рекомендації відсутні")
    
    for rec in recommendations:
        st.markdown(rec)

def show_support_matrix(validator):
    st.header("📈 Матриця підтримки форматів")
    
    st.markdown("""
    Повна таблиця підтримуваних форматів, версій та типів файлів.
    """)
    
    # Створення таблиці підтримки
    support_data = []
    
    for format_name, versions in validator.supported_formats.items():
        for version, data_types in versions.items():
            for data_type, supported in data_types.items():
                status = "✅ Підтримується" if supported else "❌ Не підтримується"
                support_data.append({
                    "Формат": format_name.upper(),
                    "Версія": version,
                    "Тип файлу": data_type.upper(),
                    "Статус": status,
                    "Валідація схеми": "✅" if supported else "❌",
                    "Бізнес-правила": "✅" if supported else "❌",
                    "Семантичний аналіз": "✅" if supported and format_name == "cyclonedx" else "⚠️"
                })
    
    df = pd.DataFrame(support_data)
    st.dataframe(df, use_container_width=True)
    
    # Статистика підтримки
    st.subheader("📊 Статистика підтримки")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        total_combinations = len(support_data)
        supported_combinations = len([d for d in support_data if "✅" in d["Статус"]])
        st.metric("📋 Всього комбінацій", total_combinations)
        st.metric("✅ Підтримується", supported_combinations)
    
    with col2:
        formats_count = len(validator.supported_formats)
        versions_count = sum(len(versions) for versions in validator.supported_formats.values())
        st.metric("📚 Форматів", formats_count)
        st.metric("🔢 Версій", versions_count)
    
    with col3:
        json_support = len([d for d in support_data if d["Тип файлу"] == "JSON" and "✅" in d["Статус"]])
        xml_support = len([d for d in support_data if d["Тип файлу"] == "XML" and "✅" in d["Статус"]])
        st.metric("📄 JSON підтримка", json_support)
        st.metric("🏷️ XML підтримка", xml_support)
    
    # Діаграма підтримки
    format_counts = df.groupby("Формат").size()
    fig = px.bar(x=format_counts.index, y=format_counts.values,
                title="Кількість підтримуваних варіантів за форматами",
                labels={'x': 'Формат', 'y': 'Кількість варіантів'})
    st.plotly_chart(fig, use_container_width=True)
    
    # Детальна інформація про можливості
    st.subheader("🔍 Детальні можливості")
    
    capabilities = {
        "Auto-Detection": {
            "SPDX JSON": "✅ Повна підтримка",
            "CycloneDX JSON": "✅ Повна підтримка", 
            "CycloneDX XML": "✅ Повна підтримка",
            "SPDX XML": "⚠️ Базова підтримка"
        },
        "Валідація схеми": {
            "JSON Schema": "✅ JSONSchema validation",
            "XML Schema": "✅ XSD validation",
            "Бізнес-правила": "✅ Custom validation rules",
            "Семантична валідація": "✅ Deep structure analysis"
        },
        "Аналітика": {
            "Компоненти": "✅ Статистика та типи",
            "Залежності": "✅ Граф та глибина",
            "Ліцензії": "✅ Розподіл та ризики",
            "Безпека": "✅ Вразливості та рівні"
        },
        "Експорт": {
            "JSON звіти": "✅ Структуровані дані",
            "CSV експорт": "⚠️ Планується",
            "PDF звіти": "⚠️ Планується", 
            "API інтеграція": "⚠️ Планується"
        }
    }
    
    for category, features in capabilities.items():
        with st.expander(f"📋 {category}"):
            for feature, status in features.items():
                st.markdown(f"- **{feature}**: {status}")

if __name__ == "__main__":
    main()