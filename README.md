# 🛡️ ARESITOS - Advanced Security Auditing Toolkit

![Aresitos](ares_aegis/recursos/Aresitos.ico)

**Aresitos** is a comprehensive cybersecurity suite developed for information security professionals. It combines scanning tools, monitoring, vulnerability analysis, advanced wordlist management, and report generation in a unified and optimized interface with **real-time data processing**.

## 🎯 Core Features

### 🔍 **Advanced Scanning Module**
- **Real-time port scanning** with nmap integration
- **Live service analysis** and detection
- **Vulnerability assessment** with CVE database
- **Advanced SIEM system** with event correlation
- **Network monitoring** and threat detection
- **Stealth scanning** capabilities

### 📊 **Real-Time System Monitoring**
- **Live resource monitoring** (CPU, Memory, Disk, Network)
- **Process behavior analysis** with anomaly detection
- **Network connection tracking** and suspicious activity alerts
- **File Integrity Monitoring (FIM)** with hash verification
- **Automated security alerts** and notifications
- **Background threat hunting**

### 🛠️ **Professional Security Utilities**
- **Security tool verification** and validation
- **Lynis security auditing** integration
- **Rootkit detection** (chkrootkit, rkhunter)
- **Advanced wordlist management** with auto-loading
- **Technical cybersecurity dictionaries** (13+ categories)
- **Permission and configuration analysis**
- **System cleanup and optimization**

### 📋 **Enterprise-Grade Reporting**
- **Comprehensive reports** in JSON/TXT/Markdown formats
- **Risk scoring** with professional metrics
- **Technical recommendations** and remediation steps
- **Data export** and historical analysis
- **Executive summaries** for management

### � **Dynamic Wordlist System**
- **16+ wordlist categories** automatically loaded
- **1,266 advanced passwords** + personalized collections
- **994 API endpoints** + custom definitions
- **930 web directories** + enterprise paths
- **852 subdomains** + custom lists
- **User-extensible** - add JSON files to auto-load

### 📚 **Technical Dictionary Database**
- **13+ specialized dictionaries** automatically loaded
- **418 cybersecurity terms** + custom definitions
- **406 hacking tools** + technical descriptions
- **371 MITRE ATT&CK** techniques and tactics
- **300 vulnerability types** + exploit information
- **Auto-discovery** system for new JSON dictionaries

## 📋 System Requirements

### **Supported Operating Systems**
- ✅ **Kali Linux** (Recommended - Full functionality)
- ✅ **Ubuntu/Debian** (Extended functionality)
- ✅ **CentOS/RHEL** (Core functionality)
- ✅ **Windows** (Limited functionality - some features require WSL)
- ⚠️ **Other Linux distributions** (Basic functionality)

### **Dependencies**
```bash
# Python 3.8 or higher required
python3 --version

# Core system dependencies
pip install -r requirements.txt

# Required packages:
# - customtkinter>=5.2.0
# - pillow>=10.0.0
# - requests>=2.31.0
# - psutil>=5.9.0
# - python-nmap>=0.7.1
# - scapy>=2.4.5
# - pandas>=2.0.0
# - matplotlib>=3.7.0
# - watchdog>=3.0.0
# - colorlog>=6.7.0
```

### **Security Tools** (Optional for full functionality)
```bash
# Critical tools for complete feature set
sudo apt install nmap masscan nikto gobuster sqlmap
sudo apt install lynis chkrootkit rkhunter
sudo apt install netcat-traditional socat
sudo apt install whatweb dirb
```

## 🚀 Installation & Setup

### **Quick Installation**
```bash
# Clone the repository
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# Install dependencies
pip install -r requirements.txt

# Launch Aresitos
python main.py
```

### **Installation Verification**
```bash
# Verify critical tools
nmap --version
lynis --version
python -c "import psutil; print('psutil OK')"
```

### **Data Auto-Loading Verification**
Upon startup, Aresitos automatically scans and loads:
- **Wordlists** from `data/wordlists/` (TXT and JSON files)
- **Dictionaries** from `data/diccionarios/` (JSON files)
- **Configuration** from `configuracion/` directory
- **User customizations** detected automatically

## 💻 Professional Interface

### **Launch Application**
```bash
python main.py
```

### **Modern GUI Interface**
Professional interface optimized for security analysts with **real-time updates**:

#### 🔍 **Scanning & SIEM Tab**
- **Advanced port scanning** with nmap integration
- **Vulnerability assessment** and CVE correlation
- **Real-time security event monitoring**
- **Log analysis** and pattern detection
- **Network discovery** and mapping

#### 📊 **System Monitoring Tab**
- **Real-time system metrics** (CPU, RAM, Disk, Network)
- **Process monitoring** with threat detection
- **Network connection analysis**
- **File integrity monitoring**
- **Security alert management**

#### 🛠️ **Security Tools Tab**
- **Security tool verification** and status
- **Hardware information** and analysis
- **Process analysis** and investigation
- **Permission verification** and hardening
- **System cleanup** and optimization

#### 🔒 **Security Auditing Tab**
- **Lynis security audit** execution
- **Rootkit detection** and analysis
- **Configuration assessment**
- **Compliance checking**
- **Security baseline validation**

#### 📋 **Professional Reports Tab**
- **Technical report generation**
- **JSON/TXT/Markdown export**
- **Historical analysis** and trending
- **Executive summaries**
- **Compliance reporting**

#### 📝 **Wordlist Management Tab**
- **16+ categories** of security wordlists
- **1,266 advanced passwords** + custom collections
- **Import/export** functionality
- **Auto-loading** from JSON files
- **User-extensible** architecture

#### 📚 **Dictionary Database Tab**
- **13+ technical dictionaries** automatically loaded
- **Cybersecurity terminology** database
- **Vulnerability definitions** and descriptions
- **Tool documentation** and references
- **Custom dictionary** support

## 🏗️ Advanced Architecture

### **Real-Time Processing Engine**
```
Aresitos/
├── main.py                     # Application launcher
├── requirements.txt            # Python dependencies
├── README.md                   # Complete documentation
├── .gitignore                  # Version control
├── ares_aegis/                 # Core application package
│   ├── __init__.py
│   ├── modelo/                 # Real-time data models
│   │   ├── modelo_principal.py         # Main coordinator
│   │   ├── modelo_escaneador.py        # Real-time scanner
│   │   ├── modelo_siem.py              # SIEM with correlation
│   │   ├── modelo_monitor.py           # System monitor
│   │   ├── modelo_fim.py               # File integrity
│   │   ├── modelo_gestor_wordlists.py  # Wordlist manager
│   │   ├── modelo_gestor_diccionarios.py # Dictionary manager
│   │   ├── modelo_reportes.py          # Report generation
│   │   └── modelo_utilidades_sistema.py # System utilities
│   ├── controlador/            # MVC Controllers
│   │   ├── controlador_principal.py    # Main controller
│   │   ├── controlador_escaneo.py      # Scan controller
│   │   ├── controlador_monitoreo.py    # Monitor controller
│   │   ├── controlador_auditoria.py    # Audit controller
│   │   ├── controlador_herramientas.py # Tools controller
│   │   ├── controlador_reportes.py     # Report controller
│   │   └── controlador_utilidades.py   # Utility controller
│   ├── vista/                  # Professional UI (CustomTkinter)
│   │   ├── vista_principal.py          # Main interface
│   │   ├── vista_escaneo.py            # Scanning interface
│   │   ├── vista_monitoreo.py          # Monitoring dashboard
│   │   ├── vista_auditoria.py          # Audit interface
│   │   ├── vista_herramientas.py       # Tools interface
│   │   ├── vista_wordlists.py          # Wordlist manager UI
│   │   ├── vista_diccionarios.py       # Dictionary UI
│   │   ├── vista_reportes.py           # Report interface
│   │   ├── vista_utilidades.py         # Utilities interface
│   │   └── burp_theme.py               # Professional theme
│   ├── recursos/               # Application resources
│   │   └── Aresitos.ico               # Application icon
│   └── utils/                  # Utility modules
├── configuracion/              # Configuration files
│   └── ares_aegis_config.json         # Main configuration
├── data/                       # Auto-loaded data
│   ├── wordlists/              # 16+ wordlist categories
│   │   ├── passwords_top1000.txt      # 1,266 passwords
│   │   ├── api_endpoints.txt          # 994 API endpoints
│   │   ├── web_directories.txt        # 930 directories
│   │   ├── subdomains_common.txt      # 852 subdomains
│   │   └── ejemplo_usuario.json       # User customizations
│   └── diccionarios/           # 13+ technical dictionaries
│       ├── cybersecurity_terms.json   # 418 security terms
│       ├── hacking_tools.json         # 406 tool descriptions
│       ├── mitre_attack.json          # 371 ATT&CK techniques
│       ├── vulnerabilities.json       # 300 vulnerability types
│       └── ejemplo_usuario.json       # User customizations
└── tests/                      # Comprehensive testing suite
    ├── run_tests.py            # Test runner
    ├── test_base.py            # Base test framework
    ├── test_escaneador.py      # Scanner tests
    ├── test_monitor.py         # Monitor tests
    ├── test_integracion.py     # Integration tests
    ├── test_wordlists_diccionarios.py # Data tests
    ├── integration/            # Integration test suite
    ├── performance/            # Performance benchmarks
    ├── security/               # Security validation tests
    └── unit/                   # Unit test modules
```

## 🔧 Real-Time Data Processing

### **Automatic Data Loading System**
```bash
# System automatically detects and loads:
- 16+ wordlist categories (5,000+ entries)
- 13+ dictionary databases (1,500+ definitions)
- User JSON files (auto-discovery)
- Configuration updates (real-time)
```

### **Live Monitoring Capabilities**
- **CPU/Memory/Disk**: Real-time psutil integration
- **Network Connections**: Live connection tracking
- **Process Analysis**: Behavioral anomaly detection
- **File Changes**: Hash-based integrity monitoring
- **Security Events**: SIEM correlation engine

### **Professional Features**
- **No simulated data** - all metrics are real-time
- **No demo modes** - production-ready functionality
- **Enterprise architecture** - scalable and robust
- **Professional interface** - optimized for analysts

## 🧪 Comprehensive Testing

### **Execute Complete Test Suite**
```bash
cd tests
python run_tests.py
```

### **Specific Test Categories**
```bash
# List available tests
python run_tests.py --list

# Execute specific test module
python run_tests.py --module test_escaneador

# Performance benchmarks
python run_tests.py --performance

# Security validation tests
python run_tests.py --security
```

### **Available Test Modules**
- `test_escaneador.py` - Scanner functionality
- `test_monitor.py` - System monitoring
- `test_integracion.py` - Integration tests
- `test_wordlists_diccionarios.py` - Data management
- `test_base.py` - Core framework tests
- `integration/` - End-to-end testing
- `performance/` - Performance benchmarks
- `security/` - Security validation

## 🛡️ Security & Professional Use

### **Professional Deployment**
- Designed for **cybersecurity professionals**
- **Real-time threat detection** capabilities
- **Enterprise-grade reporting** and documentation
- **Compliance-ready** audit trails
- **Scalable architecture** for team environments

### **Security Considerations**
- Some modules require **administrative privileges**
- Recommended execution: `sudo python main.py` for full functionality
- **Audit logging** for all security operations
- **Encrypted storage** for sensitive configurations

### **Best Practices**
- Execute in **controlled environments**
- Regular **security baseline** updates
- **Tool validation** before critical operations
- **Backup configurations** and custom data

## 🤝 Development & Contribution

### **Development Environment**
```bash
# Set up development environment
git clone https://github.com/DogSoulDev/Aresitos.git
cd Aresitos

# Install development dependencies
pip install -r requirements.txt

# Run comprehensive tests
cd tests && python run_tests.py

# Create feature branch
git checkout -b feature/new-functionality
git commit -am 'Add: new security feature'
git push origin feature/new-functionality
```

### **Code Standards**
- **Python 3.8+** minimum requirement
- **PEP 8** compliance mandatory
- **Comprehensive documentation** required
- **Unit tests** for all new features
- **MVC architecture** strictly enforced
- **Real-time processing** - no simulated data

## 📊 Changelog & Version History

### **v3.0** - Real-Time Security Platform
- ✅ **Complete refactoring** to real-time architecture
- ✅ **Advanced SIEM** with event correlation
- ✅ **File Integrity Monitoring** with hash verification
- ✅ **Auto-loading data system** for wordlists/dictionaries
- ✅ **16+ wordlist categories** with 5,000+ entries
- ✅ **13+ technical dictionaries** with 1,500+ definitions
- ✅ **Professional interface** optimized for analysts
- ✅ **Comprehensive testing** suite with 100+ tests

### **v2.5** - Professional Enhancement
- ✅ **CustomTkinter interface** for modern look
- ✅ **Burp Suite theme** integration
- ✅ **Advanced reporting** with multiple formats
- ✅ **Performance optimization** for large datasets

### **v2.0** - Security Focus
- ✅ **Advanced scanning** capabilities
- ✅ **SIEM integration** with correlation
- ✅ **Real-time monitoring** dashboard
- ✅ **Professional reporting** system

## 📞 Support & Contact

### **Professional Support**
- **GitHub Issues**: Technical problems and feature requests
- **Security Issues**: Responsible disclosure process
- **Documentation**: Comprehensive inline documentation
- **Community**: Professional cybersecurity community

### **Developer Information**
- **Author**: DogSoulDev
- **Email**: dogsouldev@protonmail.com
- **GitHub**: [@DogSoulDev](https://github.com/DogSoulDev)
- **Repository**: [Aresitos](https://github.com/DogSoulDev/Aresitos)

## 📄 License & Legal

This project is licensed under the **MIT License**. See `LICENSE` file for complete details.

---

## 🏆 Acknowledgments

- **Kali Linux Team** - For the foundational security tools
- **OWASP Community** - For security testing methodologies
- **MITRE Corporation** - For ATT&CK framework integration
- **Cybersecurity Community** - For feedback and validation
- **Open Source Contributors** - For code reviews and improvements

---

**⚠️ Legal Disclaimer**: Aresitos is designed for cybersecurity professionals and ethical security testing. The author is not responsible for misuse of this tool.

**🎯 Professional Use Cases**: 
- **Penetration Testing** and security assessments
- **Security Auditing** and compliance validation
- **Incident Response** and forensic analysis
- **System Hardening** and configuration management
- **Vulnerability Management** and risk assessment
- **Security Operations Center (SOC)** activities

**🔒 Target Audience**: Cybersecurity professionals, penetration testers, security auditors, incident responders, SOC analysts, and system administrators.
