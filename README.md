# 🔐 Encryptly

**Give unbreakable trust to your AI agents.**

---

## 🧠 What is Encryptly?

Encryptly is a powerful, developer-friendly authentication SDK that seamlessly integrates security into your multi-agent AI applications. It serves as the perfect security layer for your AI stack, providing JWT-based authentication and role-based access control that protects your agents from impersonation, unauthorized access, and malicious attacks.

With Encryptly, you can:
- **Secure agent authentication** with JWT tokens and cryptographic verification
- **Prevent agent impersonation** through robust identity validation
- **Control access with roles** to ensure only authorized agents perform specific tasks
- **Protect inter-agent communication** with signed messages and verification

---

## ⭐ Key Features

- **Universal Framework Support**: Works with CrewAI, LangChain, and any custom AI framework
- **JWT Authentication**: Industry-standard token-based authentication for agents
- **Role-Based Access Control**: Define and enforce agent permissions and capabilities
- **Message Signing**: Cryptographically sign and verify inter-agent communications
- **Simple Integration**: Clean, consistent API with easy-to-use integrations
- **Framework-Agnostic Core**: Use the same security features across different AI frameworks

---

## 🚀 Getting Started

### Installation

```bash
pip install encryptly
```

### Quick Start

```python
from encryptly.vault import Encryptly
from encryptly.integrations import CrewAIIntegration

# Initialize Encryptly
vault = Encryptly()
crew_integration = CrewAIIntegration(vault)

# Secure your agents
data_analyst_token = crew_integration.secure_agent(
    "data_analyst_001", 
    "Data Analyst", 
    "DataAnalystAgent"
)

risk_advisor_token = crew_integration.secure_agent(
    "risk_advisor_001", 
    "Risk Advisor", 
    "RiskManagementAgent"
)

# Verify agent authentication
is_valid, agent_info = vault.verify(data_analyst_token)
if is_valid:
    print(f"Agent verified: {agent_info['agent_id']} ({agent_info['role']})")

# Secure inter-agent communication
message = "Request risk assessment for AAPL"
is_verified = crew_integration.verify_agent_communication(
    "data_analyst_001", 
    "risk_advisor_001", 
    message
)
```

---

## 📚 Documentation

We've created comprehensive documentation to help you get the most out of Encryptly:

- **Quick Start Guide**: Get up and running in minutes
- **API Reference**: Complete SDK documentation
- **Framework Integrations**: CrewAI, LangChain, and custom frameworks
- **Security Best Practices**: Protect your AI agents effectively
- **Use Cases & Examples**: Real-world implementation patterns

---

