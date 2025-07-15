"""
Encryptly SDK - CrewAI Example
===============================

This example demonstrates how to use Encryptly to secure a CrewAI multi-agent system.
Shows agent registration, secure communication, and task verification.
"""

import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from encryptly import Encryptly, CrewAIIntegration
from encryptly.exceptions import AuthenticationError


# Mock CrewAI Agent classes (in real usage, these would be actual CrewAI agents)
class DataAnalystAgent:
    def __init__(self, agent_id: str, vault_token: str):
        self.agent_id = agent_id
        self.vault_token = vault_token
        self.vault = None  # Will be set by the integration
    
    def analyze_market_data(self, data: str, caller_token: str = None) -> str:
        """Analyze market data - requires caller authentication."""
        if caller_token:
            # Verify caller in real implementation
            print(f"🔍 Caller verification requested for {self.agent_id}")
        
        analysis = f"Market analysis by {self.agent_id}: {data} shows positive trends"
        return analysis
    
    def get_analysis_report(self) -> str:
        """Get analysis report."""
        return f"Analysis report from {self.agent_id}: Markets are volatile but trending upward"


class RiskAdvisorAgent:
    def __init__(self, agent_id: str, vault_token: str):
        self.agent_id = agent_id
        self.vault_token = vault_token
        self.vault = None
    
    def assess_risk(self, analysis_data: str, caller_token: str = None) -> str:
        """Assess risk based on analysis data."""
        if caller_token:
            print(f"🔍 Caller verification requested for {self.agent_id}")
        
        risk_assessment = f"Risk assessment by {self.agent_id}: Based on '{analysis_data}', risk is MODERATE"
        return risk_assessment


class TradingExecutorAgent:
    def __init__(self, agent_id: str, vault_token: str):
        self.agent_id = agent_id
        self.vault_token = vault_token
        self.vault = None
    
    def execute_trade(self, trade_data: str, caller_token: str = None) -> str:
        """Execute a trade - high security method."""
        if caller_token:
            print(f"🔍 Caller verification requested for {self.agent_id}")
        
        execution = f"Trade executed by {self.agent_id}: {trade_data}"
        return execution


def main():
    """Demonstrate Encryptly with CrewAI-style agents."""
    
    print("🚀 Encryptly + CrewAI Example")
    print("=" * 50)
    
    # Initialize Encryptly
    vault = Encryptly(token_expiry_hours=12)
    
    # Initialize CrewAI integration
    crew_integration = CrewAIIntegration(vault)
    
    print("\n1️⃣ Registering Agents")
    print("-" * 30)
    
    # Register agents
    analyst_token = crew_integration.secure_agent("analyst-001", "DataAnalyst", "DataAnalystAgent")
    risk_token = crew_integration.secure_agent("risk-advisor-001", "RiskAdvisor", "RiskAdvisorAgent")
    trader_token = crew_integration.secure_agent("trader-001", "TradingExecutor", "TradingExecutorAgent")
    
    print(f"✅ Data Analyst registered with token: {analyst_token[:20]}...")
    print(f"✅ Risk Advisor registered with token: {risk_token[:20]}...")
    print(f"✅ Trading Executor registered with token: {trader_token[:20]}...")
    
    # Create agent instances
    analyst = DataAnalystAgent("analyst-001", analyst_token)
    risk_advisor = RiskAdvisorAgent("risk-advisor-001", risk_token)
    trader = TradingExecutorAgent("trader-001", trader_token)
    
    print("\n2️⃣ Secure Task Creation")
    print("-" * 30)
    
    # Create secure tasks
    try:
        analysis_task = crew_integration.create_secure_task(
            "Analyze current market trends for tech stocks",
            "analyst-001",
            required_role="DataAnalyst"
        )
        print(f"✅ Analysis task created: {analysis_task['task_id']}")
        
        risk_task = crew_integration.create_secure_task(
            "Assess risk for the analyzed market data",
            "risk-advisor-001",
            required_role="RiskAdvisor"
        )
        print(f"✅ Risk assessment task created: {risk_task['task_id']}")
        
        # Try to create task with wrong role (should fail)
        try:
            wrong_task = crew_integration.create_secure_task(
                "Execute high-frequency trading",
                "analyst-001",  # Wrong agent for this task
                required_role="TradingExecutor"  # Requires TradingExecutor role
            )
        except AuthenticationError as e:
            print(f"❌ Task creation failed (expected): {e}")
        
    except Exception as e:
        print(f"❌ Task creation error: {e}")
    
    print("\n3️⃣ Secure Communication")
    print("-" * 30)
    
    # Simulate secure agent communication
    market_data = "TSLA: $245.67 (+2.3%), AAPL: $189.25 (+1.1%), GOOGL: $142.18 (+0.8%)"
    
    # Analyst analyzes data
    analysis = analyst.analyze_market_data(market_data)
    print(f"📊 {analysis}")
    
    # Verify communication between analyst and risk advisor
    try:
        is_verified = crew_integration.verify_agent_communication(
            "analyst-001",
            "risk-advisor-001", 
            analysis
        )
        print(f"✅ Communication verified: {is_verified}")
    except Exception as e:
        print(f"❌ Communication verification failed: {e}")
    
    # Risk advisor assesses the analysis
    risk_assessment = risk_advisor.assess_risk(analysis, caller_token=analyst_token)
    print(f"⚠️  {risk_assessment}")
    
    # Verify communication between risk advisor and trader
    try:
        is_verified = crew_integration.verify_agent_communication(
            "risk-advisor-001",
            "trader-001",
            risk_assessment
        )
        print(f"✅ Communication verified: {is_verified}")
    except Exception as e:
        print(f"❌ Communication verification failed: {e}")
    
    # Trader executes based on risk assessment
    if "MODERATE" in risk_assessment:
        trade_execution = trader.execute_trade(
            "Buy 100 shares TSLA at market price",
            caller_token=risk_token
        )
        print(f"💰 {trade_execution}")
    
    print("\n4️⃣ Message Signing & Verification")
    print("-" * 30)
    
    # Demonstrate message signing
    sensitive_message = "Execute large trade: Buy 10,000 shares TSLA"
    
    # Sign message with trader token
    signed_message = vault.sign_message(sensitive_message, trader_token)
    print(f"🔒 Message signed by trader: {signed_message['message_id']}")
    
    # Verify message authenticity
    is_authentic = vault.verify_message(signed_message, trader_token)
    print(f"✅ Message authenticity verified: {is_authentic}")
    
    # Try to tamper with message
    tampered_message = signed_message.copy()
    tampered_message['content'] = "Execute small trade: Buy 10 shares TSLA"
    
    is_tampered_authentic = vault.verify_message(tampered_message, trader_token)
    print(f"❌ Tampered message authenticity: {is_tampered_authentic}")
    
    print("\n5️⃣ Token Management")
    print("-" * 30)
    
    # Verify all tokens are still valid
    for agent_id in ["analyst-001", "risk-advisor-001", "trader-001"]:
        token = crew_integration.get_agent_token(agent_id)
        is_valid, info = vault.verify(token)
        print(f"✅ {agent_id} token valid: {is_valid} ({info['role'] if info else 'N/A'})")
    
    # Rotate a token for security
    print("\n🔄 Rotating trader token...")
    old_trader_token = trader_token
    new_trader_token = vault.rotate_token(old_trader_token)
    crew_integration.agent_tokens["trader-001"] = new_trader_token
    
    # Verify old token is invalid
    is_old_valid, _ = vault.verify(old_trader_token)
    is_new_valid, _ = vault.verify(new_trader_token)
    print(f"❌ Old token valid: {is_old_valid}")
    print(f"✅ New token valid: {is_new_valid}")
    
    print("\n6️⃣ Vault Status")
    print("-" * 30)
    
    # Get vault status
    status = vault.get_status()
    print(f"📊 Vault Status:")
    print(f"   - Total agents: {status['total_agents']}")
    print(f"   - Active agents: {status['active_agents']}")
    print(f"   - Active tokens: {status['active_tokens']}")
    print(f"   - Audit events: {status['audit_events']}")
    
    print("\n🎉 Demo completed successfully!")
    print("=" * 50)


if __name__ == "__main__":
    main() 