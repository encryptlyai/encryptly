"""
Encryptly SDK - API Key Usage Examples
======================================

This example shows how to use Encryptly with different API key configurations.
"""

import os
from encryptly import Encryptly

def development_usage():
    """Example: Development usage with auto-generated keys"""
    print("🛠️  Development Mode (Auto-Generated Keys)")
    print("=" * 50)
   
    # No API key needed - generates automatically
    vault = Encryptly()
    
    # Register some agents
    token1 = vault.register("dev-agent-1", "TestAgent", "DevAgent")
    token2 = vault.register("dev-agent-2", "TestAgent", "DevAgent")
    
    print(f"✅ Agent 1 token: {token1[:20]}...")
    print(f"✅ Agent 2 token: {token2[:20]}...")
    
    # Verify tokens
    is_valid, info = vault.verify(token1)
    print(f"✅ Token 1 valid: {is_valid}")
    
    print("⚠️  Note: These tokens will be invalid if you restart the app!")
    print()

def production_usage():
    """Example: Production usage with user-provided keys"""
    print("🏭 Production Mode (User-Provided Keys)")
    print("=" * 50)
    
    # User provides their own secret key
    # In real usage, this would come from environment variables
    user_secret_key = "your-super-secret-key-here-32-chars"
    
    vault = Encryptly(secret_key=user_secret_key)
    
    # Register agents
    token1 = vault.register("prod-agent-1", "DataAnalyst", "ProdAgent")
    token2 = vault.register("prod-agent-2", "TradingBot", "ProdAgent")
    
    print(f"✅ Agent 1 token: {token1[:20]}...")
    print(f"✅ Agent 2 token: {token2[:20]}...")
    
    # Verify tokens
    is_valid, info = vault.verify(token1)
    print(f"✅ Token 1 valid: {is_valid}")
    
    print("✅ These tokens will remain valid across app restarts!")
    print()

def environment_variable_usage():
    """Example: Using environment variables for API keys (recommended)"""
    print("🌍 Environment Variable Usage (Recommended)")
    print("=" * 50)
    
    # Set environment variable: export ENCRYPTLY_SECRET_KEY="your-key-here"
    secret_key = os.getenv('ENCRYPTLY_SECRET_KEY')
    
    if not secret_key:
        print("❌ No ENCRYPTLY_SECRET_KEY found in environment")
        print("💡 Set it with: export ENCRYPTLY_SECRET_KEY='your-secret-key-here'")
        return
    
    vault = Encryptly(secret_key=secret_key)
    
    # Register agents
    token = vault.register("env-agent", "SecurityBot", "EnvAgent")
    
    print(f"✅ Agent token: {token[:20]}...")
    
    # Verify token
    is_valid, info = vault.verify(token)
    print(f"✅ Token valid: {is_valid}")
    
    print("✅ Secret key securely loaded from environment!")
    print()

def future_api_key_system():
    """Example: What a future API key system might look like"""
    print("🔮 Future API Key System (Coming Soon)")
    print("=" * 50)
    
    # This is what we might add in the future
    print("# What users would do:")
    print("# 1. Sign up at https://dashboard.encryptly.com")
    print("# 2. Get API key: enc_1234567890abcdef")
    print("# 3. Use in their code:")
    print()
    
    print("from encryptly import Encryptly")
    print()
    print("vault = Encryptly(api_key='enc_1234567890abcdef')")
    print("token = vault.register('my-agent', 'DataAnalyst', 'MyAgent')")
    print()
    
    print("# Features this would enable:")
    print("# ✅ Usage tracking and billing")
    print("# ✅ Rate limiting per user")
    print("# ✅ Team management")
    print("# ✅ Advanced security features")
    print("# ✅ Cloud-based agent registry")
    print()

def main():
    """Run all examples"""
    print("🔑 Encryptly API Key Examples")
    print("=" * 60)
    print()
    
    development_usage()
    production_usage()
    environment_variable_usage()
    future_api_key_system()
    
    print("📋 Summary:")
    print("- Development: Use auto-generated keys (no setup needed)")
    print("- Production: Use your own secret key (secure and persistent)")
    print("- Best Practice: Load secret key from environment variables")
    print("- Future: Managed API keys with dashboard and billing")

if __name__ == "__main__":
    main() 