"""
Encryptly SDK - Command Line Interface
"""

import argparse
import sys
from typing import Optional

from .vault import Encryptly
from .exceptions import EncryptlyError


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Encryptly SDK - Lightweight Authentication for AI Agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  encryptly version                    # Show version
  encryptly demo                       # Run demonstration
  encryptly register my-agent Analyst  # Register agent
  encryptly verify <token>             # Verify token
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Version command
    version_parser = subparsers.add_parser("version", help="Show version information")
    
    # Demo command
    demo_parser = subparsers.add_parser("demo", help="Run AgentVault demonstration")
    
    # Register command
    register_parser = subparsers.add_parser("register", help="Register a new agent")
    register_parser.add_argument("agent_id", help="Unique agent identifier")
    register_parser.add_argument("role", help="Agent role (e.g., DataAnalyst)")
    register_parser.add_argument("--class", dest="agent_class", default="CLIAgent",
                                 help="Agent class name (default: CLIAgent)")
    register_parser.add_argument("--kid", dest="kid", help="Key ID for key rotation")
    
    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify an authentication token")
    verify_parser.add_argument("token", help="JWT token to verify")
    
    # Status command
    status_parser = subparsers.add_parser("status", help="Show vault status")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        if args.command == "version":
            return cmd_version()
        elif args.command == "demo":
            return cmd_demo()
        elif args.command == "register":
            return cmd_register(args.agent_id, args.role, args.agent_class, args.kid)
        elif args.command == "verify":
            return cmd_verify(args.token)
        elif args.command == "status":
            return cmd_status()
        else:
            print(f"Unknown command: {args.command}")
            return 1
    except EncryptlyError as e:
        print(f"Error: {e}")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


def cmd_version() -> int:
    """Show version information."""
    from . import __version__
    print(f"Encryptly SDK v{__version__}")
    print("Lightweight Authentication for AI Agents")
    return 0


def cmd_demo() -> int:
    """Run a simple demonstration."""
    print("Encryptly SDK Demo")
    print("=" * 30)
    
    # Initialize vault
    vault = Encryptly()
    
    # Register some agents
    print("\n1. Registering agents...")
    analyst_token = vault.register("demo-analyst", "DataAnalyst", "DemoAnalyst")
    trader_token = vault.register("demo-trader", "TradeExecutor", "DemoTrader")
    
    print(f"Analyst token: {analyst_token[:20]}...")
    print(f"Trader token: {trader_token[:20]}...")
    
    # Verify tokens
    print("\n2. Verifying tokens...")
    is_valid, info = vault.verify(analyst_token)
    print(f"Analyst verification: {is_valid} ({info['role'] if info else 'N/A'})")
    
    is_valid, info = vault.verify(trader_token)
    print(f"Trader verification: {is_valid} ({info['role'] if info else 'N/A'})")
    
    # Sign and verify message
    print("\n3. Message signing...")
    message = vault.sign_message("Demo message from analyst", analyst_token)
    print(f"Message signed: {message['message_id']}")
    
    is_authentic = vault.verify_message(message, analyst_token)
    print(f"Message verification: {is_authentic}")
    
    # Show status
    print("\n4. Vault status:")
    status = vault.get_status()
    print(f"   - Active agents: {status['active_agents']}")
    print(f"   - Active tokens: {status['active_tokens']}")
    print(f"   - Audit events: {status['audit_events']}")
    
    print("\nDemo completed successfully!")
    return 0


def cmd_register(agent_id: str, role: str, agent_class: str, kid: Optional[str] = None) -> int:
    """Register a new agent."""
    vault = Encryptly()
    
    try:
        token = vault.register(agent_id, role, agent_class, kid)
        print(f"Agent registered successfully!")
        print(f"Agent ID: {agent_id}")
        print(f"Role: {role}")
        if kid:
            print(f"Key ID: {kid}")
        print(f"Token: {token}")
        print(f"\nSave this token securely - it's needed for authentication.")
        return 0
    except EncryptlyError as e:
        print(f"Registration failed: {e}")
        return 1


def cmd_verify(token: str) -> int:
    """Verify an authentication token."""
    vault = Encryptly()
    
    is_valid, info = vault.verify(token)
    
    if is_valid:
        print("Token is valid!")
        print(f"Agent ID: {info['agent_id']}")
        print(f"Role: {info['role']}")
        print(f"Class: {info['class']}")
        print(f"Token ID: {info['token_id']}")
        return 0
    else:
        print("Token is invalid or expired")
        return 1


def cmd_status() -> int:
    """Show vault status."""
    vault = Encryptly()
    
    status = vault.get_status()
    
    print("Encryptly Status")
    print("=" * 20)
    print(f"Total agents: {status['total_agents']}")
    print(f"Active agents: {status['active_agents']}")
    print(f"Total tokens: {status['total_tokens']}")
    print(f"Active tokens: {status['active_tokens']}")
    print(f"Audit events: {status['audit_events']}")
    print(f"Version: {status['version']}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 