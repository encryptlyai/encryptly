"""
AgentVault SDK - Framework Integrations
"""

from typing import Any, Dict, Optional, Callable
from .exceptions import AuthenticationError, VerificationError


class CrewAIIntegration:
    """
    Integration helper for CrewAI agents.
    
    Makes it easy to add authentication to CrewAI workflows.
    """
    
    def __init__(self, vault_instance: Any):
        """
        Initialize CrewAI integration.
        
        Args:
            vault_instance: The Encryptly instance to use
        """
        self.vault = vault_instance
        self.agent_tokens: Dict[str, str] = {}
    
    def secure_agent(self, agent_id: str, role: str, agent_class: str = "CrewAIAgent") -> str:
        """
        Register and secure a CrewAI agent.
        
        Args:
            agent_id: Unique identifier for the agent
            role: Role of the agent (e.g., "DataAnalyst")
            agent_class: Class name for verification
            
        Returns:
            str: Authentication token for the agent
        """
        token = self.vault.register(agent_id, role, agent_class)
        self.agent_tokens[agent_id] = token
        return token
    
    def get_agent_token(self, agent_id: str) -> Optional[str]:
        """Get the authentication token for a specific agent."""
        return self.agent_tokens.get(agent_id)
    
    def verify_agent_communication(self, sender_id: str, receiver_id: str, message: str) -> bool:
        """
        Verify secure communication between two agents.
        
        Args:
            sender_id: ID of the sending agent
            receiver_id: ID of the receiving agent
            message: Message content
            
        Returns:
            bool: True if communication is verified
        """
        # Get sender token
        sender_token = self.agent_tokens.get(sender_id)
        if not sender_token:
            raise AuthenticationError(f"No token found for sender: {sender_id}")
        
        # Verify sender token
        is_valid, sender_info = self.vault.verify(sender_token)
        if not is_valid:
            raise AuthenticationError(f"Invalid token for sender: {sender_id}")
        
        # Check if receiver is registered
        receiver_token = self.agent_tokens.get(receiver_id)
        if not receiver_token:
            raise AuthenticationError(f"No token found for receiver: {receiver_id}")
        
        # Verify receiver token
        is_valid, receiver_info = self.vault.verify(receiver_token)
        if not is_valid:
            raise AuthenticationError(f"Invalid token for receiver: {receiver_id}")
        
        # Sign and verify message
        signed_message = self.vault.sign_message(message, sender_token)
        is_authentic = self.vault.verify_message(signed_message, sender_token)
        
        return is_authentic
    
    def create_secure_task(self, task_description: str, agent_id: str, required_role: str = None) -> Dict[str, Any]:
        """
        Create a secure task that can only be executed by authorized agents.
        
        Args:
            task_description: Description of the task
            agent_id: ID of the agent assigned to the task
            required_role: Optional role requirement for the task
            
        Returns:
            Dict containing secure task information
        """
        # Get agent token
        agent_token = self.agent_tokens.get(agent_id)
        if not agent_token:
            raise AuthenticationError(f"No token found for agent: {agent_id}")
       
        # Verify agent
        is_valid, agent_info = self.vault.verify(agent_token)
        if not is_valid:
            raise AuthenticationError(f"Invalid token for agent: {agent_id}")
        
        # Check role requirement
        if required_role and agent_info["role"] != required_role:
            raise AuthenticationError(f"Agent {agent_id} role '{agent_info['role']}' does not match required role '{required_role}'")
        
        return {
            "task_id": f"task_{agent_id}_{hash(task_description) % 10000}",
            "description": task_description,
            "assigned_agent": agent_id,
            "agent_role": agent_info["role"],
            "token": agent_token,
            "created_at": "2024-01-01T00:00:00.000Z"
        }


class LangChainIntegration:
    """
    Integration helper for LangChain agents.
    
    Makes it easy to add authentication to LangChain workflows.
    """
    
    def __init__(self, vault_instance: Any):
        """
        Initialize LangChain integration.
        
        Args:
            vault_instance: The Encryptly instance to use
        """
        self.vault = vault_instance
        self.agent_tokens: Dict[str, str] = {}
    
    def secure_agent(self, agent_id: str, role: str, agent_class: str = "LangChainAgent") -> str:
        """
        Register and secure a LangChain agent.
        
        Args:
            agent_id: Unique identifier for the agent
            role: Role of the agent (e.g., "ChatAgent")
            agent_class: Class name for verification
            
        Returns:
            str: Authentication token for the agent
        """
        token = self.vault.register(agent_id, role, agent_class)
        self.agent_tokens[agent_id] = token
        return token
    
    def get_agent_token(self, agent_id: str) -> Optional[str]:
        """Get the authentication token for a specific agent."""
        return self.agent_tokens.get(agent_id)
    
    def secure_chain_execution(self, chain_id: str, executor_id: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Secure execution of a LangChain chain.
        
        Args:
            chain_id: ID of the chain to execute
            executor_id: ID of the agent executing the chain
            input_data: Input data for the chain
            
        Returns:
            Dict containing execution result and security info
        """
        # Get executor token
        executor_token = self.agent_tokens.get(executor_id)
        if not executor_token:
            raise AuthenticationError(f"No token found for executor: {executor_id}")
        
        # Verify executor
        is_valid, executor_info = self.vault.verify(executor_token)
        if not is_valid:
            raise AuthenticationError(f"Invalid token for executor: {executor_id}")
        
        # Create secure execution context
        execution_context = {
            "chain_id": chain_id,
            "executor_id": executor_id,
            "executor_role": executor_info["role"],
            "input_data": input_data,
            "token": executor_token,
            "security_verified": True
        }
        
        return execution_context
    
    def create_secure_callback(self, callback_name: str, agent_id: str) -> Callable:
        """
        Create a secure callback that verifies agent identity before execution.
        
        Args:
            callback_name: Name of the callback
            agent_id: ID of the agent that should execute the callback
            
        Returns:
            Callable: Secure callback function
        """
        def secure_callback(*args, **kwargs):
            # Get agent token
            agent_token = self.agent_tokens.get(agent_id)
            if not agent_token:
                raise AuthenticationError(f"No token found for agent: {agent_id}")
            
            # Verify agent
            is_valid, agent_info = self.vault.verify(agent_token)
            if not is_valid:
                raise AuthenticationError(f"Invalid token for agent: {agent_id}")
            
            # Add security context to kwargs
            kwargs["_security_context"] = {
                "agent_id": agent_id,
                "agent_role": agent_info["role"],
                "callback_name": callback_name,
                "verified": True
            }
            
            # Execute the actual callback (would be provided by user)
            return {"status": "callback_executed", "agent_id": agent_id, "args": args, "kwargs": kwargs}
        
        return secure_callback


class BaseIntegration:
    """
    Base class for creating custom framework integrations.
    
    Inherit from this class to create integrations for other AI frameworks.
    """
    
    def __init__(self, vault_instance: Any, framework_name: str):
        """
        Initialize base integration.
        
        Args:
            vault_instance: The Encryptly instance to use
            framework_name: Name of the framework being integrated
        """
        self.vault = vault_instance
        self.framework_name = framework_name
        self.agent_tokens: Dict[str, str] = {}
    
    def secure_agent(self, agent_id: str, role: str, agent_class: str = None) -> str:
        """
        Register and secure an agent.
        
        Args:
            agent_id: Unique identifier for the agent
            role: Role of the agent
            agent_class: Class name for verification
            
        Returns:
            str: Authentication token for the agent
        """
        agent_class = agent_class or f"{self.framework_name}Agent"
        token = self.vault.register(agent_id, role, agent_class)
        self.agent_tokens[agent_id] = token
        return token
    
    def verify_agent(self, agent_id: str) -> bool:
        """
        Verify an agent's authentication.
        
        Args:
            agent_id: ID of the agent to verify
            
        Returns:
            bool: True if agent is verified
        """
        token = self.agent_tokens.get(agent_id)
        if not token:
            return False
        
        is_valid, _ = self.vault.verify(token)
        return is_valid
    
    def get_agent_info(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a registered agent.
        
        Args:
            agent_id: ID of the agent
            
        Returns:
            Optional[Dict]: Agent information if found
        """
        token = self.agent_tokens.get(agent_id)
        if not token:
            return None
        
        is_valid, agent_info = self.vault.verify(token)
        return agent_info if is_valid else None 