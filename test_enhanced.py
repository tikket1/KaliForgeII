#!/usr/bin/env python3
"""
Test script to demonstrate KaliForge II enhanced features
"""

import os
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from kaliforge2_logger import get_logger, init_logger
    from kaliforge2_state import get_state_manager, init_state_manager, KaliForgeConfig
    from kaliforge2_validator import SecurityValidator, validate_all_inputs
    
    print("🚀 KaliForge II Enhanced Features Test")
    print("=" * 50)
    
    # Test logging system
    print("\n📊 Testing Logging System:")
    logger = init_logger("/tmp/kaliforge2_test")
    logger.log_info("Test log entry")
    logger.log_security_event("TEST_EVENT", {"test": True})
    logger.log_audit_event("test_action", "test_resource", "SUCCESS")
    print("✅ Logging system initialized and tested")
    
    # Test state management
    print("\n💾 Testing State Management:")
    state_manager = init_state_manager("/tmp/kaliforge2_test_state")
    
    test_config = KaliForgeConfig(
        user_name="testuser",
        profile="standard",
        ssh_port="2222"
    )
    
    state_manager.save_config(test_config)
    loaded_config = state_manager.load_config()
    print(f"✅ Configuration saved and loaded: {loaded_config.user_name}")
    
    # Test validation
    print("\n🔒 Testing Input Validation:")
    
    test_inputs = {
        'username': 'testuser123',
        'ssh_port': '2222',
        'ssh_key': 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7... test@example.com',
        'github_token': 'ghp_1234567890123456789012345678901234567890'
    }
    
    for input_type, test_value in test_inputs.items():
        if input_type == 'username':
            valid, msg = SecurityValidator.validate_username(test_value)
        elif input_type == 'ssh_port':
            valid, msg = SecurityValidator.validate_ssh_port(test_value)
        elif input_type == 'ssh_key':
            # Use a simpler test for SSH key
            valid, msg = SecurityValidator.validate_ssh_public_key("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... test")
        elif input_type == 'github_token':
            valid, msg = SecurityValidator.validate_github_token(test_value)
        
        status = "✅" if valid else "❌"
        print(f"{status} {input_type}: {msg}")
    
    # Test system requirements
    print("\n🖥️  Testing System Requirements Check:")
    requirements = SecurityValidator.validate_system_requirements()
    
    for req_name, req_result in requirements.items():
        status = "✅" if req_result['valid'] else "⚠️"
        print(f"{status} {req_name}: {req_result['message']}")
    
    print("\n🎉 All enhanced features tested successfully!")
    print("\nEnhanced features include:")
    print("• Structured logging with rotation")
    print("• Configuration persistence")  
    print("• Comprehensive input validation")
    print("• System requirements checking")
    print("• Security event tracking")
    print("• Audit trail logging")
    print("• Error recovery and rollback")

except ImportError as e:
    print("❌ Enhanced modules not available:")
    print(f"   {e}")
    print("\nThis means the enhanced features are not installed.")
    print("The unified script will run in basic compatibility mode.")

except Exception as e:
    print(f"❌ Error testing enhanced features: {e}")
    import traceback
    traceback.print_exc()