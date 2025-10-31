#!/usr/bin/env python3
"""
Test script for LDAP directory service module.

Tests directory operations: add, search, modify, delete, authenticate.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldap.directory import DirectoryService
from ldap.user_manager import UserManager


def test_directory_initialization():
    """Test directory initialization."""
    print("=" * 60)
    print("Test 1: Directory Initialization")
    print("=" * 60)
    
    directory = DirectoryService()
    
    # Check base structure
    entries = directory.list_all_entries()
    assert len(entries) >= 3, "Should have base structure entries"
    
    print("✓ Directory initialized successfully")
    print(f"✓ Base DN: {directory.base_dn}")
    print(f"✓ Initial entries: {len(entries)}")
    print()


def test_add_user():
    """Test adding users."""
    print("=" * 60)
    print("Test 2: Add User")
    print("=" * 60)
    
    directory = DirectoryService()
    user_mgr = UserManager(directory)
    
    # Add user
    dn = user_mgr.create_user(
        username="john.doe",
        email="john@example.com",
        password="secret123",
        full_name="John Doe"
    )
    
    assert dn is not None, "Should return DN"
    print(f"✓ User added successfully")
    print(f"✓ DN: {dn}")
    
    # Try to add duplicate (should fail)
    try:
        user_mgr.create_user(
            username="john.doe",
            email="john2@example.com",
            password="password"
        )
        assert False, "Should not allow duplicate usernames"
    except ValueError:
        print("✓ Duplicate user prevented")
    print()


def test_search():
    """Test directory search."""
    print("=" * 60)
    print("Test 3: Directory Search")
    print("=" * 60)
    
    directory = DirectoryService()
    user_mgr = UserManager(directory)
    
    # Add multiple users
    user_mgr.create_user("alice", "alice@example.com", "pass1")
    user_mgr.create_user("bob", "bob@example.com", "pass2")
    
    # Search by CN
    result = directory.search_by_cn("alice", ou="Users")
    assert result is not None, "Should find user"
    assert result["cn"][0] == "alice", "Should match CN"
    print("✓ Search by CN successful")
    
    # Search with filter
    results = directory.search(
        base_dn=f"ou=Users,{directory.base_dn}",
        filter_attrs={"mail": "alice@example.com"}
    )
    assert len(results) == 1, "Should find one result"
    print("✓ Search with filter successful")
    
    # List all users
    users = user_mgr.list_users()
    assert len(users) >= 2, "Should list users"
    print(f"✓ Listed {len(users)} users")
    print()


def test_modify():
    """Test modifying entries."""
    print("=" * 60)
    print("Test 4: Modify Entry")
    print("=" * 60)
    
    directory = DirectoryService()
    user_mgr = UserManager(directory)
    
    # Add user
    user_mgr.create_user("charlie", "charlie@example.com", "pass")
    
    # Modify user
    user_mgr.update_user("charlie", displayName="Charlie Brown")
    
    # Verify modification
    user_info = user_mgr.get_user_info("charlie")
    assert user_info["displayName"][0] == "Charlie Brown", "Modification should work"
    print("✓ Entry modified successfully")
    print()


def test_authenticate():
    """Test authentication."""
    print("=" * 60)
    print("Test 5: Authentication")
    print("=" * 60)
    
    directory = DirectoryService()
    user_mgr = UserManager(directory)
    
    # Add user
    user_mgr.create_user("dave", "dave@example.com", "mypassword")
    
    # Authenticate
    user_info = user_mgr.get_user_info("dave")
    dn = user_info["dn"]
    
    is_valid = directory.authenticate(dn, "mypassword")
    assert is_valid, "Should authenticate with correct password"
    print("✓ Authentication with correct password successful")
    
    is_invalid = directory.authenticate(dn, "wrongpassword")
    assert not is_invalid, "Should not authenticate with wrong password"
    print("✓ Authentication with wrong password rejected")
    print()


def test_certificate_entry():
    """Test certificate entry management."""
    print("=" * 60)
    print("Test 6: Certificate Entry")
    print("=" * 60)
    
    directory = DirectoryService()
    
    # Add certificate entry
    cert_data = b"fake_certificate_data"
    dn = directory.add_certificate_entry(
        "server.example.com",
        cert_data,
        {"description": "Test server certificate"}
    )
    
    assert dn is not None, "Should return DN"
    print(f"✓ Certificate entry added: {dn}")
    
    # Retrieve certificate
    retrieved_cert = directory.get_certificate("server.example.com")
    assert retrieved_cert == cert_data, "Should retrieve same certificate"
    print("✓ Certificate retrieved successfully")
    print()


def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("LDAP Directory Service Module Tests")
    print("=" * 60 + "\n")
    
    try:
        test_directory_initialization()
        test_add_user()
        test_search()
        test_modify()
        test_authenticate()
        test_certificate_entry()
        
        print("=" * 60)
        print("All tests passed! ✓")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

