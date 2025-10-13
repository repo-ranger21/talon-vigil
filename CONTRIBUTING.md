# Contributing to TalonVigil

Thank you for your interest in contributing to TalonVigil! This document provides guidelines and instructions for contributing to the project.

## 🌟 Ways to Contribute

There are many ways to contribute to TalonVigil:

- 🐛 **Report bugs** and issues
- 💡 **Suggest new features** or enhancements
- 📝 **Improve documentation**
- 🔧 **Submit bug fixes**
- ✨ **Develop new features**
- 🧪 **Write tests** to improve coverage
- 🎨 **Enhance UI/UX**
- 🔍 **Review pull requests**

## 📋 Getting Started

### Prerequisites

Before contributing, make sure you have:

1. A GitHub account
2. Git installed locally
3. Python 3.9+ and Node.js 16+ installed
4. PostgreSQL and Redis running locally (for testing)
5. Familiarity with Flask, React, and basic cybersecurity concepts

### Setting Up Your Development Environment

1. **Fork the repository** on GitHub

2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/talon-vigil.git
   cd talon-vigil
   ```

3. **Add the upstream repository**:
   ```bash
   git remote add upstream https://github.com/repo-ranger21/talon-vigil.git
   ```

4. **Install dependencies**:
   ```bash
   # Backend dependencies
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   
   # Frontend dependencies
   npm install
   ```

5. **Set up your environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your local configuration
   ```

6. **Initialize the database**:
   ```bash
   flask db upgrade
   ```

## 🔄 Contribution Workflow

### 1. Create a Branch

Always create a new branch for your work:

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

Branch naming conventions:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
- `test/` - Test additions or modifications

### 2. Make Your Changes

- Write clear, concise code that follows the project's style
- Add comments for complex logic
- Update documentation as needed
- Ensure backward compatibility when possible

### 3. Test Your Changes

Before submitting, ensure:

```bash
# Run backend tests
pytest

# Run linting
flake8 .
black --check .

# Run frontend tests
npm test

# Run security checks (if applicable)
python test_security.py
```

### 4. Commit Your Changes

Write clear, descriptive commit messages:

```bash
git add .
git commit -m "Add feature: detailed description of changes"
```

Good commit message examples:
- ✅ `Add JWT token refresh endpoint to authentication system`
- ✅ `Fix IOC enrichment failing for domain types`
- ✅ `Update README with installation prerequisites`
- ❌ `Fixed stuff`
- ❌ `Updates`

### 5. Push to Your Fork

```bash
git push origin feature/your-feature-name
```

### 6. Submit a Pull Request

1. Go to the [TalonVigil repository](https://github.com/repo-ranger21/talon-vigil)
2. Click "New Pull Request"
3. Select your fork and branch
4. Fill out the PR template with:
   - Clear description of changes
   - Related issue numbers (if applicable)
   - Screenshots (for UI changes)
   - Testing performed
   - Checklist completion

## 📝 Coding Standards

### Python (Backend)

- Follow [PEP 8](https://pep8.org/) style guide
- Use type hints where appropriate
- Maximum line length: 88 characters (Black formatter)
- Use docstrings for classes and functions
- Prefer f-strings for string formatting

Example:
```python
from typing import List, Optional

def get_user_playbooks(user_id: int, limit: Optional[int] = None) -> List[Playbook]:
    """
    Retrieve playbooks for a specific user.
    
    Args:
        user_id: The ID of the user
        limit: Maximum number of playbooks to return
        
    Returns:
        List of Playbook objects
    """
    query = Playbook.query.filter_by(user_id=user_id)
    if limit:
        query = query.limit(limit)
    return query.all()
```

### JavaScript/React (Frontend)

- Use ES6+ syntax
- Follow [Airbnb JavaScript Style Guide](https://github.com/airbnb/javascript)
- Use functional components with hooks
- Use meaningful variable and function names
- Add PropTypes or TypeScript types

Example:
```javascript
import React, { useState, useEffect } from 'react';

const ThreatDashboard = ({ userId }) => {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchThreats(userId);
  }, [userId]);

  const fetchThreats = async (id) => {
    // Implementation
  };

  return (
    <div className="threat-dashboard">
      {/* Component JSX */}
    </div>
  );
};

export default ThreatDashboard;
```

### SQL/Database

- Use migrations for schema changes
- Never commit sensitive data
- Add appropriate indexes for query performance
- Write efficient queries to minimize database load

### Security

- Never commit secrets, API keys, or credentials
- Sanitize all user inputs
- Use parameterized queries to prevent SQL injection
- Implement proper authentication and authorization checks
- Follow OWASP security best practices

## 🧪 Testing Guidelines

### Writing Tests

- Write tests for new features and bug fixes
- Aim for high code coverage (>80%)
- Test both success and failure cases
- Use descriptive test names

Example:
```python
def test_playbook_creation_with_valid_data():
    """Test that playbook is created successfully with valid input."""
    playbook = create_playbook(
        name="Test Playbook",
        user_id=1,
        ioc_id=100
    )
    assert playbook.id is not None
    assert playbook.name == "Test Playbook"

def test_playbook_creation_with_invalid_user():
    """Test that playbook creation fails with non-existent user."""
    with pytest.raises(ValueError):
        create_playbook(name="Test", user_id=9999, ioc_id=100)
```

### Running Tests

```bash
# Run all backend tests
pytest

# Run specific test file
pytest test_playbook_engine.py

# Run with coverage
pytest --cov=. --cov-report=html

# Run frontend tests
npm test

# Run specific test
npm test -- ThreatDashboard.test.js
```

## 📚 Documentation

### Code Documentation

- Add docstrings to all public functions and classes
- Include parameter descriptions and return values
- Add inline comments for complex logic
- Update API documentation for new endpoints

### README and Guides

- Keep README.md up to date
- Update relevant documentation in `/docs`
- Add screenshots for UI changes
- Include examples and use cases

## 🔍 Code Review Process

All contributions go through code review:

1. **Automated Checks**: CI/CD pipeline runs tests and linting
2. **Peer Review**: At least one maintainer reviews your code
3. **Feedback**: Address review comments and suggestions
4. **Approval**: Once approved, your PR will be merged

### What Reviewers Look For

- ✅ Code quality and readability
- ✅ Test coverage and passing tests
- ✅ Documentation completeness
- ✅ Security considerations
- ✅ Performance implications
- ✅ Adherence to coding standards

## 🐛 Reporting Bugs

When reporting bugs, please include:

1. **Clear title** describing the issue
2. **Steps to reproduce** the problem
3. **Expected behavior** vs actual behavior
4. **Environment details** (OS, Python version, browser, etc.)
5. **Screenshots or logs** if applicable
6. **Possible solution** (if you have one)

Use the [bug report template](https://github.com/repo-ranger21/talon-vigil/issues/new?template=bug_report.md).

## 💡 Suggesting Features

For feature requests, provide:

1. **Clear description** of the feature
2. **Use case** - why is it needed?
3. **Proposed solution** or implementation approach
4. **Alternatives considered**
5. **Impact assessment** on existing functionality

Use the [feature request template](https://github.com/repo-ranger21/talon-vigil/issues/new?template=feature_request.md).

## 🔐 Security Vulnerabilities

If you discover a security vulnerability:

1. **DO NOT** open a public issue
2. Email security@talonvigil.com with details
3. Include steps to reproduce
4. Allow time for a fix before public disclosure

See [SECURITY.md](SECURITY.md) for our security policy.

## 📜 Code of Conduct

### Our Standards

We are committed to providing a welcoming and inclusive environment:

- ✅ Be respectful and considerate
- ✅ Welcome diverse perspectives
- ✅ Focus on what's best for the community
- ✅ Show empathy toward others
- ✅ Accept constructive criticism gracefully

### Unacceptable Behavior

- ❌ Harassment or discrimination
- ❌ Trolling or insulting comments
- ❌ Personal or political attacks
- ❌ Publishing others' private information
- ❌ Any unethical or illegal activity

## 🏆 Recognition

We value all contributions! Contributors will be:

- Listed in release notes for significant contributions
- Recognized in the project's acknowledgments
- Eligible for contributor badges and achievements

## 📞 Getting Help

Need help with your contribution?

- 💬 Join our [Discord community](#)
- 📧 Email contributors@talonvigil.com
- 📖 Check the [documentation](./docs)
- 💡 Ask in [GitHub Discussions](#)

## 📄 License

By contributing to TalonVigil, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).

---

**Thank you for contributing to TalonVigil and helping make cybersecurity more accessible and effective for everyone!** 🛡️
