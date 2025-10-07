# Contributing to Django SSO Authentication System

Welcome! This document explains how to contribute to this project safely and effectively.

---

## Philosophy

This project follows **The Bridge Safety System** - a systematic approach to building software that prevents catastrophic failures while enabling non-technical leadership.

**Core Principles:**
- **Safety over speed** - We catch issues before deployment
- **Multiple perspectives** - No single reviewer is enough
- **Functional testing** - Tests anyone can execute
- **Institutional memory** - We learn from every project
- **ADHD-friendly** - Work in 15-minute blocks with clear checkpoints

---

## Before You Start

### Required Reading
1. **README.md** - Project overview and setup
2. **claude.md** - PRIMARY source of project context, patterns, and standards
3. **RISK_ASSESSMENT_CALCULATOR.md** - Assess every change
4. **DEPLOYMENT_PROTOCOLS.md** - Deployment procedures by risk level

### Required Tools
- Python 3.11+
- Git
- Access to Google Cloud Console (for OAuth changes)
- Access to Render dashboard (for deployment)

### Recommended Tools
- Galactica (Universal Memory System) for context preservation
- Claude Code or similar AI assistant
- The Bridge (CTO command center) for strategic guidance

---

## Development Workflow

### Step 1: Assess Risk Level

**Before making ANY changes:**

```bash
# Use Risk Assessment Calculator
# Located at: RISK_ASSESSMENT_CALCULATOR.md

# Score your change:
# - Data Criticality (×3)
# - User Count (×2)  
# - Business Impact (×3)
# - Complexity (×1)
# - Integration Points (×2)

# Determine risk level:
# 0-20 = LOW RISK
# 21-40 = MEDIUM RISK
# 41-60 = HIGH RISK
# 61+ = EXTREME RISK
```

**Match your change to the appropriate protocol.**

---

### Step 2: Create a Branch

```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/bug-description

# Or for documentation
git checkout -b docs/what-you-are-documenting
```

**Branch naming:**
- `feature/` - New functionality
- `fix/` - Bug fixes
- `refactor/` - Code improvements without behavior change
- `docs/` - Documentation only
- `security/` - Security improvements
- `test/` - Test additions/improvements

---

### Step 3: Make Changes

#### Code Standards
- **Follow PEP 8** for Python code
- **Read claude.md first** before making changes
- **Use patterns documented in claude.md**
- **Write tests for all new functionality**
- **Update documentation** as you go

#### Security Requirements
- **Never commit secrets** - Use environment variables
- **Never hardcode credentials** - Use .env files
- **Follow OWASP guidelines** for web security
- **Validate all inputs** from users and external systems
- **Log security-relevant events** appropriately

#### Testing Requirements
- **70% minimum coverage** for general code
- **100% coverage required** for authentication code
- **Run tests before committing:**
  ```bash
  python manage.py test
  ```

---

### Step 4: Quality Gates (Based on Risk Level)

#### For LOW RISK Changes
- [ ] Code follows project standards
- [ ] Tests pass locally
- [ ] Documentation updated
- [ ] No secrets in code

#### For MEDIUM RISK Changes
**All LOW RISK requirements PLUS:**
- [ ] **Three-perspective review required:**
  - Security review
  - Data safety review
  - Business logic review
- [ ] Functional tests created (non-technical person can execute)
- [ ] Rollback plan documented
- [ ] Changes reviewed by independent reviewer

#### For HIGH RISK Changes
**All MEDIUM RISK requirements PLUS:**
- [ ] External technical review (if available)
- [ ] Comprehensive test coverage
- [ ] Load testing (if applicable)
- [ ] Security audit consideration
- [ ] Approval from The Bridge (project CTO)
- [ ] Rollback tested multiple times

---

### Step 5: Commit Your Changes

#### Commit Message Format
```
<type>: <short summary>

<detailed explanation if needed>

- Bullet points for multiple changes
- Reference issues: Fixes #123
- Note breaking changes: BREAKING: description
```

**Types:**
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation only
- `refactor:` - Code change without behavior change
- `test:` - Adding or updating tests
- `security:` - Security improvements
- `perf:` - Performance improvements

**Examples:**
```bash
git commit -m "feat: add token refresh mechanism

Implements automatic OAuth token refresh to prevent session timeouts.
- Checks token expiry before API calls
- Refreshes tokens transparently
- Logs refresh events for monitoring

Refs #42"
```

```bash
git commit -m "fix: resolve redirect URI mismatch

Google OAuth was failing due to trailing slash inconsistency.
Used google_redirect_uri() helper for consistency.

Fixes #38"
```

---

### Step 6: Create Pull Request

#### PR Checklist
- [ ] All tests passing
- [ ] Code follows project standards
- [ ] Documentation updated
- [ ] Risk assessment completed
- [ ] Quality gates appropriate to risk level
- [ ] No secrets or credentials in code
- [ ] CHANGELOG.md updated (if applicable)

#### PR Description Template
```markdown
## Description
Brief description of what this PR does.

## Risk Level
[ ] LOW RISK
[ ] MEDIUM RISK  
[ ] HIGH RISK
[ ] EXTREME RISK

## Risk Assessment Score: X/60

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that breaks existing functionality)
- [ ] Documentation update
- [ ] Security improvement
- [ ] Performance improvement

## Quality Gates Completed
- [ ] Three-perspective review (if MEDIUM+ risk)
- [ ] Functional tests created
- [ ] Security review passed
- [ ] Data safety review passed
- [ ] Business logic review passed

## Testing
Describe how you tested this change:
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed
- [ ] Edge cases tested

## Rollback Plan
How to undo this change if needed:
1. Step 1
2. Step 2

Rollback time estimate: X minutes

## Deployment Notes
Any special considerations for deployment:
- Environment variables needed
- Migration steps
- Configuration changes
- Monitoring to watch

## Screenshots (if applicable)
Add screenshots for UI changes.

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] All tests passing
- [ ] No console warnings/errors
- [ ] Ready for review
```

---

### Step 7: Code Review Process

#### For Contributors
- **Respond to feedback promptly**
- **Make requested changes**
- **Re-request review after changes**
- **Be open to suggestions**
- **Ask questions if unclear**

#### For Reviewers
- **Check against claude.md standards**
- **Verify risk assessment appropriate**
- **Confirm quality gates met**
- **Test the changes locally if possible**
- **Be constructive in feedback**

#### Approval Requirements
- **LOW RISK:** 1 approval
- **MEDIUM RISK:** 2 approvals (must include security perspective)
- **HIGH RISK:** 3 approvals (security + data safety + business logic) + The Bridge approval
- **EXTREME RISK:** External review required

---

### Step 8: Deployment

**Follow the deployment protocol matching your risk level:**
- See `DEPLOYMENT_PROTOCOLS.md` for detailed checklists
- LOW RISK: Basic deployment with monitoring
- MEDIUM RISK: 1-2 week parallel operation
- HIGH RISK: 1 month parallel operation with intensive monitoring

---

## Special Procedures

### Authentication Code Changes (Always HIGH RISK)

**Any change to authentication requires:**
1. Complete risk assessment (will score HIGH)
2. Three-perspective review with HIGH confidence
3. 100% test coverage
4. Security audit consideration
5. The Bridge approval
6. HIGH RISK deployment protocol
7. Multiple rollback tests

**Authentication includes:**
- Login/logout flows
- OAuth integration
- Session management
- Token handling
- Permission checks
- Access control

---

### Database Changes (MEDIUM to HIGH RISK)

**Any database changes require:**
1. Migration script tested locally
2. Backup plan before migration
3. Rollback migration script
4. Data validation after migration
5. Testing on copy of production data (if available)

**Database changes include:**
- Schema changes
- Data migrations
- Index changes
- Constraint modifications

---

### Environment Variable Changes (MEDIUM RISK)

**Any new environment variables require:**
1. Documentation in .env.example
2. Update to deployment documentation
3. Notification to deployment manager
4. Verification in all environments

---

### Security Vulnerability Fixes (HIGH RISK)

**If you discover a security issue:**
1. **DO NOT create public issue**
2. **Contact project maintainer privately**
3. **Provide details of vulnerability**
4. **Wait for guidance before submitting fix**
5. **Follow responsible disclosure practices**

---

## Working with AI Tools

### If Using Claude Code
1. **Always start by reading claude.md**
2. **Reference claude.md in your prompts**
3. **Follow patterns documented there**
4. **Update claude.md if you discover new patterns**

### If Using The Bridge (CTO Assistant)
1. **Use for strategic decisions and architecture**
2. **Request independent code review**
3. **Get risk assessment validation**
4. **Coordinate cross-AI tool work**

### Multi-Perspective Review with AI
- **Use different AI tools for each review perspective**
- **Security review:** One AI tool
- **Data safety:** Different AI tool
- **Business logic:** Third perspective
- **Prevents single-AI blind spots**

---

## Documentation Standards

### Code Comments
```python
# Good comments explain WHY, not WHAT
def refresh_token(token):
    """Refresh OAuth token before expiry.
    
    Google tokens expire after 1 hour. We refresh at 50 minutes
    to prevent race conditions during API calls.
    
    Args:
        token: Current OAuth token object
        
    Returns:
        Refreshed token object
        
    Raises:
        RefreshError: If refresh fails (token revoked, network error)
    """
    # Check if refresh needed (not what, but why we check)
    if token.expires_in < 600:  # 10 minute buffer for safety
        return oauth_client.refresh(token)
    return token
```

### README Updates
- Keep setup instructions current
- Document new features
- Update troubleshooting section
- Maintain changelog

### claude.md Updates
**REQUIRED for pattern changes:**
- New architectural patterns
- Security requirements changes
- Testing approach modifications
- Integration pattern updates

See `CLAUDE_MD_MAINTENANCE.md` for full update protocol.

---

## Post-Contribution

### After Your PR is Merged

1. **Delete your branch:**
   ```bash
   git branch -d feature/your-feature-name
   ```

2. **Update local main:**
   ```bash
   git checkout main
   git pull origin main
   ```

3. **Log to Galactica** (if you have access):
   ```bash
   memory remember "Contributed [feature/fix]: [brief description]" \
     --tags contribution,django,sso \
     --importance 6
   ```

### Post-Mortem (For Significant Changes)

Complete `POST_MORTEM_TEMPLATE.md` for:
- MEDIUM+ risk changes
- Significant refactors
- New features
- Bug fixes that revealed larger issues

**Purpose:** Build institutional knowledge about what works and what doesn't.

---

## Getting Help

### Questions About...

**Code/Implementation:**
- Check claude.md first
- Review existing patterns in codebase
- Ask in PR comments
- Contact project maintainer

**Risk Assessment:**
- Use RISK_ASSESSMENT_CALCULATOR.md
- Request review from The Bridge
- Ask for second opinion

**Deployment:**
- Check DEPLOYMENT_PROTOCOLS.md
- Review technical-handoff.md for current status
- Contact deployment manager

**Architecture Decisions:**
- Review Business Operations Context document
- Consult The Bridge
- Discuss in issue before implementing

### Where to Ask

- **GitHub Issues** - Bug reports, feature requests
- **PR Comments** - Code-specific questions
- **Direct Contact** - Security issues, urgent matters

---

## Recognition

We value all contributions:
- Code improvements
- Bug reports and fixes
- Documentation updates
- Test additions
- Security issue reports
- Usability feedback

**Contributors will be recognized in:**
- CHANGELOG.md
- Project documentation
- Institutional memory (Galactica)

---

## Project-Specific Context

### This is a HIGH RISK System
**Django SSO Authentication** is the authentication gateway for all future barge2rail.com systems. Any issues here affect everything downstream.

**Special considerations:**
- PrimeTrade integration depends on this
- Future intern database project depends on this
- All staff will use this system
- Downtime blocks all operations

**Therefore:**
- Extra caution required
- Multiple perspectives mandatory
- Thorough testing essential
- Rollback plans critical
- Clear communication vital

### Business Context
- Small logistics company
- Interrupt-driven operations
- Replacing 15+ fragmented Google Sheets
- Building unified system gradually
- SSO is the foundation for everything

**This means:**
- Changes must not disrupt operations
- Documentation must be clear for non-technical users
- Rollback must be quick and reliable
- Testing must cover real business workflows
- Learning from every deployment

---

## The Bottom Line

**We're building sustainable, safe systems with AI assistance.**

- Follow the Safety System framework
- Assess risk before every change
- Use appropriate quality gates
- Test thoroughly
- Document everything
- Learn continuously

**Quality over speed. Safety over features.**

Welcome to the team! 🚀
