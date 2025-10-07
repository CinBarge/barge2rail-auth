# claude.md Maintenance Protocol

## Purpose
Ensure Claude Code has current, comprehensive instructions for repository work by systematically updating claude.md as part of The Bridge workflow.

---

## Maintenance Triggers

**Update claude.md after:**

1. ✅ **Every architectural decision** (Layer 1 - Decision Framework)
2. ✅ **Every post-mortem** (Layer 4 - Learning Loop)
3. ✅ **Every new pattern discovered** (Layer 4 - Pattern Library)
4. ✅ **Every security issue found** (Layer 2 - Quality Gates)
5. ✅ **Every deployment** (Layer 3 - Verification Protocol)
6. ✅ **Every HIGH RISK project completion** (Layer 4 - Learning Loop)

---

## Sections to Update

### After Architectural Decision:
- **Section:** "Key Architectural Decisions"
- **Add:** Decision, rationale, impact, date
- **Who:** The Bridge (automated during decision documentation)

### After Post-Mortem:
- **Section:** "Recent Changes & Lessons Learned"
- **Add:** Date, what happened, why, lesson, impact
- **Who:** The Bridge (part of post-mortem process)

### After Pattern Discovery:
- **Section:** "Patterns That Work Here" or "Patterns That Don't Work Here"
- **Add:** Pattern name, use case, implementation, rationale
- **Who:** The Bridge (during pattern library updates)

### After Security Issue:
- **Section:** "Security Requirements" or "Known Vulnerabilities"
- **Add:** Vulnerability, mitigation, prevention
- **Who:** The Bridge (during security review)

### After Deployment:
- **Section:** "Deployment Context" or "Common Pitfalls"
- **Add:** Deployment quirks, environment variables, rollback updates
- **Who:** The Bridge (during deployment verification)

---

## Post-Mortem Checklist Addition

**Add to every post-mortem:**

```markdown
## claude.md Updates Required

**Architectural Decisions Made:**
- [ ] Documented in "Key Architectural Decisions"
- [ ] Rationale explained
- [ ] Date added

**Patterns Discovered:**
- [ ] Added to "Patterns That Work Here" or "Patterns That Don't Work Here"
- [ ] Use case documented
- [ ] Implementation example provided

**Pitfalls Encountered:**
- [ ] Added to "Common Pitfalls"
- [ ] Root cause identified
- [ ] Prevention documented

**Security Learnings:**
- [ ] Added to "Security Requirements" or "Known Vulnerabilities"
- [ ] Vulnerabilities documented
- [ ] Mitigations explained

**Deployment Updates:**
- [ ] Rollback procedure verified/updated
- [ ] Environment variables documented
- [ ] Deployment checklist current

**Version Incremented:**
- [ ] Version number updated in claude.md
- [ ] Change documented in "Version History"
```

---

## Version Control

**Format:**
```
- **vX.X - [Date]** - [Author]
  - [What changed]
  - [Why it changed]
  - [Impact]
```

**Increment:**
- Major version (2.0 → 3.0): Significant structural changes, major pattern shifts
- Minor version (2.0 → 2.1): New sections, new patterns, lessons learned

---

## The Bridge's Responsibility

**Before Assigning Work to Claude Code:**
1. Verify claude.md is current
2. Update if gaps exist
3. Reference specific sections when delegating work

**During Work:**
1. Monitor if CC follows claude.md guidelines
2. Note deviations for future updates

**After Work:**
1. Update claude.md with lessons learned
2. Add to pattern library if new patterns emerge
3. Document pitfalls encountered

---

## Success Metrics

**claude.md is working when:**
- ✅ Claude Code makes contextually appropriate decisions
- ✅ Security requirements met on first try
- ✅ Patterns are followed consistently
- ✅ Version history shows regular updates (not stale)
- ✅ Post-mortems include claude.md updates

**claude.md needs attention when:**
- ❌ Claude Code makes contextually wrong decisions repeatedly
- ❌ Security issues found that should have been documented
- ❌ Patterns not being followed
- ❌ Version history is months old
- ❌ Post-mortems skip claude.md checklist

---

## Current Status

**Django SSO (barge2rail-auth):**
- ✅ Version 2.0 created (October 4, 2025)
- ✅ Business context documented
- ✅ Architectural decisions captured
- ✅ Patterns library established
- ✅ Lessons learned from God Mode and Safety System
- ✅ Integrated with The Bridge workflow

**Next Update:** After Django SSO deployment completion (post-mortem will add deployment lessons)
