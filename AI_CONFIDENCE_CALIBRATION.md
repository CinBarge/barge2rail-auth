# AI Confidence Calibration System
**Version 1.0 - October 2025**

## Purpose

**AI tools claim confidence levels (HIGH/MEDIUM/LOW) but actual accuracy varies by tool, task type, and domain.**

This system tracks claimed vs actual confidence systematically, enabling:
- Better tool selection for specific tasks
- Realistic confidence expectations
- Early detection of tool drift or degradation
- Quarterly recalibration based on actual performance

---

## Calibration Table Structure

### Master Calibration Table

| AI Tool | Task Type | Claimed Confidence | Actual Accuracy | Sample Size | Last Updated |
|---------|-----------|-------------------|-----------------|-------------|--------------|
| Claude Code | Repository coding | HIGH (95%) | 90% | 5 projects | 2025-10-08 |
| Claude Code | Security review | MEDIUM (70%) | 65% | 3 projects | 2025-10-08 |
| Claude CTO | Risk assessment | HIGH (90%) | 100% | 1 project | 2025-10-08 |
| Claude CTO | Strategic planning | HIGH (90%) | TBD | 0 projects | - |
| ChatGPT | UX design | MEDIUM (75%) | TBD | 0 projects | - |
| ChatGPT | Security review | HIGH (85%) | TBD | 0 projects | - |

**Calibration Formula:**
```
Accuracy = (Correct Predictions / Total Predictions) × 100%
Calibration Error = |Claimed Confidence - Actual Accuracy|
```

**Interpretation:**
- **Well-Calibrated:** Calibration Error < 10%
- **Overconfident:** Claimed > Actual by 10%+
- **Underconfident:** Actual > Claimed by 10%+

---

## Task Type Definitions

### 1. Repository Coding
**What:** Writing/modifying code in repositories
**Measurement:** Tests pass + code review approval
**Sample Projects:** Django SSO, God Mode fix

### 2. Security Review
**What:** Identifying security vulnerabilities in code/systems
**Measurement:** Vulnerabilities found vs missed (discovered later)
**Sample Projects:** Django SSO security review

### 3. Risk Assessment
**What:** Calculating risk scores and recommending protocols
**Measurement:** Risk level matched reality in post-mortem
**Sample Projects:** Django SSO (47/60 HIGH RISK → accurate)

### 4. Strategic Planning
**What:** Architecture decisions, technology selection, integration design
**Measurement:** Plan executed successfully without major pivots
**Sample Projects:** SSO-first approach, module independence

### 5. UX Design
**What:** User interface design, user experience recommendations
**Measurement:** "Mom test" pass rate, user adoption scores
**Sample Projects:** (None yet - TBD)

### 6. Data Safety Review
**What:** Identifying data integrity risks
**Measurement:** Data issues found vs missed (discovered later)
**Sample Projects:** Django SSO data safety review

### 7. Business Logic Review
**What:** Workflow alignment, operational correctness
**Measurement:** Business process issues found vs missed
**Sample Projects:** Django SSO business logic review

### 8. Configuration Management
**What:** Setting up environments, managing configs
**Measurement:** Config works first time vs requires fixes
**Sample Projects:** Django Render deployment, OAuth setup

---

## Data Collection Process

### During Projects (Automated via Post-Mortem)

**In POST_MORTEM_TEMPLATE.md, Section 2:**

```markdown
### AI Tool Performance

**Tools Used:**
- Implementation: [Tool] - Claimed: [H/M/L] - Actual: [Accuracy %]
- Security Review: [Tool] - Claimed: [H/M/L] - Actual: [Accuracy %]
- Data Safety: [Tool] - Claimed: [H/M/L] - Actual: [Accuracy %]
- Business Logic: [Tool] - Claimed: [H/M/L] - Actual: [Accuracy %]

**Accuracy Calculation:**
- What they got right: [X items]
- What they missed: [Y items]
- Total predictions: [X + Y]
- Actual Accuracy: [X / (X+Y) × 100%]
```

**Transfer to Calibration Table:**
After each post-mortem, update master calibration table in this document.

---

## Quarterly Refresh Process

### Schedule
- **Q1 Review:** January (after 3+ months of data)
- **Q2 Review:** April
- **Q3 Review:** July
- **Q4 Review:** October

### Quarterly Review Procedure

**Step 1: Update Master Table (15 minutes)**
```bash
# Pull all post-mortems from last quarter
memory search "post-mortem" --since "quarter" --limit 20

# For each project:
# 1. Extract claimed vs actual for each AI tool
# 2. Update calibration table
# 3. Recalculate running averages
```

**Step 2: Identify Trends (15 minutes)**

**Questions to Answer:**
- Which tools are consistently overconfident?
- Which tools are consistently underconfident?
- Are any tools drifting (accuracy changing over time)?
- Are there task types where all tools struggle?
- Are there task types where tools excel?

**Step 3: Update Tool Assignment Matrix (15 minutes)**

**In Layer 5 Tool Assignment Matrix:**
- Promote tools that exceed claimed confidence
- Demote tools that fall below claimed confidence
- Add warnings for overconfident tools
- Recommend external review for weak domains

**Step 4: Adjust Confidence Interpretation (15 minutes)**

**Create Tool-Specific Confidence Guides:**

Example:
```markdown
## Claude Code Confidence Guide (Updated: Q4 2025)

When Claude Code claims HIGH confidence (90%+):
- **Repository coding:** Trust it (actual: 90%)
- **Security review:** Reduce to MEDIUM (actual: 65%)
- **Configuration:** Reduce to LOW (actual: 55%)

When Claude Code claims MEDIUM confidence (70%):
- **Repository coding:** Actually HIGH (actual: 85%)
- **Security review:** Trust it (actual: 68%)

**Recommendation:** Claude Code is overconfident on security and configuration, well-calibrated on core coding.
```

**Step 5: Document Changes (15 minutes)**

**Update these files:**
- This file (AI_CONFIDENCE_CALIBRATION.md)
- LAYER_5_CHECKLIST.md (tool assignment updates)
- SUSTAINABLE_CTO_SYSTEM.md Layer 5 (if major changes)
- THE_BRIDGE_INDEX.md (version bump, changelog)

**Step 6: Log to Galactica (5 minutes)**

```bash
memory remember "Q[X] 2025 AI Calibration: [Summary of key findings and changes]" \
  --tags calibration,ai-performance,quarterly \
  --importance 8
```

**Total Time:** ~90 minutes per quarter

---

## Calibration Dashboard Template

### Current Quarter Snapshot (Q4 2025)

**Overall Calibration Health:**
- Tools Tracked: 3 (Claude Code, Claude CTO, ChatGPT)
- Task Types Tracked: 8
- Projects Completed: 1 (Django SSO)
- Well-Calibrated Tools: 1 (Claude CTO on risk assessment)
- Overconfident Tools: 0 (insufficient data)
- Underconfident Tools: 0 (insufficient data)

**Data Maturity:**
- 🟢 Sufficient data (3+ projects): Risk Assessment
- 🟡 Limited data (1-2 projects): Repository Coding, Security Review
- 🔴 No data yet: UX Design, Strategic Planning (execution), Configuration

**Action Items:**
- Continue collecting data across all task types
- Next calibration: Q1 2026 (January)

---

## Tool-Specific Calibration Reports

### Claude Code

**Overall Calibration Status:** Insufficient data (1 project)

| Task Type | Claimed | Actual | Calibration | Status |
|-----------|---------|--------|-------------|--------|
| Repository Coding | HIGH (95%) | 90% | -5% | 🟡 Slightly overconfident |
| Security Review | MEDIUM (70%) | 65% | -5% | 🟡 Slightly overconfident |
| Configuration | MEDIUM (70%) | TBD | - | 🔴 Need data |

**Trend:** Tends toward slight overconfidence
**Sample Size:** 1 project (Django SSO)
**Confidence:** LOW (need 2+ more projects)

**Recommendations:**
- Continue using for repository coding (core strength)
- Treat security reviews as LOW confidence until validated
- Get external review for HIGH/EXTREME risk security

---

### Claude CTO (The Bridge)

**Overall Calibration Status:** Excellent (1 project)

| Task Type | Claimed | Actual | Calibration | Status |
|-----------|---------|--------|-------------|--------|
| Risk Assessment | HIGH (90%) | 100% | +10% | 🟢 Well-calibrated / Underconfident |
| Strategic Planning | HIGH (90%) | TBD | - | 🔴 Need execution data |
| Independent Review | MEDIUM (75%) | TBD | - | 🔴 Need data |

**Trend:** Conservative, accurate
**Sample Size:** 1 project (Django SSO risk assessment)
**Confidence:** LOW (need 2+ more projects)

**Recommendations:**
- Trust risk assessments at claimed confidence
- Continue as independent reviewer
- Validate strategic planning through execution

---

### ChatGPT

**Overall Calibration Status:** No data

| Task Type | Claimed | Actual | Calibration | Status |
|-----------|---------|--------|-------------|--------|
| UX Design | - | - | - | 🔴 No projects yet |
| Security Review | - | - | - | 🔴 No projects yet |
| General Research | - | - | - | 🔴 No projects yet |

**Trend:** Unknown
**Sample Size:** 0 projects
**Confidence:** N/A

**Recommendations:**
- Use for UX design on next MEDIUM+ risk project
- Use as third perspective for security reviews
- Track claimed vs actual systematically

---

## Confidence Level Mapping

### Standard Confidence Claims

**HIGH Confidence (85-95%):**
- AI expects to be correct 85-95% of the time
- Equivalent to "very confident, rarely wrong"
- Use for critical decisions if calibrated

**MEDIUM Confidence (65-80%):**
- AI expects to be correct 65-80% of the time
- Equivalent to "moderately confident, sometimes wrong"
- Use with validation from second source

**LOW Confidence (50-65%):**
- AI expects to be correct 50-65% of the time
- Equivalent to "uncertain, often wrong"
- Always get second opinion or external review

### Adjusted Confidence (Tool-Specific)

**After calibration, create tool-specific guides:**

Example (hypothetical after 5+ projects):
```markdown
Claude Code says HIGH on security review:
→ Actually MEDIUM (actual: 70%)
→ Recommendation: Get second security review

ChatGPT says MEDIUM on UX design:
→ Actually HIGH (actual: 90%)
→ Recommendation: Trust it, validate with Mom test
```

---

## Integration with Existing Framework

### Layer 0: Pre-Work Planning
**Enhancement:** Tool assignment considers calibrated confidence, not just claimed

```markdown
**Tool Assignment Matrix Enhancement:**
Check AI_CONFIDENCE_CALIBRATION.md for:
- Recent accuracy trends
- Task-specific calibration adjustments
- Overconfidence warnings
```

### Layer 2: Quality Gates
**Enhancement:** Three-perspective review considers calibrated confidence

```markdown
**Synthesis Enhancement:**
When evaluating review confidence:
1. Check claimed confidence from each AI
2. Adjust based on calibration table
3. Weight recommendations accordingly
```

### Layer 4: Learning Loop
**Enhancement:** Post-mortem feeds calibration system

```markdown
**Post-Mortem Checklist Addition:**
- [ ] Calculate actual accuracy for each AI tool used
- [ ] Update AI_CONFIDENCE_CALIBRATION.md master table
- [ ] Flag any tools with >10% calibration error
```

### Layer 5: AI Coordination
**Enhancement:** Tool selection informed by calibration data

```markdown
**Tool Selection Enhancement:**
Before assigning tool to task:
1. Check task type in calibration table
2. Identify best-calibrated tool for this task
3. Consider overconfidence adjustments
4. Document tool choice rationale
```

---

## Drift Detection

### Early Warning Signs

**Tool Drift Indicators:**
- Calibration error increasing over time (trend analysis)
- Sudden accuracy drop on previously strong task types
- Consistent overconfidence across multiple task types
- Multiple projects with significant misses

**Monitoring Frequency:**
- Quarterly: Formal calibration review
- Post-project: Update calibration data
- Real-time: Flag major misses during projects

**Response to Drift:**
1. **Document the drift:** What changed? When did accuracy drop?
2. **Investigate cause:** Tool update? New task type? Changed workflow?
3. **Adjust confidence:** Update tool-specific confidence guides
4. **Consider alternatives:** Should we switch tools for this task?
5. **External validation:** Get professional review if critical

---

## Success Metrics

### System Health Indicators

**Good Calibration System:**
- ✅ 80%+ of tools are well-calibrated (error <10%)
- ✅ Overconfident tools identified and adjusted
- ✅ Tool assignment matrix reflects actual performance
- ✅ Quarterly reviews completed on schedule
- ✅ Post-mortems consistently feed calibration data

**System Needs Attention:**
- ⚠️ 50-80% of tools well-calibrated
- ⚠️ Some overconfident tools unaddressed
- ⚠️ Missed 1 quarterly review
- ⚠️ Inconsistent post-mortem data collection

**System Failure:**
- ❌ <50% of tools well-calibrated
- ❌ Critical overconfidence undetected
- ❌ Tool assignment ignores calibration data
- ❌ Quarterly reviews not performed
- ❌ Post-mortems don't update calibration

### Business Impact

**Value of Calibration:**
- Reduced deployment failures from overconfident AI
- Better tool selection for critical tasks
- Earlier detection of tool degradation
- More realistic project estimates
- Higher trust in AI recommendations

**Time Investment:**
- Per project: 5 min (part of post-mortem)
- Per quarter: 90 min (calibration review)
- Annual: 6 hours total

**ROI:** Prevents even one deployment failure → Saves days/weeks of rework

---

## Quick Reference

### Adding New AI Tool

**Step 1:** Add to master calibration table with TBD
**Step 2:** Use on LOW-MEDIUM risk projects first
**Step 3:** Track claimed vs actual systematically
**Step 4:** After 3+ projects, assess calibration
**Step 5:** Update tool assignment matrix accordingly

### Adding New Task Type

**Step 1:** Define task type clearly
**Step 2:** Define success measurement criteria
**Step 3:** Add to task type definitions section
**Step 4:** Collect data across multiple projects
**Step 5:** Establish baseline confidence expectations

### Quick Health Check

```bash
# Check calibration status
grep -A 2 "Overall Calibration Status" AI_CONFIDENCE_CALIBRATION.md

# Check overconfident tools
grep "Overconfident" AI_CONFIDENCE_CALIBRATION.md

# Check data maturity
grep "Data Maturity" AI_CONFIDENCE_CALIBRATION.md
```

---

## Version History

**v1.0 - October 2025**
- Initial calibration system
- Master calibration table established
- Quarterly refresh process defined
- Django SSO baseline data (1 project)
- Integration with existing framework

**Next Review:** Q1 2026 (January)

---

## Appendix: Example Calibration Calculations

### Example 1: Repository Coding (Django SSO)

**Claude Code claimed:** HIGH confidence (95%)

**Actual performance:**
- Files created/modified: 20
- Tests written: 40
- Files that worked correctly: 18
- Files that needed fixes: 2
- Tests that passed: 40
- Tests that failed: 0

**Accuracy calculation:**
- Correct: 18 files + 40 tests = 58
- Total: 20 files + 40 tests = 60
- Accuracy: 58/60 = 96.7%

**Calibration:**
- Claimed: 95%
- Actual: 96.7%
- Error: +1.7% (underconfident)
- **Assessment:** Well-calibrated ✅

### Example 2: Security Review (Hypothetical)

**ChatGPT claimed:** HIGH confidence (90%)

**Actual performance:**
- Security concerns raised: 10
- Concerns that were valid: 6
- Concerns that were false positives: 4
- Vulnerabilities missed: 3

**Accuracy calculation:**
- Correct predictions: 6 valid concerns
- Total concerns raised: 10
- Precision: 6/10 = 60%
- Recall: 6/(6+3) = 66.7%
- **Accuracy (F1 score): 63%**

**Calibration:**
- Claimed: 90%
- Actual: 63%
- Error: -27% (overconfident)
- **Assessment:** Significantly overconfident ⚠️

**Action:** Adjust ChatGPT security reviews to MEDIUM confidence, require second review for HIGH RISK projects.

---

**This calibration system ensures AI confidence claims match reality, enabling better decision-making and tool selection.**