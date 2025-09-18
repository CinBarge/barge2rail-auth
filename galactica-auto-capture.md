# Automatic Galactica Capture Protocol

## Project-Wide Rule - ACTIVE ✅
All significant project information is automatically captured to Galactica without human involvement.

## Auto-Capture Triggers
### Immediate Capture (Importance 8-9)
- Technical milestones and decisions
- Architecture choices and rationale
- Deployment status changes
- Integration points established
- Problem resolutions and solutions

### Standard Capture (Importance 6-7)
- Configuration changes
- Tool coordination patterns
- Process improvements
- Learning outcomes

### Tags Strategy
- **Project:** django, primetrade, database-consolidation
- **Type:** deployment, decision, milestone, solution, integration
- **Status:** ready, blocked, complete, testing

## Health Check Schedule
### Daily (During Active Work)
```bash
memory search --since "today" --limit 5
# Verify recent activity is being captured
```

### Weekly System Validation
```bash
memory ask "What are the current project priorities?"
memory context --relevant-to "recent technical decisions" --copy
# Ensure UMS reflects actual project state
```

## Automatic Commands Used
```bash
memory remember "content" --tags relevant,tags --importance 6-9
memory context --relevant-to "topic" --copy  
memory ask "question about project context"
memory search "topic" --since "timeframe" --limit N
```

## Human Involvement: NONE REQUIRED
- Claude CTO executes all memory commands automatically
- Decisions and outcomes captured in real-time
- Context preparation handled seamlessly
- No copy/paste requests to human

## Success Metrics
- All major decisions findable via memory search
- Context recovery works after interruptions
- Cross-AI tool consistency maintained
- No "starting from scratch" conversations

## Last Health Check: [Auto-updated by Claude]
Status: Operational - 1569+ memories, MPS acceleration active
