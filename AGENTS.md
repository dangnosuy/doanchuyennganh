# Repository Guidelines

## Project Structure & Module Organization

```
MARL/
├── main.py              # Entry point for the MARL orchestrator
├── agents/              # Agent implementations
│   ├── manage_agent.py  # Agent management
│   ├── vuln_hunter_agent.py
│   ├── crawl_agent.py
│   ├── policy_agent.py
│   ├── red_team.py
│   └── blue_team.py
├── shared/              # Shared utilities and context
│   ├── context_manager.py
│   └── utils.py
├── tools/               # Tool implementations
├── knowledge/           # Knowledge base and playbooks
├── server/              # FastAPI server components
├── test/                # Test files and experiments
├── workspace/           # Runtime output directories
└── requirements.txt     # Python dependencies
```

## Build, Test, and Development Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run the main orchestrator
python main.py

# Run with custom target
python main.py "Test https://target.com user:admin pass:secret"

# Start the FastAPI server
uvicorn server.main:app --reload
```

## Coding Style & Naming Conventions

- **Language**: Python 3
- **Indentation**: 4 spaces
- **Naming**: 
  - Functions: `snake_case`
  - Classes: `PascalCase`
  - Constants: `UPPER_SNAKE_CASE`
  - Files: `snake_case.py`
- **Docstrings**: Use triple quotes for module and function documentation
- **Comments**: Inline comments in Vietnamese or English as appropriate

## Testing Guidelines

- Test files located in `test/` directory
- No formal testing framework currently configured
- Manual testing via `test/` scripts for agent interactions
- Integration tests for debate flows and agent coordination

## Commit & Pull Request Guidelines

- **Commit messages**: Use descriptive, concise messages
- **Branch naming**: Feature branches for new functionality
- **PR requirements**: 
  - Clear description of changes
  - Reference related issues if applicable
  - Test with target environments before submission

## Architecture Overview

This project implements a multi-agent reinforcement learning system for security testing with five phases:

1. **RECON**: CrawlAgent gathers target information
2. **DEBATE**: Red and Blue teams discuss attack strategies
3. **EXECUTION**: Approved workflows are executed
4. **EVALUATION**: Results are assessed
5. **REPORT**: Final outcomes are documented

The system uses OpenAI models for agent intelligence and FastAPI for server components.
