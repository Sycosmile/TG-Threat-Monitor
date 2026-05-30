Thank you for considering contributing to TG Threat Monitor!

Guidelines
- Fork the repository and create a feature branch from `main`.
- Keep changes small and focused; include tests where possible.
- Run linters and formatting locally before opening a PR:

```bash
python -m pip install -r requirements.txt flake8 pylint black
python -m black .
python -m flake8 .
python -m pylint main.py core/*.py
```

- Open a pull request describing your change and link any relevant issue.

Code of Conduct
- Be respectful and constructive. Report abusive behavior to the repository owners.
