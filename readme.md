pip install -r requirements.txt

Commands to run:

Withoout using blocked packages:
python -m agent.main samples/sample_sbom.json

Using blocked packages ruleset:
python -m agent.main samples/sample_sbom.json --rules/blocked_packages.yaml

