# Evidence register

Jenkins writes generated evidence bundles to `evidence/generated/`. Keep the source baseline and the generated outputs separate.

| ID | Created by | Purpose |
| --- | --- | --- |
| E001 | Baseline pipeline job | Simulated baseline findings |
| E002 | Baseline pipeline job | Baseline pipeline definition captured for review |
| E003 | Baseline pipeline job | SHA-256 checksums for integrity/repeatability |
| E004 | Assessment pipeline job | Gitleaks secret-scanning result |
| E005 | Assessment pipeline job | Bandit Python SAST result |
| E006 | Assessment pipeline job | pip-audit dependency result |
| E007 | Assessment pipeline job | Scanner exit codes, recorded even when a finding is present |
| E008 | Container pipeline stage | Local image build metadata; no registry push |
| E009 | Container pipeline stage | Trivy vulnerability scan of the built image |
| E010 | Container pipeline stage | Container build, inspect, and Trivy exit codes |
| E014 | Analysis pipeline stage | Local evidence summary from E004–E010; human review required |
| E015 | Analysis pipeline stage | MITRE ATT&CK/D3FEND candidate review worksheet |
| E016 | AI analysis stage | AI-generated security narrative based only on E014; human review required |
| E017 | AI analysis stage | Model, execution status, and data-boundary metadata |

Only safe, fictional test data belongs in this repository.
