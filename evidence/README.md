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

Only safe, fictional test data belongs in this repository.
