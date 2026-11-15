import sys
from pathlib import Path

# Add person-b to sys.path
PERSON_B_ROOT = Path(__file__).resolve().parent.parent
if str(PERSON_B_ROOT) not in sys.path:
    sys.path.insert(0, str(PERSON_B_ROOT))
