#!/usr/bin/env python3
"""Apply reviewed source fixes, preserving independently changed files."""
from pathlib import Path
import hashlib
import shutil
root=Path('/Users/iseunghyeon/rookies_final/Victim')
old=Path('/private/tmp/fiveeyes-mentor-source-check')
base=Path(__file__).resolve().parent
items={
'app/auth/mfa.php':'mfa-overlay/app/auth/mfa.php',
'public/login.php':'mfa-overlay/public/login.php',
'public/mfa.php':'mfa-overlay/public/mfa.php',
'tests/mfa_domain.php':'mfa-overlay/tests/mfa_domain.php',
'app/customer-photos.php':'photo-overlay/app/customer-photos.php',
'tests/customer_photos_domain.php':'photo-overlay/tests/customer_photos_domain.php',
'config/compose.mfa.example.yaml':'mfa-overlay/config/compose.mfa.example.yaml',
}
for rel,src in items.items():
 dst=root/rel; prior=old/rel; candidate=base/src
 if not candidate.is_file() or dst.is_symlink(): raise SystemExit(f'Invalid source or target: {rel}')
 if dst.exists() and not prior.exists(): raise SystemExit(f'Unexpected existing file: {rel}')
 if prior.exists() and (not dst.exists() or hashlib.sha256(prior.read_bytes()).digest()!=hashlib.sha256(dst.read_bytes()).digest()): raise SystemExit(f'Changed since snapshot: {rel}')
for rel,src in items.items():
 dst=root/rel; backup=base.parent/'evidence'/'20261103-web-before'/rel
 if dst.is_file():
  backup.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(dst,backup)
 dst.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(base/src,dst)
print('Applied reviewed source fixes:',len(items),'files. No deployment or DB migration.')
