"""测试环境隔离：测试一律写入临时 SQLite 与临时上传目录，避免污染 data/。

上传目录同样要隔离：`/api/logs/upload` 会把原始文件落到 `UPLOAD_ROOT`，
若指向项目的 `data/uploads`，每次跑测试都会留下一个没有分析记录的孤儿目录。
"""

import os
import tempfile
from pathlib import Path

tmp_dir = Path(tempfile.mkdtemp(prefix="loginsight-tests-"))
os.environ["LOGINSIGHT_DB_PATH"] = str(tmp_dir / "loginsight-test.db")
os.environ["LOGINSIGHT_UPLOAD_ROOT"] = str(tmp_dir / "uploads")
# 默认关闭 Sigma 社区规则（500+ 条）：
# ① 单元测试断言的是内置行为，社区规则在攻击样本上「重复检出」会不断打破精确计数；
# ② 全量启用会把测试套件从 ~6 秒拖到 ~4 分钟。
# 社区规则的质量由 tests/test_rule_quality.py 的门禁覆盖（那里显式启用）。
os.environ.setdefault("RULE_SIGMA_IMPORTED_ENABLED", "false")

