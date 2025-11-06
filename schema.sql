-- 漏洞信息表
DROP TABLE IF EXISTS vulnerabilities;
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    time TEXT NOT NULL,
    ids TEXT NOT NULL,
    source TEXT NOT NULL,
    detail_url TEXT NOT NULL,
    md5 TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

-- 创建索引
CREATE INDEX idx_vulnerabilities_time ON vulnerabilities(time);
CREATE INDEX idx_vulnerabilities_source ON vulnerabilities(source);
CREATE INDEX idx_vulnerabilities_md5 ON vulnerabilities(md5); 