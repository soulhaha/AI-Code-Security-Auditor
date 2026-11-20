"""SQL 注入样本 —— 仅用于 Semgrep 规则与上下文提取器测试，请勿在生产代码中使用。

每个 BAD 函数的最后一行是规则期望命中的 sink 行，行号见文件末尾注释。
"""
import sqlite3
import sys

DB_PATH = "app.db"


def connect() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)


# BAD 1: f-string 插值
def find_user_fstring(name: str):
    cur = connect().cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cur.fetchall()


# BAD 2: % 格式化
def find_user_percent(name: str):
    cur = connect().cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return cur.fetchall()


# BAD 3: str.format
def find_user_format(name: str):
    cur = connect().cursor()
    sql = "SELECT * FROM users WHERE name = '{}'".format(name)
    cur.execute(sql)
    return cur.fetchall()


# BAD 4: 字符串拼接
def find_user_concat(min_id: str):
    cur = connect().cursor()
    cur.execute("SELECT * FROM users WHERE id > " + min_id)
    return cur.fetchall()


# GOOD: 参数化查询，不应命中 SQL 注入规则
def find_user_safe(name: str):
    cur = connect().cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cur.fetchall()


if __name__ == "__main__":
    print(find_user_fstring(input("name> ")))
    print(find_user_percent("alice"))
    print(find_user_format("bob"))
    print(find_user_concat(sys.argv[1] if len(sys.argv) > 1 else "0"))
    print(find_user_safe("carol"))

# 期望命中行: 18、25、40；第 33 行先赋值再执行，需污点规则（见 rules/README 与 docs/roadmap.md）
