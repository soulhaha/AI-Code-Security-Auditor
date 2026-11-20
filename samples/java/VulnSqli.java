import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * SQL 注入样本 —— 仅用于 Semgrep 规则测试，请勿在生产代码中使用。
 */
public class VulnSqli {

    private final Connection conn;

    public VulnSqli(Connection conn) {
        this.conn = conn;
    }

    // BAD 1: Statement + 字符串拼接
    public ResultSet findUserConcat(String name) throws SQLException {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    // BAD 2: Statement + String.format
    public ResultSet findUserFormat(String name) throws SQLException {
        Statement st = conn.createStatement();
        return st.executeQuery(String.format("SELECT * FROM users WHERE name = '%s'", name));
    }

    // BAD 3: executeUpdate 拼接
    public void deleteUser(String id) throws SQLException {
        Statement st = conn.createStatement();
        st.executeUpdate("DELETE FROM users WHERE id = " + id);
    }

    // GOOD: PreparedStatement 占位符，不应命中 SQL 注入规则
    public ResultSet findUserSafe(String name) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        return ps.executeQuery();
    }
}

// 期望命中行: 21、27、33
