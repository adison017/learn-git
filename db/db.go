package db

import (
    "database/sql"
    "log"
    _ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

func InitDB() error {
    var err error
    DB, err = sql.Open("mysql", "if0_37494134:Az284091@tcp(sql101.infinityfree.com:3306)/if0_37494134_dbgo")
    if err != nil {
        return err
    }

    if err = DB.Ping(); err != nil {
        return err
    }
    log.Println("Connected to database!")
    return nil
}

// ฟังก์ชันตรวจสอบการล็อกอิน
func CheckLogin(username, password string) bool {
    var dbPassword string
    err := DB.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&dbPassword)
    
    if err != nil {
        if err == sql.ErrNoRows {
            return false
        }
        log.Println("Error querying the database:", err)
        return false
    }

    return password == dbPassword
}
// FetchRoles ดึงข้อมูลบทบาทจากฐานข้อมูล
func FetchRoles() ([]Role, error) {
    rows, err := DB.Query("SELECT id, name FROM roles")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var roles []Role
    for rows.Next() {
        var role Role
        if err := rows.Scan(&role.ID, &role.Name); err != nil {
            return nil, err
        }
        roles = append(roles, role)
    }
    return roles, nil
}

// Role แทนบทบาทใน dropdown
type Role struct {
    ID   int
    Name string
}