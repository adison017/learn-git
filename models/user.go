package models

import (
    "errors"
    "golang.org/x/crypto/bcrypt"
    "database/sql"
    "project/db"
    "fmt"
  
)

// User struct เพื่อเก็บข้อมูลของผู้ใช้
type User struct {
    ID        int
    Username  string
    Password  string
    Firstname string
    Lastname  string
    Email     string
    Birthdate string
    Status    string
    //  Statuses  []string
}

func AuthenticateUser(username, password string) (bool, error) {
    var storedPassword string

    // ดึงรหัสผ่านที่ตรงกับ username จากฐานข้อมูล โดยใช้ parameterized queries
    err := db.DB.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedPassword)
    if err != nil {
        if err == sql.ErrNoRows {
            return false, errors.New("user not found")
        }
        return false, err
    }

    // ตรวจสอบว่ารหัสผ่านที่ดึงมา ตรงกับรหัสผ่านที่ผู้ใช้กรอกหรือไม่
    err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
    if err != nil {
        return false, errors.New("invalid password")
    }

    return true, nil
}

// ฟังก์ชันสร้างผู้ใช้ใหม่
func CreateUser(username, password, firstname, lastname, email, birthdate, status string) error {
    // เข้ารหัสรหัสผ่านก่อนที่จะเก็บลงฐานข้อมูล
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return err
    }

    query := "INSERT INTO users (username, password, firstname, lastname, email, birthdate, status) VALUES (?, ?, ?, ?, ?, ?, ?)"
    _, err = db.DB.Exec(query, username, hashedPassword, firstname, lastname, email, birthdate, status)
    return err
}
// UserExists ตรวจสอบว่าชื่อผู้ใช้หรืออีเมลมีอยู่ในฐานข้อมูล
func UserExists(username, email string) (bool, error) {
    var count int
    query := "SELECT COUNT(*) FROM users WHERE username = ? OR email = ?"
    err := db.DB.QueryRow(query, username, email).Scan(&count)
    if err != nil {
        return false, err
    }
    return count > 0, nil
}

func GetAllUsers() ([]User, error) {
    rows, err := db.DB.Query("SELECT username, password,firstname, lastname, email, birthdate, status FROM users")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var users []User
    for rows.Next() {
        var user User
        err := rows.Scan(&user.Username, &user.Password ,&user.Firstname, &user.Lastname, &user.Email, &user.Birthdate, &user.Status)
        if err != nil {
            return nil, err
        }
        users = append(users, user)
    }
    return users, nil
}

func GetUserByUsername(username string) (User, error) {
    var user User
    // ใช้ SELECT ระบุชื่อคอลัมน์ที่ต้องการแทน *
    err := db.DB.QueryRow("SELECT username, password, firstname, lastname, email, birthdate, status FROM users WHERE username = ?", username).Scan(
        &user.Username, 
        &user.Password, 
        &user.Firstname, 
        &user.Lastname, 
        &user.Email, 
        &user.Birthdate, 
        &user.Status,
    )
    
    // ตรวจสอบข้อผิดพลาดที่เกิดขึ้น
    if err != nil {
        if err == sql.ErrNoRows {
            return User{}, fmt.Errorf("User not found")
        }
        return User{}, fmt.Errorf("Error retrieving user: %v", err)
    }
    return user, nil
}

func UpdateUser(username, password, firstname, lastname, email, birthdate string) error {
    var query string
    var err error

    // ตรวจสอบว่ามีการระบุรหัสผ่านใหม่หรือไม่
    if password != "" {
        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
        if err != nil {
            return err
        }

        query = "UPDATE users SET password = ?, firstname = ?, lastname = ?, email = ?, birthdate = ? WHERE username = ?"
        _, err = db.DB.Exec(query, hashedPassword, firstname, lastname, email, birthdate, username)
    } else {
        query = "UPDATE users SET firstname = ?, lastname = ?, email = ?, birthdate = ? WHERE username = ?"
        _, err = db.DB.Exec(query, firstname, lastname, email, birthdate, username)
    }
    
    return err
}
func SearchUsers(search string) ([]User, error) {
    var users []User
    query := "SELECT username, firstname, lastname, email, birthdate, status FROM users WHERE username LIKE ?"

    rows, err := db.DB.Query(query, "%"+search+"%")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    for rows.Next() {
        var user User
        if err := rows.Scan(&user.Username, &user.Firstname, &user.Lastname, &user.Email, &user.Birthdate, &user.Status); err != nil {
            return nil, err
        }
        users = append(users, user)
    }

    return users, nil
}

// UpdateAdmin อัปเดตข้อมูลผู้ดูแลระบบ
func UpdateAdmin(username, password, firstname, lastname, email, birthdate, status string) error {
    var query string
    // ตรวจสอบว่ามีการระบุรหัสผ่านหรือไม่
    if password != "" {
        // ถ้ามีการระบุรหัสผ่าน ให้เข้ารหัสก่อนการอัปเดต
        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
        if err != nil {
            return err
        }
        // อัปเดตรหัสผ่านพร้อมกับข้อมูลอื่นๆ
        query = "UPDATE users SET password = ?, firstname = ?, lastname = ?, email = ?, birthdate = ?, status = ? WHERE username = ?"
        _, err = db.DB.Exec(query, string(hashedPassword), firstname, lastname, email, birthdate, status, username)
        return err
    }

    // ถ้าไม่มีการระบุรหัสผ่าน ให้ไม่เปลี่ยนรหัสผ่าน
    query = "UPDATE users SET firstname = ?, lastname = ?, email = ?, birthdate = ?, status = ? WHERE username = ?"
    _, err := db.DB.Exec(query, firstname, lastname, email, birthdate, status, username)
    return err
}

func DeleteUser(username string) error {
    query := "DELETE FROM users WHERE username = ?"
    _, err := db.DB.Exec(query, username)
    return err
}
