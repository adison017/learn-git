package handlers

import (
    "encoding/json" // สำหรับการเข้ารหัส JSON
    "net/http"
    "project/models"
    "html/template"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        password := r.FormValue("password")

        // ตรวจสอบการล็อกอิน
        valid, err := models.AuthenticateUser(username, password)
        if err != nil {
            http.Error(w, err.Error(), http.StatusUnauthorized)
            return
        }
        if !valid {
            http.Error(w, "Invalid username or password", http.StatusUnauthorized)
            return
        }

        // ดึงข้อมูลผู้ใช้จากฐานข้อมูล
        user, err := models.GetUserByUsername(username)
        if err != nil {
            http.Error(w, "Failed to retrieve user data", http.StatusInternalServerError)
            return
        }

        // ตั้งค่า session พร้อมบันทึกค่า status
        session, err := Store.Get(r, "session-name")
        if err != nil {
            http.Error(w, "Failed to get session", http.StatusInternalServerError)
            return
        }
        session.Values["username"] = user.Username
        session.Values["status"] = user.Status

        if err := session.Save(r, w); err != nil {
            http.Error(w, "Failed to save session", http.StatusInternalServerError)
            return
        }

        // เช็คสถานะของผู้ใช้และตั้งค่าเส้นทาง redirect
        var redirectUrl string
        if user.Status == "Admin" {
            redirectUrl = "/admin"
        } else {
            redirectUrl = "/users"
        }

        // ส่ง JSON กลับไปยังหน้าเข้าสู่ระบบ
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "username":    user.Username,
            "redirectUrl": redirectUrl,
        })
    } else {
        tmpl := template.Must(template.ParseFiles("templates/login.html"))
        tmpl.Execute(w, nil)
    }
}


func AdminHandler(w http.ResponseWriter, r *http.Request) {
    // ดึงข้อมูลจาก session
    session, err := Store.Get(r, "session-name")
    if err != nil || session.IsNew {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    username, _ := session.Values["username"].(string) // ดึง username
    status, _ := session.Values["status"].(string)     // ดึง status

    // ตรวจสอบว่าผู้ใช้มีสถานะ Admin หรือไม่
    if status != "Admin" {
        http.Error(w, "Access denied", http.StatusForbidden)
        return
    }

    // ดึง query parameter สำหรับการค้นหา
    search := r.URL.Query().Get("search")

    // ดึงข้อมูลผู้ใช้ทั้งหมดหรือที่ตรงตามคำค้นหา
    var users []models.User
    if search != "" {
        users, err = models.SearchUsers(search) // สร้างฟังก์ชันใน models.go เพื่อค้นหาผู้ใช้
    } else {
        users, err = models.GetAllUsers() // ฟังก์ชันดั้งเดิมที่ดึงข้อมูลผู้ใช้ทั้งหมด
    }

    if err != nil {
        http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
        return
    }

    tmpl := template.Must(template.ParseFiles("templates/admin.html"))
    tmpl.Execute(w, struct {
        Users []models.User
        LoggedInUser struct {
            Username string
            Status   string
        }
        Search string // ส่งคำค้นหาไปยัง template
    }{
        Users: users,
        LoggedInUser: struct {
            Username string
            Status   string
        }{
            Username: username,
            Status:   status,
        },
        Search: search,
    })
}
