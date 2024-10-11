package handlers

import (
    "net/http"
    "html/template"
    "github.com/gorilla/sessions"
    "project/models"
    "golang.org/x/crypto/bcrypt" // เพิ่มบรรทัดนี้
    "encoding/json" // เพิ่มบรรทัดนี้
    "project/db"
 
)
type UserData struct {
    Statuses []string     // รายการ status ทั้งหมด
}
var Store = sessions.NewCookieStore([]byte("1234"))

func SetNoCacheHeaders(w http.ResponseWriter) {
    w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
    w.Header().Set("Pragma", "no-cache")
    w.Header().Set("Expires", "0")
}


func CheckLogin(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        session, err := Store.Get(r, "session-name")
        if err != nil || session.Values["username"] == nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }
        next.ServeHTTP(w, r)
    })
}
func ListUsersHandler(w http.ResponseWriter, r *http.Request) {
    SetNoCacheHeaders(w) // ตั้งค่า headers เพื่อไม่ให้แคช
    session, err := Store.Get(r, "session-name")
    if err != nil {
        http.Error(w, "Failed to get session", http.StatusInternalServerError)
        return
    }

    username, ok1 := session.Values["username"].(string)
    status, ok2 := session.Values["status"].(string)

    if !ok1 || !ok2 {
        http.Error(w, "Session data is missing", http.StatusUnauthorized)
        return
    }

    // ดึงข้อมูลผู้ใช้ที่ล็อกอินอยู่
    user, err := models.GetUserByUsername(username)
    if err != nil {
        http.Error(w, "Failed to retrieve user data", http.StatusInternalServerError)
        return
    }

    // ส่งข้อมูลไปยัง template
    tmpl := template.Must(template.ParseFiles("templates/users.html"))
    tmpl.Execute(w, struct {
        Users []models.User // ใช้ slice แต่มีผู้ใช้เพียงคนเดียว
        LoggedInUser struct {
            Username string
            Status   string
        }
    }{
        Users: []models.User{user}, // ส่งข้อมูลของผู้ใช้ที่ล็อกอิน
        LoggedInUser: struct {
            Username string
            Status   string
        }{
            Username: username,
            Status:   status,
        },
    })
}

func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
    SetNoCacheHeaders(w) // ป้องกันการแคช

    // ตรวจสอบสิทธิ์การเข้าใช้งาน (เฉพาะผู้ที่เป็น Admin เท่านั้น)
    session, err := Store.Get(r, "session-name")
    if err != nil {
        http.Error(w, "Failed to get session", http.StatusInternalServerError)
        return
    }

    status, ok := session.Values["status"].(string)
    if !ok || status != "Admin" {
        http.Redirect(w, r, "/users", http.StatusSeeOther)
        return
    }

    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        password := r.FormValue("password")
        firstname := r.FormValue("firstname")
        lastname := r.FormValue("lastname")
        email := r.FormValue("email")
        birthdate := r.FormValue("birthdate")
        userStatus := r.FormValue("status")

        // ตรวจสอบข้อมูลที่กรอก
        if username == "" || password == "" || firstname == "" || lastname == "" || email == "" || birthdate == "" || userStatus == "" {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusBadRequest) // ตั้งค่าผลลัพธ์ HTTP Status Code
            json.NewEncoder(w).Encode(map[string]string{"error": "ข้อมูลไม่ครบถ้วน"})
            return
        }

        // เพิ่มข้อมูลผู้ใช้ในฐานข้อมูล
        err := models.CreateUser(username, password, firstname, lastname, email, birthdate, userStatus)
        if err != nil {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusInternalServerError) // ตั้งค่าผลลัพธ์ HTTP Status Code
            json.NewEncoder(w).Encode(map[string]string{"error": "ไม่สามารถเพิ่มผู้ใช้ได้: " + err.Error()})
            return
        }

        // หากสำเร็จ
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK) // ตั้งค่าผลลัพธ์ HTTP Status Code
        json.NewEncoder(w).Encode(map[string]string{"message": "เพิ่มผู้ใช้สำเร็จ"})
        return
    }

    // ดึงข้อมูลบทบาทจากฐานข้อมูลเพื่อแสดงในฟอร์ม (กรณีไม่ใช่การ POST)
    roles, err := db.FetchRoles()
    if err != nil {
        http.Error(w, "Failed to fetch roles", http.StatusInternalServerError)
        return
    }

    // สำหรับการร้องขอแบบ GET แสดงฟอร์มการเพิ่มผู้ใช้
    data := struct {
        Roles []db.Role // รายการบทบาท จากฐานข้อมูล
    }{
        Roles: roles,
    }

    tmpl := template.Must(template.ParseFiles("templates/Addform.html"))
    if err := tmpl.Execute(w, data); err != nil { // ส่งข้อมูลบทบาทไปยังเทมเพลต
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
}




func EditUserHandler(w http.ResponseWriter, r *http.Request) {
    SetNoCacheHeaders(w)
    // session, err := Store.Get(r, "session-name")
    // if err != nil {
    //     http.Error(w, "Failed to get session", http.StatusInternalServerError)
    //     return
    // }

    // status, ok := session.Values["status"].(string)
    // if !ok || status != "Admin" {
    //     http.Redirect(w, r, "/users", http.StatusSeeOther)
    //     return
    // }

    if r.Method == http.MethodPost {
        // ดึงข้อมูลจากแบบฟอร์ม
        username := r.FormValue("username")
        password := r.FormValue("password")
        firstname := r.FormValue("firstname")
        email := r.FormValue("email")
        lastname := r.FormValue("lastname")
        birthdate := r.FormValue("birthdate")

        // เรียกใช้งานฟังก์ชันเพื่ออัปเดตข้อมูลผู้ใช้
        err := models.UpdateUser(username, password, firstname, lastname, email, birthdate)
        if err != nil {
            // ส่ง JSON แจ้งข้อผิดพลาด
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"error": "Failed to update user"})
            return
        }

        // ส่ง JSON แจ้งอัปเดตสำเร็จ
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{"message": "อัปเดตผู้ใช้เสร็จสิ้น"})
        return
    } else {
        username := r.URL.Query().Get("username")
        user, err := models.GetUserByUsername(username)
        if err != nil {
            http.Error(w, "User not found: "+err.Error(), http.StatusNotFound)
            return
        }

        tmpl := template.Must(template.ParseFiles("templates/Editus.html"))
        tmpl.Execute(w, user)
    }
}

func EditadminHandler(w http.ResponseWriter, r *http.Request) {
    SetNoCacheHeaders(w) // ตั้งค่า HTTP headers
    session, err := Store.Get(r, "session-name")
    if err != nil {
        http.Error(w, "Failed to get session", http.StatusInternalServerError)
        return
    }

    status, ok := session.Values["status"].(string)
    if !ok || status != "Admin" {
        http.Redirect(w, r, "/users", http.StatusSeeOther)
        return
    }

    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        password := r.FormValue("password")
        firstname := r.FormValue("firstname")
        lastname := r.FormValue("lastname")
        email := r.FormValue("email")
        birthdate := r.FormValue("birthdate")
        status := r.FormValue("status")

        err := models.UpdateAdmin(username, password, firstname, lastname, email, birthdate, status)
        if err != nil {
             // ส่ง JSON แจ้งข้อผิดพลาด
             w.Header().Set("Content-Type", "application/json")
             json.NewEncoder(w).Encode(map[string]string{"error": "Failed to update user"})
             return
        }

        // ส่งกลับข้อความ JSON เมื่อการอัปเดตสำเร็จ
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{"message": "อัปเดตข้อมูลเรียบร้อยแล้ว"})
        return
    } else {
        username := r.URL.Query().Get("username")
        user, err := models.GetUserByUsername(username)
        if err != nil {
            http.Error(w, "User not found: "+err.Error(), http.StatusNotFound)
            return
        }

        // ดึงข้อมูลบทบาททั้งหมดจาก db
        roles, err := db.FetchRoles() // ฟังก์ชันที่ดึงบทบาททั้งหมด
        if err != nil {
            http.Error(w, "Failed to fetch roles: "+err.Error(), http.StatusInternalServerError)
            return
        }

        // ส่งข้อมูลไปยังเทมเพลต
        data := struct {
            User  *models.User // ข้อมูลผู้ใช้
            Roles []db.Role    // รายการบทบาท จาก db
        }{
            User:  &user, // ส่ง pointer
            Roles: roles,
        }

        tmpl := template.Must(template.ParseFiles("templates/EditAdmin.html"))
        if err := tmpl.Execute(w, data); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
    }
}




func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
    SetNoCacheHeaders(w) // ตั้งค่า HTTP headers

    session, err := Store.Get(r, "session-name")
    if err != nil {
        http.Error(w, "Failed to get session", http.StatusInternalServerError)
        return
    }

    status, ok := session.Values["status"].(string)
    if !ok || status != "Admin" {
        http.Redirect(w, r, "/users", http.StatusSeeOther)
        return
    }

    username := r.URL.Query().Get("username")
    err = models.DeleteUser(username)
    if err != nil {
        // ส่งกลับ JSON หากเกิดข้อผิดพลาด
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Failed to delete user"})
        return
    }

    // ส่งกลับ JSON เมื่อการลบสำเร็จ
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK) // 200 OK
    json.NewEncoder(w).Encode(map[string]string{"message": "ลบผู้ใช้เสร็จสิ้นแล้ว"})
}


func LogoutHandler(w http.ResponseWriter, r *http.Request) {
    session, err := Store.Get(r, "session-name")
    if err != nil {
        http.Error(w, "Failed to get session", http.StatusInternalServerError)
        return
    }

    // เคลียร์ค่าใน session
    session.Values["username"] = ""
    session.Values["status"] = ""
    session.Options.MaxAge = -1 // ทำให้ session หมดอายุ
    if err := session.Save(r, w); err != nil {
        http.Error(w, "Failed to save session", http.StatusInternalServerError)
        return
    }

    http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        password := r.FormValue("password")
        firstname := r.FormValue("firstname")
        lastname := r.FormValue("lastname")
        email := r.FormValue("email")
        birthdate := r.FormValue("birthdate")

        // ตรวจสอบชื่อผู้ใช้หรืออีเมลมีอยู่ในฐานข้อมูล
        exists, err := models.UserExists(username, email)
        if err != nil {
            http.Error(w, "Failed to check user existence", http.StatusInternalServerError)
            return
        }
        if exists {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusConflict) // 409 Conflict
            json.NewEncoder(w).Encode(map[string]string{
                "message": "ชื่อผู้ใช้หรืออีเมลนี้มีอยู่แล้ว",
            })
            return
        }

        // เข้ารหัสรหัสผ่าน
        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
        if err != nil {
            http.Error(w, "Failed to hash password", http.StatusInternalServerError)
            return
        }

        // สร้างผู้ใช้ใหม่
        user := models.User{
            Username:  username,
            Password:  string(hashedPassword),
            Firstname: firstname,
            Lastname:  lastname,
            Email:     email,
            Birthdate: birthdate,
            Status: "User",
        }

        // บันทึกผู้ใช้ใหม่ในฐานข้อมูล
        err = models.CreateUser(user.Username, user.Password, user.Firstname, user.Lastname, user.Email, user.Birthdate, user.Status)
        if err != nil {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusInternalServerError)
            json.NewEncoder(w).Encode(map[string]string{
                "message": "Failed to create user",
            })
            return
        }

        // ส่ง JSON กลับไปยังผู้ใช้
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{
            "message": "ลงทะเบียนผู้ใช้เรียบร้อยแล้ว!!",
        })
    } else {
        tmpl := template.Must(template.ParseFiles("templates/register.html"))
        tmpl.Execute(w, nil)
    }
}
