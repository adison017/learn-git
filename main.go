package main

import (
    "log"
    "mime"
    "net/http"
    "project/handlers"
    "project/db"
)

func main() {
    // เชื่อมต่อฐานข้อมูล
    if err := db.InitDB(); err != nil {
        log.Fatalf("Could not connect to database: %v", err)
    }

    // ตั้งค่า MIME type สำหรับไฟล์ CSS
    mime.AddExtensionType(".css", "text/css")

    http.Handle("/", http.FileServer(http.Dir("./static"))) 
    // Routes
    http.Handle("/lib/", http.StripPrefix("/lib/", http.FileServer(http.Dir("lib"))))
    http.HandleFunc("/login", handlers.LoginHandler)
    
    // ใช้ http.HandlerFunc เพื่อแปลงเป็น http.Handler
    http.HandleFunc("/register", handlers.RegisterHandler)
    http.Handle("/admin", handlers.CheckLogin(http.HandlerFunc(handlers.AdminHandler))) 
    http.Handle("/users", handlers.CheckLogin(http.HandlerFunc(handlers.ListUsersHandler))) 
    http.Handle("/user/create", handlers.CheckLogin(http.HandlerFunc(handlers.CreateUserHandler))) 
    http.Handle("/user/edituser", handlers.CheckLogin(http.HandlerFunc(handlers.EditUserHandler))) 
    http.Handle("/user/edit", handlers.CheckLogin(http.HandlerFunc(handlers.EditadminHandler))) 
    http.Handle("/user/delete", handlers.CheckLogin(http.HandlerFunc(handlers.DeleteUserHandler))) 
    http.HandleFunc("/logout", handlers.LogoutHandler)

    log.Println("Server started at :8080...")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
