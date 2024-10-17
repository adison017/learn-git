package main

import (
    "log"
    "net/http"
    "project/handlers"
    "project/db"
)

func main() {
    // เชื่อมต่อฐานข้อมูล
    if err := db.InitDB(); err != nil {
        log.Fatalf("Could not connect to database: %v", err)
    }


    // ตั้งค่า FileServer สำหรับ static files
    http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static")))) 

    // Redirect root path ไปที่ /login
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        http.Redirect(w, r, "/login", http.StatusFound)
    })

    // Routes
    http.HandleFunc("/login", handlers.LoginHandler)
    http.HandleFunc("/register", handlers.RegisterHandler)
    http.Handle("/admin", handlers.CheckLogin(http.HandlerFunc(handlers.AdminHandler))) 
    http.Handle("/users", handlers.CheckLogin(http.HandlerFunc(handlers.ListUsersHandler))) 
    http.Handle("/user/create", handlers.CheckLogin(http.HandlerFunc(handlers.CreateUserHandler))) 
    http.Handle("/user/edituser", handlers.CheckLogin(http.HandlerFunc(handlers.EditUserHandler))) 
    http.Handle("/user/edit", handlers.CheckLogin(http.HandlerFunc(handlers.EditadminHandler))) 
    http.Handle("/user/delete", handlers.CheckLogin(http.HandlerFunc(handlers.DeleteUserHandler))) 
    http.HandleFunc("/logout", handlers.LogoutHandler)

    log.Println("Server started!!")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
