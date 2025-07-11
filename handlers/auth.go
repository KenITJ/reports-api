package handlers

import (
	"database/sql"
	"encoding/json"
	"golang_API/db"
	"golang_API/models"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// RegisterAuthRoutes sets up all authentication-related routes
// This function registers the login and registration endpoints
func RegisterAuthRoutes(r *mux.Router) {
	r.HandleFunc("/auth/login", LoginHandler).Methods("POST")
	r.HandleFunc("/auth/registerUser", RegisterHandler("user")).Methods("POST")
	r.HandleFunc("/auth/registerAdmin", RegisterHandler("admin")).Methods("POST")
	r.HandleFunc("/auth/updateUser", UpdateUserHandler).Methods("PUT")
	r.HandleFunc("/auth/deleteUser", DeleteUserHandler).Methods("DELETE")
	r.HandleFunc("/auth/logout", LogoutHandler).Methods("POST")
}

// LoginHandler handles user login requests
// It validates username/password against the database and returns success/failure response
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse the login request from JSON body
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "❌ Invalid request", http.StatusBadRequest)
		return
	}

	// Query database for user password and role
	var password string
	var role string
	err := db.DB.QueryRow("SELECT password, role FROM users WHERE username = ?", req.Username).Scan(&password, &role)
	if err == sql.ErrNoRows {
		// User not found in database
		json.NewEncoder(w).Encode(models.LoginResponse{Success: false, Message: "❌ ไม่พบชื่อผู้ใช้นี้ในระบบ"})
		return
	} else if err != nil {
		// Database error occurred
		http.Error(w, "❌ Database error", http.StatusInternalServerError)
		return
	}

	// Compare provided password with stored password
	if req.Password != password {
		// Password doesn't match
		json.NewEncoder(w).Encode(models.LoginResponse{Success: false, Message: "❌ รหัสผ่านไม่ถูกต้อง"})
		return
	}

	// Login successful
	response := models.LoginResponse{
		Success: true,
		Message: "✅ เข้าสู่ระบบสำเร็จ",
		Role:    role,
	}
	json.NewEncoder(w).Encode(response)
}

// RegisterHandler creates a new user registration handler with specified role
// This is a closure that returns an http.HandlerFunc configured for a specific role
func RegisterHandler(role string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Parse the registration request from JSON body
		var req models.RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "❌ Invalid request", http.StatusBadRequest)
			return
		}

		// Insert new user into database with the specified role
		_, err := db.DB.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", req.Username, req.Password, role)
		if err != nil {
			// Database error occurred during insertion
			http.Error(w, "❌ Database error", http.StatusInternalServerError)
			return
		}

		// Registration successful
		json.NewEncoder(w).Encode(models.RegisterResponse{Success: true, Message: "✅ ลงทะเบียนสำเร็จ"})
	}
}

func UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req models.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "❌ Invalid request", http.StatusBadRequest)
		return
	}

	_, err := db.DB.Exec("UPDATE users SET username = ?, password = ?, role = ? WHERE id = ?", req.Username, req.Password, req.Role, req.ID)
	if err != nil {
		http.Error(w, "❌ Database error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(models.UpdateUserResponse{Success: true, Message: "✅ อัพเดตผู้ใช้สำเร็จ"})
}

func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req models.DeleteUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "❌ Invalid request", http.StatusBadRequest)
		return
	}

	_, err := db.DB.Exec("DELETE FROM users WHERE id = ?", req.ID)
	if err != nil {
		http.Error(w, "❌ Database error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(models.DeleteUserResponse{Success: true, Message: "✅ ลบผู้ใช้สำเร็จ"})
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	cookie := http.Cookie{
		Name:     "token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour * 24),
		HttpOnly: true,
	}

	http.SetCookie(w, &cookie)

	json.NewEncoder(w).Encode(models.LogoutResponse{Success: true, Message: "✅ ออกจากระบบสำเร็จ"})
}
