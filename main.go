package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "./userdb.sqlite")
	if err != nil {
		log.Fatal(err)
	}

	createTable := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        username TEXT NOT NULL UNIQUE
    );`
	if _, err = db.Exec(createTable); err != nil {
		log.Fatal(err)
	}
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		email := r.FormValue("email")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirmPassword")
		username := r.FormValue("username")

		// Vérifiez que les mots de passe correspondent
		if password != confirmPassword {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"passwordError": "Passwords do not match"})
			return
		}

		// Vérifiez si l'utilisateur ou l'email existe déjà
		var emailExists, usernameExists bool
		err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email=?)", email).Scan(&emailExists)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"formError": "Internal Server Error"})
			log.Println("Error checking existing email:", err)
			return
		}
		err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username=?)", username).Scan(&usernameExists)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"formError": "Internal Server Error"})
			log.Println("Error checking existing username:", err)
			return
		}

		errors := make(map[string]string)
		if emailExists {
			errors["emailError"] = "Email already taken"
		}
		if usernameExists {
			errors["usernameError"] = "Username already taken"
		}
		if len(errors) > 0 {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(errors)
			return
		}

		hashedPassword, err := hashPassword(password)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"formError": "Internal Server Error"})
			log.Println("Error hashing password:", err)
			return
		}

		stmt, err := db.Prepare("INSERT INTO users (email, password, username) VALUES (?, ?, ?)")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"formError": "Internal Server Error"})
			log.Println("Error preparing SQL statement:", err)
			return
		}
		defer stmt.Close()

		_, err = stmt.Exec(email, hashedPassword, username)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"formError": "Internal Server Error"})
			log.Println("Error executing SQL statement:", err)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
	} else {
		tmpl, err := template.ParseFiles("register.html")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Println("Error parsing template:", err)
			return
		}
		tmpl.Execute(w, nil)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		email := r.FormValue("email")
		password := r.FormValue("password")

		var dbPassword, username string
		err := db.QueryRow("SELECT password, username FROM users WHERE email = ?", email).Scan(&dbPassword, &username)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "User not found", http.StatusUnauthorized)
			} else {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				log.Println("Error querying user:", err)
			}
			return
		}

		if checkPasswordHash(password, dbPassword) {
			fmt.Fprintf(w, "Welcome, %s!", username)
		} else {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		}
	} else {
		tmpl, err := template.ParseFiles("login.html")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Println("Error parsing template:", err)
			return
		}
		tmpl.Execute(w, nil)
	}
}

func main() {
	initDB()
	defer db.Close()

	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	fmt.Println("Server is running on port 8080")
	fmt.Println("http://localhost:8080/register?")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
