package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var (
	db          *sql.DB
	currentUser *User // Variable globale pour stocker l'utilisateur connecté
)

func init() {
	initDB()
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./db/db.sqlite")
	if err != nil {
		log.Fatal(err)
	}

	createTableUsers := `
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE
        );
    `
	createTableCategories := `
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );
    `

	if _, err = db.Exec(createTableUsers); err != nil {
		log.Fatal(err)
	}

	if _, err = db.Exec(createTableCategories); err != nil {
		log.Fatal(err)
	}
}

type User struct {
	ID       int
	Email    string
	Password string
	Username string
	LoggedIn bool
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

type registerHandler struct{}

func (h *registerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		tmpl, err := template.ParseFiles("tmpl/register.html")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Println("Error parsing template:", err)
			return
		}
		tmpl.Execute(w, nil)
	case "POST":
		email := r.FormValue("email")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirmPassword")
		username := r.FormValue("username")

		// Vérification de la correspondance des mots de passe
		if password != confirmPassword {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"passwordError": "Passwords do not match"})
			return
		}

		// Vérification si l'email ou le nom d'utilisateur existe déjà
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

		// Gestion des erreurs enregistrées
		errors := make(map[string]string)
		if emailExists {
			errors["emailError"] = "Email address already used"
		}
		if usernameExists {
			errors["usernameError"] = "Username already used"
		}
		if len(errors) > 0 {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(errors)
			return
		}

		// Hachage du mot de passe
		hashedPassword, err := hashPassword(password)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"formError": "Internal Server Error"})
			log.Println("Error hashing password:", err)
			return
		}

		// Insertion du nouvel utilisateur dans la base de données
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

		// Enregistrement réussi
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully", "redirect": "/login"})
	}
}

type loginHandler struct{}

func (h *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		tmpl, err := template.ParseFiles("tmpl/login.html")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Println("Error parsing template:", err)
			return
		}
		tmpl.Execute(w, nil)
	case "POST":
		login := r.FormValue("login")
		password := r.FormValue("password")

		var dbPassword, email, username string
		err := db.QueryRow("SELECT password, email, username FROM users WHERE email = ? OR username = ?", login, login).Scan(&dbPassword, &email, &username)
		if err != nil {
			if err == sql.ErrNoRows {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"formError": "User not found"})
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"formError": "Internal Server Error"})
				log.Println("Error querying user:", err)
			}
			return
		}

		if checkPasswordHash(password, dbPassword) {
			currentUser = &User{
				Email:    email,
				Username: username,
				LoggedIn: true,
			}
			w.WriteHeader(http.StatusOK)
			// Retourne "/home" comme URL de redirection
			json.NewEncoder(w).Encode(map[string]string{"message": fmt.Sprintf("Welcome, %s!", username), "redirect": "/home"})
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"formError": "Invalid credentials"})
		}
	}
}

type homeHandler struct{}

func (h *homeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("tmpl/home.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error parsing template:", err)
		return
	}

	// Récupérer les catégories depuis la base de données
	categories, err := getCategories()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error retrieving categories:", err)
		return
	}

	// Vérifie l'état de connexion de l'utilisateur
	if currentUser != nil && currentUser.LoggedIn {
		tmpl.Execute(w, map[string]interface{}{
			"LoggedIn":   true,
			"Username":   currentUser.Username,
			"Categories": categories,
		})
	} else {
		tmpl.Execute(w, map[string]interface{}{
			"LoggedIn":   false,
			"Categories": categories,
		})
	}
}

func getCategories() ([]Category, error) {
	rows, err := db.Query("SELECT id, name FROM categories")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var categories []Category
	for rows.Next() {
		var category Category
		if err := rows.Scan(&category.ID, &category.Name); err != nil {
			return nil, err
		}
		categories = append(categories, category)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return categories, nil
}

type profileHandler struct{}

func (h *profileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if currentUser != nil && currentUser.LoggedIn {
		tmpl, err := template.ParseFiles("tmpl/profile.html")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Println("Error parsing template:", err)
			return
		}
		tmpl.Execute(w, map[string]interface{}{
			"Username": currentUser.Username,
			"Email":    currentUser.Email,
		})
	} else {
		// Si l'utilisateur n'est pas connecté, rediriger vers la page de connexion
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

type logoutHandler struct{}

func (h *logoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Supprimer l'état de connexion (ex: currentUser = nil)
	currentUser = nil
	// Rediriger vers la page d'accueil
	http.Redirect(w, r, "/home", http.StatusSeeOther)
}

type Category struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type saveCategoryRequest struct {
	CategoryName string `json:"categoryName"`
}

type saveCategoryResponse struct {
	Message string `json:"message"`
}

func saveCategoryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req saveCategoryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		log.Println("Error decoding request:", err)
		return
	}

	// Vérifier si la catégorie existe déjà
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM categories WHERE name=?)", req.CategoryName).Scan(&exists)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error checking existing category:", err)
		return
	}

	if exists {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "Category already exists"})
		return
	}

	// Insérer la nouvelle catégorie dans la base de données
	stmt, err := db.Prepare("INSERT INTO categories (name) VALUES (?)")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error preparing SQL statement:", err)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(req.CategoryName)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error executing SQL statement:", err)
		return
	}

	// Répondre avec un message de succès
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(saveCategoryResponse{
		Message: "Category saved successfully",
	})
}

type CategoryPageHandler struct{}

func (h *CategoryPageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Récupérer l'ID de la catégorie à partir de l'URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 3 {
		http.Error(w, "Category not found", http.StatusBadRequest)
		return
	}
	categoryID := parts[2]

	// Récupérer le nom de la catégorie depuis la base de données
	var categoryName string
	err := db.QueryRow("SELECT name FROM categories WHERE id = ?", categoryID).Scan(&categoryName)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Category not found", http.StatusNotFound)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Println("Error retrieving category name:", err)
		}
		return
	}

	// Récupérer les informations de la catégorie et les afficher
	tmpl, err := template.ParseFiles("tmpl/category.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error parsing template:", err)
		return
	}

	tmpl.Execute(w, map[string]interface{}{
		"CategoryID":   categoryID,
		"CategoryName": categoryName,
	})
}

type PostInCategoryHandler struct{}

func (h *PostInCategoryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Récupérer l'ID de la catégorie à partir de l'URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 3 {
		http.Error(w, "Category not found", http.StatusBadRequest)
		return
	}
	categoryID := parts[2]

	// Rediriger l'utilisateur vers la page de la catégorie spécifiée
	http.Redirect(w, r, fmt.Sprintf("/category/%s", categoryID), http.StatusSeeOther)
}

func getCategoryID(categoryName string) (int, error) {
	var id int
	err := db.QueryRow("SELECT id FROM categories WHERE name = ?", categoryName).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func main() {
	// Gestion des fichiers statiques dans le dossier "tmpl"
	fs := http.FileServer(http.Dir("tmpl"))
	http.Handle("/tmpl/", http.StripPrefix("/tmpl/", fs))

	// Routes pour les gestionnaires d'enregistrement, de connexion et de déconnexion
	http.Handle("/home", &homeHandler{})
	http.Handle("/register", &registerHandler{})
	http.Handle("/login", &loginHandler{})
	http.Handle("/profile", &profileHandler{})
	http.Handle("/logout", &logoutHandler{})
	http.Handle("/category", &CategoryHandler{})
	http.Handle("/postInCategory/", &PostInCategoryHandler{})
	http.HandleFunc("/save-category", saveCategoryHandler)
	http.Handle("/category/", &CategoryPageHandler{})

	fmt.Println("Server is running on port 1414")
	fmt.Println("http://localhost:1414/home")
	log.Fatal(http.ListenAndServe(":1414", nil))
}
