package routes

import (
	"golang_API/handlers"

	"github.com/gorilla/mux"
)

// RegisterRoutes registers all API routes
func RegisterRoutes(r *mux.Router) {
	// Problem routes
	r.HandleFunc("/problemEntry/reportProblem", handlers.ReportProblemHandler).Methods("POST")
	r.HandleFunc("/problemEntry/solveProblem", handlers.SolveProblemHandler).Methods("PUT")
	r.HandleFunc("/problemEntry/problems", handlers.GetProblemsHandler).Methods("GET")
	r.HandleFunc("/problemEntry/problem/{id}", handlers.GetProblemByIDHandler).Methods("GET")
	r.HandleFunc("/problemEntry/problem/{id}", handlers.UpdateProblemHandler).Methods("PUT")
	r.HandleFunc("/problemEntry/problem/{id}", handlers.DeleteProblemHandler).Methods("DELETE")
	r.HandleFunc("/problemEntry/problem/{id}/reset-solution", handlers.ResetSolutionHandler).Methods("PUT")
	r.HandleFunc("/problemEntry/problem/{id}/update-solution", handlers.UpdateSolutionHandler).Methods("PUT")
	r.HandleFunc("/problemEntry/problem/{id}/update-problem", handlers.UpdateProblemANDSolveProblemHandler).Methods("PUT")
	r.HandleFunc("/problemEntry/problem/{id}/delete-solution", handlers.DeleteProblemandSolveProblemHandler).Methods("DELETE")

	// Branch office routes
	r.HandleFunc("/branchEntry/branchOffice", handlers.AddBranchOfficeHandler).Methods("POST")
	r.HandleFunc("/branchEntry/branchOffice/{ip_phone}", handlers.UpdateBranchOfficeHandler).Methods("PUT")
	r.HandleFunc("/branchEntry/branchOffice/{ip_phone}", handlers.DeleteBranchOfficeHandler).Methods("DELETE")
	r.HandleFunc("/branchEntry/branchOffices", handlers.GetBranchOfficesHandler).Methods("GET")

	// User routes
	r.HandleFunc("/userEntry/user", handlers.AddUserHandler).Methods("POST")
	r.HandleFunc("/userEntry/users", handlers.GetUsersHandler).Methods("GET")

	// Program routes
	r.HandleFunc("/programEntry/program", handlers.AddProgramHandler).Methods("POST")
	r.HandleFunc("/programEntry/programs", handlers.GetProgramsHandler).Methods("GET")
	r.HandleFunc("/programEntry/program/{id}", handlers.UpdateProgramHandler).Methods("PUT")
	r.HandleFunc("/programEntry/program/{id}", handlers.DeleteProgramHandler).Methods("DELETE")

	// Delete all data routes
	r.HandleFunc("/problemEntry/deleteAllProblems", handlers.DeleteAllProblemsHandler).Methods("DELETE")
	r.HandleFunc("/branchEntry/deleteAllBranchOffices", handlers.DeleteAllBranchOfficesHandler).Methods("DELETE")
	r.HandleFunc("/programEntry/deleteAllPrograms", handlers.DeleteAllProgramsHandler).Methods("DELETE")

	// Dashboard routes
	r.HandleFunc("/dashboardEntry/dashboard", handlers.GetDashboardDataHandler).Methods("GET")

	r.HandleFunc("/healthEntry/health", handlers.HealthCheckHandler).Methods("GET")
}

// RegisterAuthRoutes registers all authentication-related routes
func RegisterAuthRoutes(r *mux.Router) {
	// Authentication routes
	r.HandleFunc("/authEntry/login", handlers.LoginHandler).Methods("POST")
	r.HandleFunc("/authEntry/registerUser", handlers.RegisterHandler("user")).Methods("POST")
	r.HandleFunc("/authEntry/registerAdmin", handlers.RegisterHandler("admin")).Methods("POST")
	r.HandleFunc("/authEntry/updateUser", handlers.UpdateUserHandler).Methods("PUT")
	r.HandleFunc("/authEntry/deleteUser", handlers.DeleteUserHandler).Methods("DELETE")
	r.HandleFunc("/authEntry/logout", handlers.LogoutHandler).Methods("POST")
}
