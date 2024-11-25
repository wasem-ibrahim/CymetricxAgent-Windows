package ldb

import (
	"database/sql"
	"fmt"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

func InitDB() (*sql.DB, error) {
	dbPath := `C:\Program Files\CYMETRICX\`
	db, err := sql.Open("sqlite3", filepath.Join(dbPath, "cymetricx.db"))
	if err != nil {
		return nil, fmt.Errorf("error opening database: %w", err)
	}

	db.Exec("PRAGMA foreign_keys = ON;")

	err = createWindowsClientServicesTable(db)
	if err != nil {
		return nil, fmt.Errorf("error creating WindowsClientServices table: %w", err)
	}

	err = WindowsProcessTable(db)
	if err != nil {
		return nil, fmt.Errorf("error creating WindowsProcess table: %w", err)
	}

	return db, nil
}

func createWindowsClientServicesTable(db *sql.DB) error {
	query := `CREATE TABLE IF NOT EXISTS listening_services  (
        id INTEGER PRIMARY KEY,
        Port_Number INTEGER,
        Protocol TEXT,
        Service_Name TEXT,
        PID INTEGER,
        Address TEXT
    );`

	_, err := db.Exec(query)
	if err != nil {
		return err
	}

	return nil
}

func WindowsProcessTable(db *sql.DB) error {
	query := `CREATE TABLE IF NOT EXISTS processes (
        Id INTEGER PRIMARY KEY,
        Path TEXT,
        ProcessId INTEGER,
        CreationDate TEXT,
        Name TEXT,
        UserName TEXT,
        CommandLine TEXT,
        ExecutablePath TEXT
    );`

	_, err := db.Exec(query)
	if err != nil {
		return err
	}

	return nil
}
