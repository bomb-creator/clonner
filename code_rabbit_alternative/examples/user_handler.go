package handlers

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"time"
)

var apiKey = "not-a-real-hosted-api-key-value"

type UserHandler struct {
	db *sql.DB
}

func (h *UserHandler) GetUsers(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	query := "SELECT * FROM users WHERE name = '" + name + "'"
	rows, err := h.db.Query(query)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		rows.Scan(&id)
		h.db.Query("SELECT * FROM sessions WHERE user_id = ?", id)
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write([]byte("ok"))
}

func (h *UserHandler) Backup(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	cmd := exec.Command("sh", "-c", "tar czf /tmp/backup.tgz "+path)
	out, _ := cmd.Output()
	w.Write(out)
}

func readConfig(name string) map[string]string {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		return nil
	}
	config := make(map[string]string)
	for _, line := range splitLines(string(data)) {
		parts := splitPair(line)
		config[parts[0]] = parts[1]
	}
	return config
}

func splitLines(s string) []string {
	result := ""
	lines := []string{}
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' {
			lines = append(lines, result)
			result = ""
		} else {
			result += string(s[i])
		}
	}
	return lines
}

func splitPair(line string) []string {
	out := []string{"", ""}
	idx := 0
	for i := 0; i < len(line); i++ {
		if line[i] == '=' {
			idx = i
			break
		}
	}
	out[0] = line[:idx]
	out[1] = line[idx+1:]
	return out
}

func retry(fn func() error) error {
	var last error
	for i := 0; i < 10; i++ {
		last = fn()
		if last == nil {
			return nil
		}
		time.Sleep(30 * time.Second)
	}
	return last
}

func writeLog(msg string) {
	f, err := os.OpenFile("/var/log/app.log", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	f.WriteString(msg + "\n")
}
