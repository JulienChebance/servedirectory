package main

import (
	"archive/zip"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	Log "log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const APP_VERSION string = "1.0.0"
const HTTP_TIMEOUT time.Duration = 2 * time.Minute
const LOG_MAX_FILES int = 3                 // Used for log rotation
const LOG_MAX_SIZE int64 = 10 * 1024 * 1024 // Used for log rotation
var log *Log.Logger

//go:embed index.html
var html embed.FS

// Log in a file if its path is passed as the first parameter (optionnal)
func InitLog(optionnalLogFilePath ...string) error {
	logfile := ""
	if len(optionnalLogFilePath) > 0 {
		logfile = optionnalLogFilePath[0]
	}

	var logwriter io.Writer
	var e error = nil
	logwriter = os.Stdout // Default log output
	if logfile != "" {
		fi, err := os.Stat(logfile)
		if err == nil {
			if fi.Size() > LOG_MAX_SIZE {
				// Rotate logs
				ext := filepath.Ext(logfile)
				base := logfile[0 : len(logfile)-len(ext)]
				for b := LOG_MAX_FILES - 1; b > 1; b-- {
					os.Rename(base+"."+strconv.Itoa(b-1)+ext, base+"."+strconv.Itoa(b)+ext)
				}
				os.Rename(logfile, base+".1"+ext)
			}
		} else {
			_ = os.MkdirAll(filepath.Dir(logfile), 0744)
		}
		f, err := os.OpenFile(logfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			e = err
		} else {
			logwriter = io.MultiWriter(os.Stdout, f) // Output to both console and file
		}
	}
	log = Log.New(logwriter, "", Log.Ldate|Log.Ltime|Log.LUTC)
	return e
}

// Structure required to get the response status
type StatusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *StatusResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func LogAccess(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		usr, _, _ := r.BasicAuth()
		srw := &StatusResponseWriter{ResponseWriter: w}
		h.ServeHTTP(srw, r)
		log.Println(r.RemoteAddr, usr, "\""+r.Method, r.RequestURI, r.Proto+"\"", srw.status, srw.Header().Get("Content-Length"), "\""+r.Header.Get("User-Agent")+"\"")
	})
}

func BasicAuth(h http.Handler, username string, password string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		usr, pwd, ok := r.BasicAuth()
		if (!ok && (username != "" || password != "")) ||
			(username != "" && username != usr) ||
			(password != "" && password != pwd) {
			log.Println(r.RemoteAddr, "User not authenticated")
			w.Header().Set("WWW-Authenticate", `Basic realm="Authorization Required"`)
			w.WriteHeader(401)
		} else {
			h.ServeHTTP(w, r)
		}
	})
}

func SanitizePath(path string) string {
	re := regexp.MustCompile(`\.{2,}(\\|/|$)`)
	return re.ReplaceAllString(path, ".$1")
}

type Entry struct {
	Name  string `json:"name"`
	Size  int64  `json:"size,omitempty"`
	Mtime int64  `json:"mtime,omitempty"`
	IsDir bool   `json:"dir,omitempty"`
}

func ServeDirectory(rootDirectory string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			if strings.HasSuffix(r.URL.Path, "/") && r.URL.RawQuery != "index.html" { // "/index.html" is redirected to "/". Call "/?index.html" to get this file served
				// Folder
				t, _ := template.ParseFS(html, "index.html")
				var listing []Entry
				entries, err := os.ReadDir(filepath.Join(rootDirectory, r.URL.Path))
				if err != nil {
					http.Error(w, "Not found", http.StatusNotFound)
					log.Println("Error:", err)
					return
				}
				for _, entry := range entries {
					fileInfo, err := entry.Info()
					if err == nil {
						listing = append(listing, Entry{Name: fileInfo.Name(), Size: fileInfo.Size(), Mtime: fileInfo.ModTime().Unix(), IsDir: fileInfo.IsDir()})
					}
				}
				listingJson, _ := json.Marshal(listing)
				data := struct {
					Path    template.JS
					Listing template.JS
				}{
					template.JS(r.URL.Path),
					template.JS(listingJson),
				}
				t.Execute(w, data)
			} else {
				// File
				name := r.URL.Path
				if r.URL.RawQuery == "index.html" {
					name += "index.html"
				}
				log.Println("Serve file:", name)
				w.Header().Set("Content-Disposition", "attachment; filename="+path.Base(name))
				http.ServeFile(w, r, filepath.Join(rootDirectory, name))
			}
		} else if r.Method == "POST" && r.ContentLength > 0 {
			// Zip
			var files []string
			err := json.NewDecoder(r.Body).Decode(&files)
			defer r.Body.Close()
			if err != nil {
				http.Error(w, "Bad request", http.StatusBadRequest)
				log.Println("Error:", err)
				return
			}
			log.Println("Zip files:", files)

			buf := new(bytes.Buffer)
			zw := zip.NewWriter(buf)

			err = os.Chdir(SanitizePath(filepath.Join(rootDirectory, r.URL.Path))) // zip has to work with relative path
			if err != nil {
				http.Error(w, "Not found", http.StatusNotFound)
				log.Println("Error:", err)
				return
			}

			for _, file := range files {
				walker := func(path string, d fs.DirEntry, err error) error {
					log.Printf("Crawling: %#v\n", path)
					if err != nil {
						return err
					}
					if d.IsDir() {
						return nil
					}
					file, err := os.Open(path)
					if err != nil {
						return err
					}
					defer file.Close()

					f, err := zw.Create(path)
					if err != nil {
						return err
					}

					_, err = io.Copy(f, file)
					if err != nil {
						return err
					}

					return nil
				}
				err = filepath.WalkDir(SanitizePath(file), walker)
				if err != nil {
					http.Error(w, "Not found", http.StatusNotFound)
					log.Println("Error:", err)
					return
				}
			}

			zipname := path.Base(r.URL.Path)
			if len(files) == 1 {
				zipname = files[0]
			} else if zipname == "/" {
				zipname = "root"
			}
			err = zw.Close()
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				log.Println("Error:", err)
				return
			}
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Disposition", "attachment; filename="+zipname+".zip")
			w.Write(buf.Bytes())
			log.Println("Zip file size:", buf.Len())
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "%s - %s\nMIT License - Copyright (c) 2021 Julien CHEBANCE\n\nUsage:\n", filepath.Base(os.Args[0]), APP_VERSION)
		flag.PrintDefaults()
	}
	credentials := flag.String("c", "", "\b\b")
	flag.StringVar(credentials, "credentials", "", "Add Basic Authentication (credentials should be in the username:password format)\n")
	directory := flag.String("d", "", "\b\b")
	flag.StringVar(directory, "directory", "", "Directory to serve\nBy default, the current directory is used\n")
	logfile := flag.String("l", "", "\b\b")
	flag.StringVar(logfile, "logfile", "", "Optional log file\n")
	port := flag.Int("p", 0, "\b\b\b\b\b\b")
	flag.IntVar(port, "port", 0, "Bind to a specific port\nBy default, a random port is used\n")
	secured := flag.Bool("s", false, "\b\b")
	flag.BoolVar(secured, "secured", false, "Create a secured (HTTPS) server\n")

	flag.Parse()

	if InitLog(*logfile) != nil {
		log.Println("Warning: can't log to specified file")
	}

	if *directory == "" {
		*directory = "."
	}
	rootDirectory, err := filepath.Abs(*directory)
	if err != nil {
		log.Fatal("Error: can't serve this directory")
	}

	if *port == 80 && *secured {
		log.Println("Warning: can't use port 80 for a secure connection")
		*port = 0
	} else if *port == 443 && !*secured {
		log.Println("Warning: can't use port 443 for an unsecure connection")
		*port = 0
	} else if *port != 0 && *port < 1024 && *port != 80 && *port != 443 {
		log.Printf("Warning: can't use port %d as it is a reserved port\n", *port)
		*port = 0
	}
	// If the port is not specified, find any available port
	if *port == 0 {
		listener, err := net.Listen("tcp", ":0")
		if err != nil {
			log.Fatal("Error: can't find any available port")
		}
		*port = listener.Addr().(*net.TCPAddr).Port
		listener.Close()
	}

	var username, password string
	if *credentials != "" {
		if strings.Count(*credentials, ":") != 1 {
			log.Println("Warning: credentials are not in the expected format and thus won't be used")
		} else {
			username, password = strings.Split(*credentials, ":")[0], strings.Split(*credentials, ":")[1]
		}
	}

	var srv http.Server
	srv.Addr = ":" + strconv.Itoa(*port)
	http.Handle("/", http.TimeoutHandler(LogAccess(BasicAuth(ServeDirectory(rootDirectory), username, password)), HTTP_TIMEOUT, "Timeout"))

	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint

		// We received an interrupt signal, shut down.
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			log.Printf("HTTP server Shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()

	log.Printf("Serve \"%s\" on port %d\n", rootDirectory, *port)
	if *secured {
		log.Fatal(srv.ListenAndServeTLS("./cert.pem", "./key.pem"))
	} else {
		log.Fatal(srv.ListenAndServe())
	}

	<-idleConnsClosed
}
