// This program downloads the dist assets for the current swagger-ui version
//go:build ignore
// +build ignore

package swagger

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type releaseResp []struct {
	TagName string `json:"tag_name"`
}

func main() {
	log.SetFlags(0)
	var releases releaseResp
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/swagger-api/swagger-ui/releases", nil)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("error getting release list: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("got status [%s] on release list download", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		log.Fatalf("error decoding response: %v", err)
	}
	resp.Body.Close()
	if len(releases) == 0 {
		log.Fatal("somehow got no releases, nothing to do")
	}
	tag := releases[0].TagName

	log.Printf("downloading release %s...", tag)

	resp, err = http.Get(fmt.Sprintf("https://github.com/swagger-api/swagger-ui/archive/%s.tar.gz", tag))
	if err != nil {
		log.Fatalf("error downloading release archive: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("got status [%s] on release archive download", resp.Status)
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		log.Fatalf("error opening file as gzip: %v", err)
	}
	if err := os.RemoveAll("embed"); err != nil {
		log.Fatalf("error removing old embed directory")
	}
	if err := os.Mkdir("embed", 0o700); err != nil {
		log.Fatalf("error recreating embed directory")
	}
	tr := tar.NewReader(zr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("tar parsing error: %v", err)
		}
		if header.Typeflag == tar.TypeReg {
			fname := header.Name[strings.Index(header.Name, `/`):]
			if strings.HasPrefix(fname, `/dist`) {
				fname = strings.TrimPrefix(fname, `/dist`)
				out, err := os.Create(filepath.Join("embed", fname))
				if err != nil {
					log.Fatalf("error create output file: %v", err)
				}
				if _, err := io.Copy(out, tr); err != nil {
					log.Fatalf("error writing output file: %v", err)
				}
			}
		}
	}
	initFile, _ := os.ReadFile(filepath.Join("embed", "swagger-initializer.js"))
	newInit := regexp.MustCompile(`url:\s+"[^"]*"`).ReplaceAllLiteral(initFile, []byte(`url: "/swagger.json"`))
	newInit = regexp.MustCompile(`,?\s+SwaggerUIStandalonePreset.*\n`).ReplaceAllLiteral(newInit, []byte("\n"))
	newInit = regexp.MustCompile(`(?s),\s+plugins: \[.*],\n`).ReplaceAllLiteral(newInit, []byte("\n"))
	newInit = regexp.MustCompile(`\n\s*layout:.*\n`).ReplaceAllLiteral(newInit, []byte("\n"))
	newinitFile, _ := os.Create(filepath.Join("embed", "swagger-initializer.js"))
	defer newinitFile.Close()
	newinitFile.Write(newInit)
}
