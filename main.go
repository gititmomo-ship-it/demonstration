package main

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"time"

	yara "github.com/VirusTotal/yara-x/go"
)

// loadCompilerFromDir takes all rules from a folder, and returns a compiler with all the rules loaded.
func loadCompilerFromDir(dir string) (*yara.Compiler, error) {
	compiler, _ := yara.NewCompiler()

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (filepath.Ext(path) == ".yar" || filepath.Ext(path) == ".yara") {
			source, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read %s: %w", path, err)
			}
			compiler.AddSource(string(source))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return compiler, nil
}

func main() {
	rulesDir := "./rules/"

	fmt.Println("The program is empty. The compiler should start contruction in 5 seconds.")
	time.Sleep(10 * time.Second)

	compiler, err := loadCompilerFromDir(rulesDir)
	if err != nil {
		log.Fatalf("Error loading rules: %v", err)
	}
	fmt.Println("Compiler is created, should destroy compiler in 10 seconds")
	time.Sleep(10 * time.Second)

	fmt.Println("compiler destroyed")
	compiler.Destroy()
	time.Sleep(20 * time.Second)
}
