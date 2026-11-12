package unzip

import (
	"archive/zip"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	securejoin "github.com/cyphar/filepath-securejoin"
)

func unzipVulnerable(archive, target string) error {
	reader, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(target, 0750); err != nil {
		return err
	}

	for _, file := range reader.File {
		path := filepath.Join(target, file.Name)
		// ruleid: path-traversal-inside-zip-extraction
		os.MkdirAll(path, 0750)

		fileReader, err := file.Open()
		if err != nil {
			return err
		}
		defer fileReader.Close()

		// ruleid: path-traversal-inside-zip-extraction
		targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return err
		}
		defer targetFile.Close()

		if _, err := io.Copy(targetFile, fileReader); err != nil {
			return err
		}
	}

	return nil
}

func unzipCreate(archive, target string) error {
	reader, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}

	for _, file := range reader.File {
		path := filepath.Join(target, file.Name)
		// ruleid: path-traversal-inside-zip-extraction
		out, err := os.Create(path)
		if err != nil {
			return err
		}
		defer out.Close()

		rc, err := file.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		_, err = io.Copy(out, rc)
		return err
	}
}

func unzipWriteFile(archive string, rc *zip.ReadCloser, target string) error {
	for _, file := range rc.File {
		rc2, err := file.Open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(rc2)
		if err != nil {
			return err
		}
		path := filepath.Join(target, file.FileHeader.Name)
		// ruleid: path-traversal-inside-zip-extraction
		if err := os.WriteFile(path, data, 0600); err != nil {
			return err
		}
	}

	return nil
}

func unzipMkdirOnly(reader *zip.ReadCloser, target string) error {
	for _, f := range reader.File {
		dest := filepath.Join(target, f.Name)
		// ruleid: path-traversal-inside-zip-extraction
		if err := os.Mkdir(dest, f.Mode()); err != nil {
			return err
		}
	}
	return nil
}

func unzipRename(reader *zip.ReadCloser, target, staging string) error {
	for _, f := range reader.File {
		dest := filepath.Join(target, f.Name)
		// ruleid: path-traversal-inside-zip-extraction
		if err := os.Rename(staging, dest); err != nil {
			return err
		}
	}
	return nil
}

func unzipSanitized(archive, target string) error {
	reader, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(target, 0750); err != nil {
		return err
	}

	for _, file := range reader.File {
		path := filepath.Join(target, file.Name)
		path = filepath.Clean(path)
		// ok: path-traversal-inside-zip-extraction
		if !strings.HasPrefix(path, target) {
			return fmt.Errorf("illegal file path: %s", path)
		}

		if file.FileInfo().IsDir() {
			// ok: path-traversal-inside-zip-extraction
			os.MkdirAll(path, file.Mode())
			continue
		}

		fileReader, err := file.Open()
		if err != nil {
			return err
		}
		defer fileReader.Close()

		// ok: path-traversal-inside-zip-extraction
		targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return err
		}
		defer targetFile.Close()

		if _, err := io.Copy(targetFile, fileReader); err != nil {
			return err
		}
	}

	return nil
}

func unzipSanitizedSeparator(reader *zip.ReadCloser, target string) error {
	for _, f := range reader.File {
		dest := filepath.Clean(filepath.Join(target, f.Name))
		// ok: path-traversal-inside-zip-extraction
		if !strings.HasPrefix(dest, target+string(filepath.Separator)) {
			return fmt.Errorf("illegal file path: %s", dest)
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(rc)
		if err != nil {
			return err
		}
		// ok: path-traversal-inside-zip-extraction
		if err := os.WriteFile(dest, data, 0600); err != nil {
			return err
		}
	}
	return nil
}

func unzipRelCheck(reader *zip.ReadCloser, target string) error {
	for _, f := range reader.File {
		dest := filepath.Join(target, f.Name)
		rel, err := filepath.Rel(target, dest)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("illegal file path: %s", dest)
		}

		// ok: path-traversal-inside-zip-extraction
		out, err := os.Create(dest)
		if err != nil {
			return err
		}
		defer out.Close()
	}
	return nil
}

func unzipSecureJoin(reader *zip.ReadCloser, target string) error {
	for _, f := range reader.File {
		// ok: path-traversal-inside-zip-extraction
		dest, err := securejoin.SecureJoin(target, f.Name)
		if err != nil {
			return err
		}
		out, err := os.Create(dest)
		if err != nil {
			return err
		}
		defer out.Close()
	}
	return nil
}

func unzip_good() {
	// Open a zip archive for reading.
	r, err := zip.OpenReader("testdata/readme.zip")
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()
	// Iterate through the files in the archive,
	// printing some of their contents.
	for _, f := range r.File {
		fmt.Printf("Contents of %s:\n", f.Name)
		rc, err := f.Open()
		if err != nil {
			log.Fatal(err)
		}
		_, err = io.CopyN(os.Stdout, rc, 68)
		if err != nil {
			log.Fatal(err)
		}
		rc.Close()
		fmt.Println()
	}
	// Output:
	// Contents of README:
	// This is the source code repository for the Go programming language.
}
