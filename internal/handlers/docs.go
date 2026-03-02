package handlers

import (
	"bytes"
	"embed"
	"net/http"
	"regexp"

	bf "github.com/russross/blackfriday/v2"

	"github.com/gin-gonic/gin"
	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/templates"
)

// docsMeta defines the ordered list of documentation pages.
var docsMeta = []struct {
	Slug  string
	Title string
}{
	{"getting-started", "Getting Started"},
	{"device-flow", "Device Flow"},
	{"auth-code-flow", "Auth Code Flow"},
}

// parsedDoc holds the pre-rendered HTML for a single documentation page.
type parsedDoc struct {
	Slug  string
	Title string
	HTML  string
}

// DocsHandler serves static documentation pages rendered from embedded Markdown.
type DocsHandler struct {
	pages   []parsedDoc
	pageMap map[string]parsedDoc
}

// NewDocsHandler reads and pre-parses all Markdown documentation files at startup.
func NewDocsHandler(templatesFS embed.FS) *DocsHandler {
	h := &DocsHandler{
		pageMap: make(map[string]parsedDoc, len(docsMeta)),
	}

	for _, meta := range docsMeta {
		path := "internal/templates/docs/" + meta.Slug + ".md"

		mdBytes, err := templatesFS.ReadFile(path)
		if err != nil {
			// Non-fatal: page will be missing from the map and sidebar
			continue
		}

		htmlBytes := bf.Run(
			mdBytes,
			bf.WithExtensions(bf.CommonExtensions|bf.AutoHeadingIDs|bf.HardLineBreak),
		)

		doc := parsedDoc{
			Slug:  meta.Slug,
			Title: meta.Title,
			HTML:  postProcessMermaid(htmlBytes),
		}

		h.pages = append(h.pages, doc)
		h.pageMap[meta.Slug] = doc
	}

	return h
}

// ShowDocsIndex redirects to the first documentation page.
func (h *DocsHandler) ShowDocsIndex(c *gin.Context) {
	if len(h.pages) == 0 {
		c.Redirect(http.StatusFound, "/")
		return
	}

	c.Redirect(http.StatusFound, "/docs/"+h.pages[0].Slug)
}

// ShowDocsPage renders a single documentation page identified by :slug.
func (h *DocsHandler) ShowDocsPage(c *gin.Context) {
	slug := c.Param("slug")

	doc, ok := h.pageMap[slug]
	if !ok {
		// Unknown slug → redirect to first page
		if len(h.pages) > 0 {
			c.Redirect(http.StatusFound, "/docs/"+h.pages[0].Slug)
		} else {
			c.Redirect(http.StatusFound, "/")
		}
		return
	}

	// Build sidebar entries, marking the active page
	entries := make([]templates.DocsEntry, len(h.pages))
	for i, p := range h.pages {
		entries[i] = templates.DocsEntry{
			Slug:     p.Slug,
			Title:    p.Title,
			IsActive: p.Slug == slug,
		}
	}

	// Resolve optional navbar props from session
	navbarProps := templates.NavbarProps{
		ActiveLink: "docs",
	}

	if u, exists := c.Get("user"); exists {
		if user, ok := u.(*models.User); ok {
			navbarProps.Username = user.Username
			navbarProps.IsAdmin = user.IsAdmin()
		}
	}

	templates.RenderTempl(c, http.StatusOK, templates.DocsPage(templates.DocsPageProps{
		NavbarProps: navbarProps,
		Title:       doc.Title,
		ContentHTML: doc.HTML,
		Entries:     entries,
	}))
}

// mermaidPattern matches <pre><code class="language-mermaid">…</code></pre> blocks
// produced by blackfriday from fenced ```mermaid code blocks.
var mermaidPattern = regexp.MustCompile(
	`<pre><code class="language-mermaid">([\s\S]*?)</code></pre>`,
)

// postProcessMermaid converts blackfriday-rendered mermaid code fences into
// <div class="mermaid"> elements that mermaid.js can pick up and render.
func postProcessMermaid(html []byte) string {
	replaced := mermaidPattern.ReplaceAllFunc(html, func(match []byte) []byte {
		// Extract the inner content (everything between the <code> tags)
		sub := mermaidPattern.FindSubmatch(match)
		if len(sub) < 2 {
			return match
		}

		inner := bytes.TrimSpace(sub[1])
		var buf bytes.Buffer
		buf.WriteString(`<div class="mermaid">`)
		buf.Write(inner)
		buf.WriteString(`</div>`)
		return buf.Bytes()
	})

	return string(replaced)
}
