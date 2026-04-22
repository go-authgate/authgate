package handlers

import (
	"bytes"
	"io/fs"
	"net/http"
	"regexp"
	"strings"

	bf "github.com/russross/blackfriday/v2"

	"github.com/gin-gonic/gin"
	"github.com/go-authgate/authgate/internal/templates"
)

// Locale identifies a supported documentation language.
type Locale string

const (
	LocaleEN   Locale = "en"
	LocaleZHTW Locale = "zh-TW"

	// DocsDefaultLocale is the fallback when no user preference is detectable.
	DocsDefaultLocale = LocaleEN

	docsLangCookie    = "docs_lang"
	docsLangCookieTTL = 60 * 60 * 24 * 365 // 1 year
)

// DocsSupportedLocales lists the locales the handler can serve, in the order
// they should appear in the language switcher (first entry is the default).
var DocsSupportedLocales = []Locale{LocaleEN, LocaleZHTW}

// docsMetaEntry describes a single documentation page with per-locale titles.
type docsMetaEntry struct {
	Slug   string
	Titles map[Locale]string
}

// DocsMeta defines the ordered list of documentation pages and their titles
// per locale. Exported so locale-parity tests can assert against it.
var DocsMeta = []docsMetaEntry{
	{Slug: "getting-started", Titles: map[Locale]string{
		LocaleEN:   "Getting Started",
		LocaleZHTW: "開始使用",
	}},
	{Slug: "auth-code-flow", Titles: map[Locale]string{
		LocaleEN:   "Auth Code Flow",
		LocaleZHTW: "授權碼流程",
	}},
	{Slug: "device-flow", Titles: map[Locale]string{
		LocaleEN:   "Device Flow",
		LocaleZHTW: "裝置流程",
	}},
	{Slug: "client-credentials", Titles: map[Locale]string{
		LocaleEN:   "Client Credentials",
		LocaleZHTW: "用戶端憑證",
	}},
	{Slug: "oidc", Titles: map[Locale]string{
		LocaleEN:   "OpenID Connect",
		LocaleZHTW: "OpenID Connect",
	}},
	{Slug: "jwt-verification", Titles: map[Locale]string{
		LocaleEN:   "JWT Verification",
		LocaleZHTW: "JWT 驗證",
	}},
	{Slug: "tokens", Titles: map[Locale]string{
		LocaleEN:   "Tokens & Revocation",
		LocaleZHTW: "Token 與撤銷",
	}},
	{Slug: "errors", Titles: map[Locale]string{
		LocaleEN:   "Errors",
		LocaleZHTW: "錯誤處理",
	}},
}

// docsStrings holds UI strings shown on the docs chrome (not the Markdown body), per locale.
type docsStrings struct {
	SidebarTitle      string
	LangSwitcherLabel string
	LangEnglish       string
	LangZhTW          string
}

var docsStringsByLocale = map[Locale]docsStrings{
	LocaleEN: {
		SidebarTitle:      "Documentation",
		LangSwitcherLabel: "Language",
		LangEnglish:       "English",
		LangZhTW:          "繁體中文",
	},
	LocaleZHTW: {
		SidebarTitle:      "技術文件",
		LangSwitcherLabel: "語言",
		LangEnglish:       "English",
		LangZhTW:          "繁體中文",
	},
}

// parsedDoc holds the pre-rendered HTML for a single documentation page.
type parsedDoc struct {
	Slug  string
	Title string
	HTML  string
}

// DocsHandler serves static documentation pages rendered from embedded Markdown,
// with per-locale content served from language subfolders. Sidebar entries and
// language-switcher options are precomputed at boot so each request only
// passes pointers to immutable slices into the template.
type DocsHandler struct {
	pages           map[Locale][]parsedDoc
	pageMap         map[Locale]map[string]parsedDoc
	sidebarEntries  map[Locale][]templates.DocsEntry
	switcherOptions map[Locale][]templates.DocsLocaleOption
	secureCookies   bool
}

// NewDocsHandler reads and pre-parses all Markdown documentation files, for every
// supported locale, at startup. Missing translations transparently fall back to
// the default locale so new languages can be added incrementally.
//
// The handler accepts any fs.FS; production wires the embed.FS from main, while
// tests can supply an fstest.MapFS to assert locale-parity invariants without
// reading from disk. secureCookies should be true when the server is reachable
// over HTTPS (matches middleware.SessionOptions' isProduction convention).
func NewDocsHandler(templatesFS fs.FS, secureCookies bool) *DocsHandler {
	h := &DocsHandler{
		pages:           make(map[Locale][]parsedDoc, len(DocsSupportedLocales)),
		pageMap:         make(map[Locale]map[string]parsedDoc, len(DocsSupportedLocales)),
		sidebarEntries:  make(map[Locale][]templates.DocsEntry, len(DocsSupportedLocales)),
		switcherOptions: make(map[Locale][]templates.DocsLocaleOption, len(DocsSupportedLocales)),
		secureCookies:   secureCookies,
	}

	for _, loc := range DocsSupportedLocales {
		ordered := make([]parsedDoc, 0, len(DocsMeta))
		bySlug := make(map[string]parsedDoc, len(DocsMeta))

		for _, meta := range DocsMeta {
			mdBytes, err := fs.ReadFile(templatesFS, docsFilePath(loc, meta.Slug))
			if err != nil && loc != DocsDefaultLocale {
				// Fallback to the default-locale content when a translation is missing.
				mdBytes, err = fs.ReadFile(templatesFS, docsFilePath(DocsDefaultLocale, meta.Slug))
			}
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
				Title: docsTitleFor(meta, loc),
				HTML:  postProcessMermaid(htmlBytes),
			}

			ordered = append(ordered, doc)
			bySlug[meta.Slug] = doc
		}

		h.pages[loc] = ordered
		h.pageMap[loc] = bySlug

		entries := make([]templates.DocsEntry, len(ordered))
		for i, p := range ordered {
			entries[i] = templates.DocsEntry{Slug: p.Slug, Title: p.Title}
		}
		h.sidebarEntries[loc] = entries

		strs, ok := docsStringsByLocale[loc]
		if !ok {
			strs = docsStringsByLocale[DocsDefaultLocale]
		}
		options := make([]templates.DocsLocaleOption, 0, len(DocsSupportedLocales))
		for _, l := range DocsSupportedLocales {
			options = append(options, templates.DocsLocaleOption{
				Code:  string(l),
				Label: docsLocaleLabel(l, strs),
			})
		}
		h.switcherOptions[loc] = options
	}

	return h
}

// docsFilePath returns the embedded-FS path for a given (locale, slug).
// The default locale keeps the historical flat layout; additional locales live
// under a subdirectory named after the locale code.
func docsFilePath(loc Locale, slug string) string {
	if loc == DocsDefaultLocale {
		return "internal/templates/docs/" + slug + ".md"
	}
	return "internal/templates/docs/" + string(loc) + "/" + slug + ".md"
}

func docsTitleFor(m docsMetaEntry, loc Locale) string {
	if title, ok := m.Titles[loc]; ok && title != "" {
		return title
	}
	return m.Titles[DocsDefaultLocale]
}

// ShowDocsIndex handles GET /docs. It detects the user's preferred locale and
// redirects to the canonical /docs/<locale>/<first-slug> URL so every rendered
// page has the locale explicitly in its path.
func (h *DocsHandler) ShowDocsIndex(c *gin.Context) {
	loc := h.resolveLocale(c)
	pages := h.pages[loc]
	if len(pages) == 0 {
		c.Redirect(http.StatusFound, "/")
		return
	}
	c.Redirect(http.StatusFound, docsPageURL(loc, pages[0].Slug))
}

// ShowDocsEntry handles GET /docs/:lang where the path parameter may be
// either a locale code (e.g. /docs/zh-TW → first page of zh-TW) or a legacy
// slug from the pre-i18n URL scheme (/docs/getting-started → same slug under
// the detected locale). Unknown values redirect back to /docs.
func (h *DocsHandler) ShowDocsEntry(c *gin.Context) {
	raw := c.Param("lang")

	if loc, ok := matchLocaleTag(raw); ok {
		if pages := h.pages[loc]; len(pages) > 0 {
			c.Redirect(http.StatusFound, docsPageURL(loc, pages[0].Slug))
			return
		}
	}

	if _, ok := h.pageMap[DocsDefaultLocale][raw]; ok {
		loc := h.resolveLocale(c)
		// Ensure the redirect lands somewhere that actually renders: if the
		// resolved locale lacks this slug for any reason, drop to default.
		if _, ok := h.pageMap[loc][raw]; !ok {
			loc = DocsDefaultLocale
		}
		c.Redirect(http.StatusFound, docsPageURL(loc, raw))
		return
	}

	c.Redirect(http.StatusFound, "/docs")
}

// ShowDocsPage handles GET /docs/:lang/:slug — the canonical URL. It validates
// both path parameters, renders the page, and persists the locale to a cookie
// so future bare-URL visits (/docs or /docs/<slug>) default to the same choice.
func (h *DocsHandler) ShowDocsPage(c *gin.Context) {
	langParam := c.Param("lang")
	slug := c.Param("slug")

	loc, ok := exactLocaleTag(langParam)
	if !ok {
		// Unknown locale in the URL — bounce to the detection entry so the
		// user ends up on a valid canonical URL.
		c.Redirect(http.StatusFound, "/docs")
		return
	}

	// If the URL came in with non-canonical casing (e.g. "zh-tw"), 301 to
	// the canonical form. Keeps one indexable URL per page while still being
	// forgiving of manual typing and mixed-case inbound links.
	if langParam != string(loc) {
		c.Redirect(http.StatusMovedPermanently, docsPageURL(loc, slug))
		return
	}

	pages := h.pages[loc]
	doc, ok := h.pageMap[loc][slug]
	if !ok {
		// Known locale, unknown slug → redirect to that locale's first page.
		if len(pages) > 0 {
			c.Redirect(http.StatusFound, docsPageURL(loc, pages[0].Slug))
		} else {
			c.Redirect(http.StatusFound, "/")
		}
		return
	}

	// Persist the explicit path-based choice so bare-URL visits remember it.
	// Skip when the cookie already matches: avoids a Set-Cookie header on
	// every page load, which would also bust any shared-cache heuristics.
	if current, err := c.Cookie(docsLangCookie); err != nil || current != string(loc) {
		h.setLangCookie(c, loc)
	}

	navbarProps := templates.NavbarProps{ActiveLink: "docs-" + slug}
	if user := getUserFromContext(c); user != nil {
		navbarProps.Username = user.Username
		navbarProps.FullName = user.FullName
		navbarProps.IsAdmin = user.IsAdmin()
	}

	strs, ok := docsStringsByLocale[loc]
	if !ok {
		strs = docsStringsByLocale[DocsDefaultLocale]
	}

	templates.RenderTempl(c, http.StatusOK, templates.DocsPage(templates.DocsPageProps{
		NavbarProps:   navbarProps,
		Title:         doc.Title,
		ContentHTML:   doc.HTML,
		CurrentSlug:   slug,
		Entries:       h.sidebarEntries[loc],
		Locale:        string(loc),
		SidebarTitle:  strs.SidebarTitle,
		LangLabel:     strs.LangSwitcherLabel,
		LocaleOptions: h.switcherOptions[loc],
	}))
}

// docsPageURL builds the canonical path for a given locale + slug.
func docsPageURL(loc Locale, slug string) string {
	return "/docs/" + string(loc) + "/" + slug
}

func docsLocaleLabel(l Locale, s docsStrings) string {
	switch l {
	case LocaleZHTW:
		return s.LangZhTW
	case LocaleEN:
		return s.LangEnglish
	default:
		return string(l)
	}
}

// resolveLocale detects the user's locale for URLs that don't carry one
// explicitly in the path (i.e. /docs and the legacy /docs/<slug> entry points).
// Priority:
//  1. docs_lang cookie — remembered from a previous canonical page visit.
//  2. Accept-Language header — best-effort tag matching.
//  3. DocsDefaultLocale.
//
// The canonical /docs/<lang>/<slug> route does not go through resolveLocale;
// its locale comes straight from the URL path.
func (h *DocsHandler) resolveLocale(c *gin.Context) Locale {
	if ck, err := c.Cookie(docsLangCookie); err == nil && ck != "" {
		if loc, ok := matchLocaleTag(ck); ok {
			return loc
		}
	}
	if header := c.GetHeader("Accept-Language"); header != "" {
		if loc, ok := parseAcceptLanguage(header); ok {
			return loc
		}
	}
	return DocsDefaultLocale
}

// exactLocaleTag accepts only the supported locale codes (case-insensitive).
// BCP-47 language tags are defined as case-insensitive; the canonical spelling
// (lowercase language subtag + uppercase region subtag, e.g. "zh-TW") is a
// presentation convention. ShowDocsPage uses this matcher and 301-redirects
// non-canonical casings to the canonical URL so each page still has one
// canonical form for crawlers and share links.
func exactLocaleTag(s string) (Locale, bool) {
	for _, loc := range DocsSupportedLocales {
		if strings.EqualFold(s, string(loc)) {
			return loc, true
		}
	}
	return "", false
}

func (h *DocsHandler) setLangCookie(c *gin.Context, loc Locale) {
	// httpOnly is false on purpose — nothing reads this cookie from JS, but
	// leaving it readable keeps future client-side UX (e.g. a theme-aware
	// switcher) unblocked without a server round-trip.
	c.SetCookie(docsLangCookie, string(loc), docsLangCookieTTL, "/", "", h.secureCookies, false)
}

// localeAliases maps lowercased BCP-47 tag *prefixes* to supported locales,
// so browser-sent variants resolve to the closest translation we ship.
// Keys are treated as exact matches; a trailing "-" in the key means prefix.
var localeAliases = map[string]Locale{
	"zh":       LocaleZHTW,
	"zh-hant":  LocaleZHTW,
	"zh-hant-": LocaleZHTW, // zh-Hant-TW, zh-Hant-HK, …
	"zh-hk":    LocaleZHTW,
	"zh-mo":    LocaleZHTW,
	"en":       LocaleEN,
	"en-":      LocaleEN, // en-US, en-GB, …
}

// matchLocaleTag maps a single BCP-47-style tag to a supported Locale. It
// normalises the tag (underscores → dashes, lowercased) then looks for an
// exact-case match against a canonical code, then consults the alias table
// for common regional/script variants that users' browsers send.
func matchLocaleTag(s string) (Locale, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	norm := strings.ToLower(strings.ReplaceAll(s, "_", "-"))
	if loc, ok := exactLocaleTag(norm); ok {
		return loc, true
	}
	if loc, ok := localeAliases[norm]; ok {
		return loc, true
	}
	for prefix, loc := range localeAliases {
		if strings.HasSuffix(prefix, "-") && strings.HasPrefix(norm, prefix) {
			return loc, true
		}
	}
	return "", false
}

// parseAcceptLanguage picks the first tag in an Accept-Language header that
// maps to a supported locale. q-values are intentionally ignored — browsers
// list preferred tags first, which is good enough for docs-page routing.
func parseAcceptLanguage(header string) (Locale, bool) {
	for part := range strings.SplitSeq(header, ",") {
		tag := strings.TrimSpace(part)
		if i := strings.Index(tag, ";"); i >= 0 {
			tag = strings.TrimSpace(tag[:i])
		}
		if tag == "" {
			continue
		}
		if loc, ok := matchLocaleTag(tag); ok {
			return loc, true
		}
	}
	return "", false
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
