package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildDocsTestFS constructs an in-memory templates filesystem populated with
// stub Markdown for every (locale, slug) pair defined in DocsMeta. Each stub
// embeds the locale code and slug in its heading so assertions can tell them
// apart after Markdown rendering.
func buildDocsTestFS(t *testing.T, omit ...string) fstest.MapFS {
	t.Helper()
	skip := make(map[string]struct{}, len(omit))
	for _, p := range omit {
		skip[p] = struct{}{}
	}

	m := fstest.MapFS{}
	for _, loc := range DocsSupportedLocales {
		for _, meta := range DocsMeta {
			path := docsFilePath(loc, meta.Slug)
			if _, ok := skip[path]; ok {
				continue
			}
			m[path] = &fstest.MapFile{
				Data: []byte("# " + string(loc) + ":" + meta.Slug + "\n\nbody\n"),
			}
		}
	}
	return m
}

// newTestDocsHandler builds a handler backed by buildDocsTestFS with
// secureCookies=false so tests don't have to repeat the constructor args.
func newTestDocsHandler(t *testing.T, omit ...string) *DocsHandler {
	t.Helper()
	return NewDocsHandler(buildDocsTestFS(t, omit...), false)
}

// TestDocsMetaLocaleParity — CI-friendly guard: every entry in DocsMeta must
// declare a title for every supported locale. Catches missing translations
// before they reach production.
func TestDocsMetaLocaleParity(t *testing.T) {
	for _, meta := range DocsMeta {
		for _, loc := range DocsSupportedLocales {
			title, ok := meta.Titles[loc]
			assert.Truef(t, ok, "slug %q is missing title for locale %q", meta.Slug, loc)
			assert.NotEmptyf(t, title, "slug %q has empty title for locale %q", meta.Slug, loc)
		}
	}
}

// TestDocsSupportedLocalesStringsDefined — every supported locale must have a
// corresponding entry in docsStringsByLocale, otherwise the sidebar title and
// switcher labels silently fall back to the default locale.
func TestDocsSupportedLocalesStringsDefined(t *testing.T) {
	for _, loc := range DocsSupportedLocales {
		s, ok := docsStringsByLocale[loc]
		require.Truef(t, ok, "locale %q has no docsStrings entry", loc)
		assert.NotEmptyf(t, s.SidebarTitle, "locale %q has empty SidebarTitle", loc)
		assert.NotEmptyf(t, s.LangSwitcherLabel, "locale %q has empty LangSwitcherLabel", loc)
	}
}

func TestMatchLocaleTag(t *testing.T) {
	cases := []struct {
		in        string
		wantLoc   Locale
		wantMatch bool
	}{
		{"en", LocaleEN, true},
		{"EN", LocaleEN, true},
		{"en-US", LocaleEN, true},
		{"en-gb", LocaleEN, true},
		{"zh-TW", LocaleZHTW, true},
		{"zh-tw", LocaleZHTW, true},
		{"zh_TW", LocaleZHTW, true},
		{"zh", LocaleZHTW, true},
		{"zh-Hant", LocaleZHTW, true},
		{"zh-Hant-TW", LocaleZHTW, true},
		{"zh-HK", LocaleZHTW, true},
		{"zh-MO", LocaleZHTW, true},
		{"fr", "", false},
		{"", "", false},
		{"   ", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			loc, ok := matchLocaleTag(tc.in)
			assert.Equal(t, tc.wantMatch, ok)
			if tc.wantMatch {
				assert.Equal(t, tc.wantLoc, loc)
			}
		})
	}
}

// TestExactLocaleTag — BCP-47 language tags are case-insensitive, so the
// /docs/:lang/:slug route accepts any casing of a supported locale code. It
// must still reject aliases ("zh", "zh-Hant") and bare words so the router
// doesn't paper over typos; canonicalisation to the preferred casing happens
// in ShowDocsPage via a 301 redirect, covered separately below.
func TestExactLocaleTag(t *testing.T) {
	cases := []struct {
		in     string
		wantOK bool
		want   Locale
	}{
		{"en", true, LocaleEN},
		{"EN", true, LocaleEN},
		{"En", true, LocaleEN},
		{"zh-TW", true, LocaleZHTW},
		{"zh-tw", true, LocaleZHTW},
		{"ZH-TW", true, LocaleZHTW},
		{"Zh-Tw", true, LocaleZHTW},
		{"zh", false, ""},      // alias, not an exact code
		{"zh-Hant", false, ""}, // alias, not an exact code
		{"", false, ""},
		{"getting-started", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := exactLocaleTag(tc.in)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestParseAcceptLanguage(t *testing.T) {
	cases := []struct {
		header  string
		wantLoc Locale
		wantOK  bool
	}{
		{"zh-TW,zh;q=0.9,en;q=0.7", LocaleZHTW, true},
		{"en-US,en;q=0.9", LocaleEN, true},
		{"fr-FR,de;q=0.9,en;q=0.5", LocaleEN, true},
		{"fr-FR,de;q=0.9", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.header, func(t *testing.T) {
			loc, ok := parseAcceptLanguage(tc.header)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.wantLoc, loc)
			}
		})
	}
}

// TestNewDocsHandlerLoadsEveryLocale — the handler must expose the full page
// list for every supported locale when every file is present.
func TestNewDocsHandlerLoadsEveryLocale(t *testing.T) {
	h := newTestDocsHandler(t)

	for _, loc := range DocsSupportedLocales {
		pages := h.pages[loc]
		require.Lenf(
			t,
			pages,
			len(DocsMeta),
			"locale %q has %d pages, want %d",
			loc,
			len(pages),
			len(DocsMeta),
		)

		// Titles must be the locale-specific ones from DocsMeta.
		for i, meta := range DocsMeta {
			assert.Equalf(t, meta.Titles[loc], pages[i].Title,
				"locale %q slug %q: unexpected title", loc, meta.Slug)
		}
	}
}

// TestNewDocsHandlerFallsBackToDefault — when a translation file is missing,
// the handler should still surface the page with English content so the
// sidebar stays complete.
func TestNewDocsHandlerFallsBackToDefault(t *testing.T) {
	missing := docsFilePath(LocaleZHTW, "getting-started")
	h := newTestDocsHandler(t, missing)

	got, ok := h.pageMap[LocaleZHTW]["getting-started"]
	require.True(t, ok, "zh-TW getting-started should fall back instead of disappearing")

	// Fallback body came from the en stub, not the zh-TW stub.
	assert.Contains(t, got.HTML, "en:getting-started")
	assert.NotContains(t, got.HTML, "zh-TW:getting-started")

	// Title still comes from DocsMeta, which is locale-aware.
	assert.Equal(t, "開始使用", got.Title)
}

// Locale-detection priority covers the entry points that *don't* have a
// locale in the URL: bare /docs and the legacy single-segment /docs/<slug>.

func TestResolveLocale_CookieBeatsHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newTestDocsHandler(t)

	c, _ := newDocsCtx(t, http.MethodGet, "/docs", map[string]string{
		"Accept-Language": "en-US",
		"Cookie":          docsLangCookie + "=zh-TW",
	})
	loc := h.resolveLocale(c)
	assert.Equal(t, LocaleZHTW, loc)
}

func TestResolveLocale_FallsBackToAcceptLanguage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newTestDocsHandler(t)

	c, _ := newDocsCtx(t, http.MethodGet, "/docs", map[string]string{
		"Accept-Language": "zh-TW,zh;q=0.9,en;q=0.7",
	})
	loc := h.resolveLocale(c)
	assert.Equal(t, LocaleZHTW, loc)
}

func TestResolveLocale_DefaultWhenNothingMatches(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newTestDocsHandler(t)

	c, _ := newDocsCtx(t, http.MethodGet, "/docs", map[string]string{
		"Accept-Language": "fr,de;q=0.9",
	})
	loc := h.resolveLocale(c)
	assert.Equal(t, DocsDefaultLocale, loc)
}

// Routing behavior — assert the handlers emit the right redirects and stop
// short of rendering when they should.

func TestShowDocsIndex_RedirectsToCanonicalFirstPage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newTestDocsHandler(t)

	c, w := newDocsCtx(t, http.MethodGet, "/docs", map[string]string{
		"Accept-Language": "zh-TW",
	})
	h.ShowDocsIndex(c)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/docs/zh-TW/getting-started", w.Header().Get("Location"))
}

func TestShowDocsEntry_LocaleCodeRedirectsToFirstSlug(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newTestDocsHandler(t)

	c, w := newDocsCtx(t, http.MethodGet, "/docs/zh-TW", nil)
	c.Params = gin.Params{{Key: "lang", Value: "zh-TW"}}
	h.ShowDocsEntry(c)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/docs/zh-TW/getting-started", w.Header().Get("Location"))
}

func TestShowDocsEntry_LegacySlugRedirectsToResolvedLocale(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newTestDocsHandler(t)

	c, w := newDocsCtx(t, http.MethodGet, "/docs/tokens", map[string]string{
		"Cookie": docsLangCookie + "=zh-TW",
	})
	c.Params = gin.Params{{Key: "lang", Value: "tokens"}}
	h.ShowDocsEntry(c)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/docs/zh-TW/tokens", w.Header().Get("Location"))
}

func TestShowDocsEntry_UnknownRedirectsToIndex(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newTestDocsHandler(t)

	c, w := newDocsCtx(t, http.MethodGet, "/docs/bogus", nil)
	c.Params = gin.Params{{Key: "lang", Value: "bogus"}}
	h.ShowDocsEntry(c)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/docs", w.Header().Get("Location"))
}

func TestShowDocsPage_RendersWithLocaleFromPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newTestDocsHandler(t)

	c, w := newDocsCtx(t, http.MethodGet, "/docs/zh-TW/tokens", nil)
	c.Params = gin.Params{
		{Key: "lang", Value: "zh-TW"},
		{Key: "slug", Value: "tokens"},
	}
	h.ShowDocsPage(c)

	assert.Equal(t, http.StatusOK, w.Code)

	// Cookie should be written so bare-URL visits remember the explicit choice.
	var cookieFound bool
	for _, ck := range w.Result().Cookies() {
		if ck.Name == docsLangCookie && ck.Value == string(LocaleZHTW) {
			cookieFound = true
			break
		}
	}
	assert.True(t, cookieFound, "docs_lang cookie should be set on canonical render")
}

func TestShowDocsPage_NonCanonicalCasingRedirectsToCanonical(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newTestDocsHandler(t)

	cases := []struct {
		in       string
		wantPath string
	}{
		{"zh-tw", "/docs/zh-TW/tokens"},
		{"ZH-TW", "/docs/zh-TW/tokens"},
		{"Zh-Tw", "/docs/zh-TW/tokens"},
		{"EN", "/docs/en/tokens"},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			c, w := newDocsCtx(t, http.MethodGet, "/docs/"+tc.in+"/tokens", nil)
			c.Params = gin.Params{
				{Key: "lang", Value: tc.in},
				{Key: "slug", Value: "tokens"},
			}
			h.ShowDocsPage(c)

			// 301 (permanent) so crawlers and browsers cache the canonical form.
			assert.Equal(t, http.StatusMovedPermanently, w.Code)
			assert.Equal(t, tc.wantPath, w.Header().Get("Location"))
		})
	}
}

func TestShowDocsPage_SkipsCookieWriteWhenAlreadyMatches(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newTestDocsHandler(t)

	c, w := newDocsCtx(t, http.MethodGet, "/docs/zh-TW/tokens", map[string]string{
		"Cookie": docsLangCookie + "=zh-TW",
	})
	c.Params = gin.Params{
		{Key: "lang", Value: "zh-TW"},
		{Key: "slug", Value: "tokens"},
	}
	h.ShowDocsPage(c)

	assert.Equal(t, http.StatusOK, w.Code)
	for _, ck := range w.Result().Cookies() {
		if ck.Name == docsLangCookie {
			t.Fatalf(
				"docs_lang cookie should not be rewritten when already matching; got Set-Cookie: %q",
				ck.String(),
			)
		}
	}
}

func TestShowDocsPage_UnknownLocaleInPathRedirectsHome(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newTestDocsHandler(t)

	c, w := newDocsCtx(t, http.MethodGet, "/docs/ja-JP/tokens", nil)
	c.Params = gin.Params{
		{Key: "lang", Value: "ja-JP"},
		{Key: "slug", Value: "tokens"},
	}
	h.ShowDocsPage(c)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/docs", w.Header().Get("Location"))
}

func TestShowDocsPage_UnknownSlugRedirectsToFirstOfLocale(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newTestDocsHandler(t)

	c, w := newDocsCtx(t, http.MethodGet, "/docs/zh-TW/bogus", nil)
	c.Params = gin.Params{
		{Key: "lang", Value: "zh-TW"},
		{Key: "slug", Value: "bogus"},
	}
	h.ShowDocsPage(c)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/docs/zh-TW/getting-started", w.Header().Get("Location"))
}

// newDocsCtx builds a minimal *gin.Context wired to a recorded ResponseWriter,
// suitable for exercising handler methods without a full router.
func newDocsCtx(
	t *testing.T,
	method, target string,
	headers map[string]string,
) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest(method, target, http.NoBody)
	for k, v := range headers {
		if k == "Cookie" {
			for part := range strings.SplitSeq(v, ";") {
				if kv := strings.SplitN(strings.TrimSpace(part), "=", 2); len(kv) == 2 {
					req.AddCookie(&http.Cookie{Name: kv[0], Value: kv[1]})
				}
			}
			continue
		}
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	return c, w
}
