package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPaginationParams(t *testing.T) {
	t.Run("valid_parameters", func(t *testing.T) {
		p := NewPaginationParams(3, 25, "hello")
		assert.Equal(t, 3, p.Page)
		assert.Equal(t, 25, p.PageSize)
		assert.Equal(t, "hello", p.Search)
	})

	t.Run("page_below_1_defaults_to_1", func(t *testing.T) {
		p := NewPaginationParams(0, 10, "")
		assert.Equal(t, 1, p.Page)

		p = NewPaginationParams(-5, 10, "")
		assert.Equal(t, 1, p.Page)
	})

	t.Run("page_size_below_1_defaults_to_10", func(t *testing.T) {
		p := NewPaginationParams(1, 0, "")
		assert.Equal(t, 10, p.PageSize)

		p = NewPaginationParams(1, -1, "")
		assert.Equal(t, 10, p.PageSize)
	})

	t.Run("page_size_above_50_capped_at_50", func(t *testing.T) {
		p := NewPaginationParams(1, 100, "")
		assert.Equal(t, 50, p.PageSize)

		p = NewPaginationParams(1, 51, "")
		assert.Equal(t, 50, p.PageSize)
	})

	t.Run("boundary_page_size_50_allowed", func(t *testing.T) {
		p := NewPaginationParams(1, 50, "")
		assert.Equal(t, 50, p.PageSize)
	})
}

func TestPaginationResultOffset(t *testing.T) {
	t.Run("page_1", func(t *testing.T) {
		r := PaginationResult{CurrentPage: 1, PageSize: 10}
		assert.Equal(t, 0, r.Offset())
	})

	t.Run("page_3_size_20", func(t *testing.T) {
		r := PaginationResult{CurrentPage: 3, PageSize: 20}
		assert.Equal(t, 40, r.Offset())
	})

	t.Run("page_5_size_15", func(t *testing.T) {
		r := PaginationResult{CurrentPage: 5, PageSize: 15}
		assert.Equal(t, 60, r.Offset())
	})
}

func TestCalculatePagination(t *testing.T) {
	t.Run("first_page_of_multiple", func(t *testing.T) {
		r := CalculatePagination(100, 1, 10)
		assert.Equal(t, int64(100), r.Total)
		assert.Equal(t, 10, r.TotalPages)
		assert.Equal(t, 1, r.CurrentPage)
		assert.False(t, r.HasPrev)
		assert.True(t, r.HasNext)
		assert.Equal(t, 1, r.PrevPage)
		assert.Equal(t, 2, r.NextPage)
	})

	t.Run("middle_page", func(t *testing.T) {
		r := CalculatePagination(100, 5, 10)
		assert.Equal(t, 5, r.CurrentPage)
		assert.True(t, r.HasPrev)
		assert.True(t, r.HasNext)
		assert.Equal(t, 4, r.PrevPage)
		assert.Equal(t, 6, r.NextPage)
	})

	t.Run("last_page", func(t *testing.T) {
		r := CalculatePagination(100, 10, 10)
		assert.Equal(t, 10, r.CurrentPage)
		assert.True(t, r.HasPrev)
		assert.False(t, r.HasNext)
		assert.Equal(t, 9, r.PrevPage)
		assert.Equal(t, 10, r.NextPage)
	})

	t.Run("single_page", func(t *testing.T) {
		r := CalculatePagination(5, 1, 10)
		assert.Equal(t, 1, r.TotalPages)
		assert.Equal(t, 1, r.CurrentPage)
		assert.False(t, r.HasPrev)
		assert.False(t, r.HasNext)
	})

	t.Run("empty_result_set", func(t *testing.T) {
		r := CalculatePagination(0, 1, 10)
		assert.Equal(t, int64(0), r.Total)
		assert.Equal(t, 0, r.TotalPages)
		assert.Equal(t, 1, r.CurrentPage)
		assert.False(t, r.HasPrev)
		assert.False(t, r.HasNext)
	})

	t.Run("page_beyond_total_clamped", func(t *testing.T) {
		r := CalculatePagination(25, 10, 10)
		assert.Equal(t, 3, r.TotalPages)
		assert.Equal(t, 3, r.CurrentPage)
		assert.True(t, r.HasPrev)
		assert.False(t, r.HasNext)
	})

	t.Run("page_below_1_clamped", func(t *testing.T) {
		r := CalculatePagination(50, 0, 10)
		assert.Equal(t, 1, r.CurrentPage)
	})

	t.Run("partial_last_page", func(t *testing.T) {
		r := CalculatePagination(23, 3, 10)
		assert.Equal(t, 3, r.TotalPages)
		assert.Equal(t, 3, r.CurrentPage)
		assert.True(t, r.HasPrev)
		assert.False(t, r.HasNext)
	})
}
