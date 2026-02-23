package store

import "math"

// PaginationParams contains parameters for paginated queries
type PaginationParams struct {
	Page     int    // Current page number (1-indexed)
	PageSize int    // Number of items per page
	Search   string // Search keyword
}

// PaginationResult contains pagination metadata
type PaginationResult struct {
	Total       int64 // Total number of records
	TotalPages  int   // Total number of pages
	CurrentPage int   // Current page number
	PageSize    int   // Number of items per page
	HasPrev     bool  // Whether there is a previous page
	HasNext     bool  // Whether there is a next page
	PrevPage    int   // Previous page number
	NextPage    int   // Next page number
}

// NewPaginationParams creates a new PaginationParams with default values
func NewPaginationParams(page, pageSize int, search string) PaginationParams {
	// Default to page 1 if invalid
	if page < 1 {
		page = 1
	}

	// Default to 10 items per page, max 50
	if pageSize < 1 {
		pageSize = 10
	}
	if pageSize > 50 {
		pageSize = 50
	}

	return PaginationParams{
		Page:     page,
		PageSize: pageSize,
		Search:   search,
	}
}

// CalculatePagination calculates pagination metadata
func CalculatePagination(total int64, currentPage, pageSize int) PaginationResult {
	totalPages := int(math.Ceil(float64(total) / float64(pageSize)))

	// Ensure current page is within bounds
	if currentPage < 1 {
		currentPage = 1
	}
	if currentPage > totalPages && totalPages > 0 {
		currentPage = totalPages
	}

	hasPrev := currentPage > 1
	hasNext := currentPage < totalPages

	prevPage := max(currentPage-1, 1)
	nextPage := min(currentPage+1, totalPages)

	return PaginationResult{
		Total:       total,
		TotalPages:  totalPages,
		CurrentPage: currentPage,
		PageSize:    pageSize,
		HasPrev:     hasPrev,
		HasNext:     hasNext,
		PrevPage:    prevPage,
		NextPage:    nextPage,
	}
}
