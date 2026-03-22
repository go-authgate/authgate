package services

import (
	"errors"

	"github.com/go-authgate/authgate/internal/models"
	"github.com/go-authgate/authgate/internal/store"
	"github.com/go-authgate/authgate/internal/util"

	"gorm.io/gorm"
)

// Token query operations

// GetUserTokens returns all tokens for a user
func (s *TokenService) GetUserTokens(userID string) ([]models.AccessToken, error) {
	return s.store.GetTokensByUserID(userID)
}

// IsTokenOwnedByUser returns true if the token with the given ID belongs to the given user.
// A missing token is treated the same as an unowned token: returns (false, nil).
func (s *TokenService) IsTokenOwnedByUser(tokenID, userID string) (bool, error) {
	tok, err := s.store.GetAccessTokenByID(tokenID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return tok.UserID == userID, nil
}

// enrichTokensWithClients batch-fetches client names and joins them onto a token slice.
func (s *TokenService) enrichTokensWithClients(
	tokens []models.AccessToken,
) ([]TokenWithClient, error) {
	clientIDs := util.UniqueKeys(tokens, func(t models.AccessToken) string { return t.ClientID })
	clientMap, err := s.store.GetClientsByIDs(clientIDs)
	if err != nil {
		return nil, err
	}
	result := make([]TokenWithClient, 0, len(tokens))
	for _, tok := range tokens {
		clientName := tok.ClientID // Default to ClientID if not found
		if client, ok := clientMap[tok.ClientID]; ok && client != nil {
			clientName = client.ClientName
		}
		result = append(result, TokenWithClient{AccessToken: tok, ClientName: clientName})
	}
	return result, nil
}

// GetUserTokensWithClient returns all tokens for a user with client information
func (s *TokenService) GetUserTokensWithClient(userID string) ([]TokenWithClient, error) {
	tokens, err := s.store.GetTokensByUserID(userID)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return []TokenWithClient{}, nil
	}
	return s.enrichTokensWithClients(tokens)
}

// GetUserTokensWithClientPaginated returns paginated tokens for a user with client information
func (s *TokenService) GetUserTokensWithClientPaginated(
	userID string,
	params store.PaginationParams,
) ([]TokenWithClient, store.PaginationResult, error) {
	tokens, pagination, err := s.store.GetTokensByUserIDPaginated(userID, params)
	if err != nil {
		return nil, store.PaginationResult{}, err
	}
	if len(tokens) == 0 {
		return []TokenWithClient{}, pagination, nil
	}
	result, err := s.enrichTokensWithClients(tokens)
	if err != nil {
		return nil, store.PaginationResult{}, err
	}
	return result, pagination, nil
}

// GetUserByID returns a user by their ID.
func (s *TokenService) GetUserByID(userID string) (*models.User, error) {
	return s.store.GetUserByID(userID)
}
