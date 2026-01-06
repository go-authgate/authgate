package services

import (
	"errors"

	"oauth-device-flow/models"
	"oauth-device-flow/store"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUserNotFound       = errors.New("user not found")
)

type UserService struct {
	store *store.Store
}

func NewUserService(s *store.Store) *UserService {
	return &UserService{store: s}
}

func (s *UserService) Authenticate(username, password string) (*models.User, error) {
	user, err := s.store.GetUserByUsername(username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}

func (s *UserService) GetUserByID(id string) (*models.User, error) {
	user, err := s.store.GetUserByID(id)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}
