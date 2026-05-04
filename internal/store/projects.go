package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ErrNotFound is returned by Get/GetBySlug helpers when no row matches.
var ErrNotFound = errors.New("store: not found")

// Project mirrors the projects table row.
type Project struct {
	ID        int
	Slug      string
	Name      string
	CreatedAt int64
}

// Projects is the data access object for the projects table.
type Projects struct {
	DB  *sql.DB
	Now func() time.Time
}

func (p Projects) now() int64 {
	if p.Now != nil {
		return p.Now().Unix()
	}
	return time.Now().Unix()
}

// List returns every project, oldest first.
func (p Projects) List(ctx context.Context) ([]Project, error) {
	rows, err := p.DB.QueryContext(ctx,
		`SELECT id, slug, name, created_at FROM projects ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Project
	for rows.Next() {
		var r Project
		if err := rows.Scan(&r.ID, &r.Slug, &r.Name, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get returns one project by id. ErrNotFound when missing.
func (p Projects) Get(ctx context.Context, id int) (Project, error) {
	return p.scanOne(ctx,
		`SELECT id, slug, name, created_at FROM projects WHERE id = ?`, id)
}

// GetBySlug returns one project by slug. ErrNotFound when missing.
func (p Projects) GetBySlug(ctx context.Context, slug string) (Project, error) {
	return p.scanOne(ctx,
		`SELECT id, slug, name, created_at FROM projects WHERE slug = ?`, slug)
}

func (p Projects) scanOne(ctx context.Context, query string, arg any) (Project, error) {
	var r Project
	err := p.DB.QueryRowContext(ctx, query, arg).
		Scan(&r.ID, &r.Slug, &r.Name, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	return r, err
}

// Create inserts a project. Returns the inserted row.
func (p Projects) Create(ctx context.Context, slug, name string) (Project, error) {
	now := p.now()
	res, err := p.DB.ExecContext(ctx,
		`INSERT INTO projects (slug, name, created_at) VALUES (?, ?, ?)`,
		slug, name, now)
	if err != nil {
		return Project{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Project{}, err
	}
	return Project{ID: int(id), Slug: slug, Name: name, CreatedAt: now}, nil
}

// Delete removes the project (cascading to envs, secrets, tokens).
func (p Projects) Delete(ctx context.Context, id int) error {
	_, err := p.DB.ExecContext(ctx, `DELETE FROM projects WHERE id = ?`, id)
	return err
}
