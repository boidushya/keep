package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Env mirrors the envs table row.
type Env struct {
	ID        int
	ProjectID int
	Slug      string
	Name      string
	CreatedAt int64
}

// Envs is the data access object for the envs table.
type Envs struct {
	DB  *sql.DB
	Now func() time.Time
}

func (e Envs) now() int64 {
	if e.Now != nil {
		return e.Now().Unix()
	}
	return time.Now().Unix()
}

// ListByProject returns every env in projectID, oldest first.
func (e Envs) ListByProject(ctx context.Context, projectID int) ([]Env, error) {
	rows, err := e.DB.QueryContext(ctx, `
		SELECT id, project_id, slug, name, created_at
		FROM envs
		WHERE project_id = ?
		ORDER BY created_at ASC, id ASC
	`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Env
	for rows.Next() {
		var r Env
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.Slug, &r.Name, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get returns the env by id, ErrNotFound otherwise.
func (e Envs) Get(ctx context.Context, id int) (Env, error) {
	return e.scanOne(ctx, `
		SELECT id, project_id, slug, name, created_at
		FROM envs WHERE id = ?
	`, id)
}

// GetBySlug returns the (projectID, slug) env, ErrNotFound otherwise.
func (e Envs) GetBySlug(ctx context.Context, projectID int, slug string) (Env, error) {
	var r Env
	err := e.DB.QueryRowContext(ctx, `
		SELECT id, project_id, slug, name, created_at
		FROM envs WHERE project_id = ? AND slug = ?
	`, projectID, slug).Scan(&r.ID, &r.ProjectID, &r.Slug, &r.Name, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Env{}, ErrNotFound
	}
	return r, err
}

func (e Envs) scanOne(ctx context.Context, query string, arg any) (Env, error) {
	var r Env
	err := e.DB.QueryRowContext(ctx, query, arg).
		Scan(&r.ID, &r.ProjectID, &r.Slug, &r.Name, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Env{}, ErrNotFound
	}
	return r, err
}

// Create inserts an env. Slug must be unique within a project.
func (e Envs) Create(ctx context.Context, projectID int, slug, name string) (Env, error) {
	now := e.now()
	res, err := e.DB.ExecContext(ctx, `
		INSERT INTO envs (project_id, slug, name, created_at)
		VALUES (?, ?, ?, ?)
	`, projectID, slug, name, now)
	if err != nil {
		return Env{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Env{}, err
	}
	return Env{
		ID: int(id), ProjectID: projectID, Slug: slug, Name: name, CreatedAt: now,
	}, nil
}

// Delete removes the env (cascading to secrets and tokens).
func (e Envs) Delete(ctx context.Context, id int) error {
	_, err := e.DB.ExecContext(ctx, `DELETE FROM envs WHERE id = ?`, id)
	return err
}
