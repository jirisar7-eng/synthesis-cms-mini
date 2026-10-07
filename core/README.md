# Core Engine Layer (core/)

## Purpose
The `core/` directory establishes the universal CMS engine ownership boundary.

## Scope & Boundaries
- **Belongs here:** Universal headless CMS domain logic, content lifecycle management, event bus, and core runtime orchestration.
- **Explicitly does NOT belong:** No project-specific business logic or custom branding. No domain subdirectories (such as `auth`, `users`, `content`, `media`, `navigation`, or `database`) are created in Step 7.
- **Future Roadmap:** Domain capabilities will be implemented incrementally in dedicated subsequent roadmap steps.
- **Status:** Structural ownership boundary established for Step 7.
