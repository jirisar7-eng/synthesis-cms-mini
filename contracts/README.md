# Contracts Layer (contracts/)

## Purpose
The `contracts/` directory defines public and stable extension interfaces for Synthesis CMS mini.

## Scope & Boundaries
- **Belongs here:** Public interface contracts, module runtime interfaces, SDK type declarations, and stable extension point definitions.
- **Critical Distinction:** This directory is strictly separated from `.synthesis/contracts/`. Internal repository governance and capsule schemas reside exclusively in `.synthesis/contracts/`. Runtime product contracts belong in `contracts/`. There is no duplicate governance authority.
- **Explicitly does NOT belong yet:** No governance contracts, no runtime implementations.
- **Future Roadmap:** Module and runtime contracts will be formalized alongside module system development.
- **Status:** Structural ownership boundary established for Step 7.
