# Phylex - Interactive Phylogenetic Tree Browser

Explore the tree of life with an intuitive, user-friendly interface. Browse 27,000+ organisms from the origin of life to modern species.
Feel free to download the data as csv and expand it or build new navigations/apps based on it.

**Live Demo:** https://phylexnew-bueacfd8ctbchbc3.francecentral-01.azurewebsites.net/
---

This data is based on AronRA's Phylogeny Explorer seen in 'Systematic Classification of Life' youtube series.

A shoutout to ToLWeb.org, Wikipedia's phylogenies & Wikispecies, OneZoom tree of life, OTT (OpenTreeofLife), iToL

## What You Can Do

### For Everyone (No Login Required)
- Navigate the evolutionary tree from Life to Species
- Search 27,728 organisms instantly
- Click "Homo sapiens" to see the human evolutionary path
- Switch between vertical tree view and horizontal lineage view
- Export the entire database as CSV
- Works on mobile and desktop

### For Contributors (Login Required)
- Add new species and classifications
- Move organisms to correct parents
- Update descriptions and traits
- All changes logged and audited

---

## Quick Start Guide

### Step 1: Open the App
Visit: https://phylexnew-bueacfd8ctbchbc3.francecentral-01.azurewebsites.net/

The app starts at "Life" - the root of all living things.

### Step 2: Navigate the Tree

**Vertical View (Default)**
- Shows the current organism and all its children
- Click any child to go deeper
- Use the breadcrumb path on the left to go back up

**Horizontal Lineage View**
- Click "Horizontal Lineage" button in the header
- See the entire evolutionary chain from left to right
- Perfect for understanding long ancestral lines
- Switch back with "Vertical Lineage" button

### Step 3: Search for Organisms
- Type in the search box at the top
- Results appear instantly as you type
- Case insensitive (works with partial names)
- Click any result to jump to that organism

**Try searching for:**
- "Homo sapiens" - Humans
- "Tyrannosaurus" - T-Rex
- "Mammalia" - All mammals
- "Aves" - Birds

### Step 4: Understand What You See

Each organism card shows:
- **Name** - Scientific classification (e.g., "Canis lupus")
- **Description** - What it is and key facts
- **Eras** - WHen a clade appeared
- **Timescale** - Highlighted in red the lifespan of the clade
- **Children** - Number of sub-classifications
- **Path Badge** - Green highlight if on the path to Homo sapiens

### Step 5: Quick Actions
- **Jump to humans:** Click "Homo sapiens" in the top-right header
- **Export data:** Click "Export CSV" button (no login needed)
- **Switch views:** Use "Horizontal Lineage" / "Vertical Lineage" buttons

---

## Navigation Tips

**How to Move Around:**
- Click any child name to go deeper into the tree
- Click items in the breadcrumb path (left sidebar) to go back up
- Use search to jump anywhere instantly
- Click "Homo sapiens" stat to see human evolution

---

## Mobile Experience

The app works also on phones:
- Clean, scrollable interface optimized for touch
- Large buttons easy to tap
- Search works perfectly
- Export CSV available
- Editing tools hidden on mobile (use desktop to edit)

---

## Editing Guide (For Contributors)

### Getting Edit Access
1. Click "Edit Mode" button in the top-right
2. Enter your username and password
3. The editing toolbar appears at the top

### Adding New Organisms
1. Navigate to where the new organism belongs
2. In the toolbar, enter:
   - Parent ID (ID of the parent organism)
   - Child name (name of the new organism)
3. Click "Add Child"
4. The new organism appears immediately

### Moving Organisms
1. Find the ID of the organism you want to move
2. Find the ID of the new parent
3. In the toolbar, enter both IDs
4. Click "Move"
5. The organism relocates with all its children

### Safety Features
- You cannot delete organisms that have children
- All changes are logged with your username and IP address
- Request timing is tracked for performance monitoring
- Role-based permissions (Editor or Admin)

---

## Database Information

Current database contains:
- ~27,800 total organisms and classifications
- 75 nodes on the direct evolutionary path to Homo sapiens
- All major biological kingdoms
- Descriptions and traits for most organisms
- Both extinct and living species
- Very small size: ~4MB with few descriptions, ~10MB with most descriptions

---

## For Developers

### Technology Stack
- Python 3.11
- Flask 3.0
- PostgreSQL 14+
- Gunicorn WSGI server
- Azure App Service
- GitHub Actions for CI/CD

### Running Locally
```bash
git clone https://github.com/SlopaStefan/phylexnew.git
cd phylexnew
python -m venv .venv
source .venv/bin/activate
pip install Flask psycopg2-binary bcrypt
python phylex.py
```

### Environment Variables Required
```
DB_HOST - PostgreSQL hostname
DB_NAME - Database name
DB_USER - Write user
DB_PASS - Write password
DB_USER_RO - Read-only user
DB_PASS_RO - Read-only password
FLASK_SECRET_KEY - Session secret
```

### Database Schema
```sql
CREATE TABLE clades (
    node_id TEXT PRIMARY KEY,
    node_name TEXT,
    parent_id TEXT REFERENCES clades(node_id),
    description TEXT,
    traits TEXT,
    other_names TEXT,
    extant BOOLEAN
);

CREATE TABLE users (
    username TEXT PRIMARY KEY,
    password TEXT,
    role TEXT,
    is_active BOOLEAN,
    last_login TIMESTAMP
);
```

---

## Contributing

Contributions are welcome:
- Add missing organisms using Edit Mode
- Improve descriptions and add details
- Fix misclassifications
- Report bugs via GitHub Issues
- Submit pull requests for code improvements

---

## License

MIT License - Free to use, modify, and distribute

---

## Credits

This python app is made by Slopa, 2026
Built with Flask, PostgreSQL, and Azure App Service
Data compiled from biological classification sources (Wikipedia & NCBI) based on a mongodb dump of AronRA's PhylEX corrupted data.
