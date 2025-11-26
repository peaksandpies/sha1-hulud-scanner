#!/bin/bash
# SHA1-HULUD Scanner - Multi-project version with 350+ packages
# Scans Node.js projects to detect compromised packages


# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Known false positives (legitimate packages with "sha1" in their name)
FALSE_POSITIVES=(
  "@aws-crypto/sha1-browser"
  "@aws-crypto/sha256-browser"
  "@aws-crypto/sha256-js"
  "sha1"
  "sha.js"
)

# File containing list of compromised packages
PACKAGES_FILE="$(dirname "$0")/sha1-hulud-packages.txt"

# Load package list
if [ ! -f "$PACKAGES_FILE" ]; then
  echo -e "${RED}❌ Error: Package file not found: $PACKAGES_FILE${NC}"
  echo "Create sha1-hulud-packages.txt in the same directory as this script."
  exit 1
fi

# Read packages (ignore empty lines and comments)
COMPROMISED_PACKAGES=()
while IFS= read -r line; do
  [[ "$line" =~ ^#.*$ ]] && continue
  [[ -z "$line" ]] && continue
  COMPROMISED_PACKAGES+=("$line")
done < "$PACKAGES_FILE"

# -------------------------------
# Functions
# -------------------------------

show_help() {
  echo "Usage: $0 <project_or_projects_directory>"
  echo ""
  echo "Scans Node.js projects to detect packages compromised by SHA1-HULUD pt 2"
  echo ""
  echo "Example:"
  echo "  $0 /path/to/project"
  echo "  $0 /path/to/projects_folder"
}

# Check false positives
is_false_positive() {
  local package="$1"
  for fp in "${FALSE_POSITIVES[@]}"; do
    if [[ "$package" == *"$fp"* ]]; then
      return 0
    fi
  done
  return 1
}

# -------------------------------
# Single-project scan functions
# -------------------------------

scan_package_json() {
  echo "🔎 [1/4] Scanning direct dependencies (package.json)..."

  if [ ! -f "$PROJECT_DIR/package.json" ]; then
    echo -e "  ${YELLOW}⚠️  package.json not found${NC}"
    return
  fi

  local found=0
  for package in "${COMPROMISED_PACKAGES[@]}"; do
    if grep -q "\"$package\"" "$PROJECT_DIR/package.json" 2>/dev/null; then
      echo -e "  ${RED}⚠️  FOUND: $package in package.json${NC}"
      FOUND=$((FOUND + 1))
      FOUND_PACKAGES+=("$package (direct)")
      found=$((found + 1))
    fi
  done

  if [ $found -eq 0 ]; then
    echo -e "  ${GREEN}✓ No compromised packages in direct dependencies${NC}"
  fi
}

scan_node_modules() {
  echo ""
  echo "🔎 [2/4] Scanning node_modules (transitive)..."

  if [ ! -d "$PROJECT_DIR/node_modules" ]; then
    echo -e "  ${YELLOW}⚠️  node_modules not found (run 'npm install' first)${NC}"
    return
  fi

  local found_in_modules=0

  for package in "${COMPROMISED_PACKAGES[@]}"; do
    if [[ "$package" == @*/* ]]; then
      [[ -d "$PROJECT_DIR/node_modules/$package" ]] && {
        echo -e "  ${RED}🚨 FOUND: $package installed${NC}"
        FOUND=$((FOUND + 1))
        FOUND_PACKAGES+=("$package (transitive)")
        found_in_modules=$((found_in_modules + 1))
      }
    else
      [[ -d "$PROJECT_DIR/node_modules/$package" ]] && {
        echo -e "  ${RED}🚨 FOUND: $package installed${NC}"
        FOUND=$((FOUND + 1))
        FOUND_PACKAGES+=("$package (transitive)")
        found_in_modules=$((found_in_modules + 1))
      }
    fi
  done

  if [ $found_in_modules -eq 0 ]; then
    echo -e "  ${GREEN}✓ No compromised packages installed${NC}"
  fi
}

scan_lockfiles() {
  echo ""
  echo "🔎 [3/4] Scanning lockfiles..."

  local found_in_locks=0

  for lockfile in "package-lock.json" "yarn.lock" "bun.lock" "pnpm-lock.yaml"; do
    if [ -f "$PROJECT_DIR/$lockfile" ]; then
      echo "  📄 Scanning $lockfile..."
      case "$lockfile" in
        package-lock.json|pnpm-lock.yaml)
          for package in "${COMPROMISED_PACKAGES[@]}"; do
            grep -q "$package" "$PROJECT_DIR/$lockfile" 2>/dev/null && {
              echo -e "    ${RED}⚠️  FOUND: $package${NC}"
              FOUND=$((FOUND + 1))
              FOUND_PACKAGES+=("$package (lockfile)")
              found_in_locks=$((found_in_locks + 1))
            }
          done
          ;;
        yarn.lock)
          for package in "${COMPROMISED_PACKAGES[@]}"; do
            grep -q "$package@" "$PROJECT_DIR/$lockfile" 2>/dev/null && {
              echo -e "    ${RED}⚠️  FOUND: $package${NC}"
              FOUND=$((FOUND + 1))
              FOUND_PACKAGES+=("$package (lockfile)")
              found_in_locks=$((found_in_locks + 1))
            }
          done
          ;;
        bun.lock)
          for package in "${COMPROMISED_PACKAGES[@]}"; do
            strings "$PROJECT_DIR/$lockfile" 2>/dev/null | grep -q "$package" && {
              echo -e "    ${RED}⚠️  FOUND: $package${NC}"
              FOUND=$((FOUND + 1))
              FOUND_PACKAGES+=("$package (lockfile)")
              found_in_locks=$((found_in_locks + 1))
            }
          done
          ;;
      esac
    fi
  done

  if [ $found_in_locks -eq 0 ]; then
    echo -e "  ${GREEN}✓ No compromised packages in lockfiles${NC}"
  fi
}

scan_sha1_markers() {
  echo ""
  echo "🔎 [4/4] Scanning for SHA1-HULUD markers..."

  local found_markers=0
  local false_positive_count=0

  for lockfile in "package-lock.json" "yarn.lock" "bun.lock" "pnpm-lock.yaml"; do
    [ ! -f "$PROJECT_DIR/$lockfile" ] && continue

    local sha1_packages=""
    case "$lockfile" in
      package-lock.json|pnpm-lock.yaml)
        sha1_packages=$(grep -oE '"[^"]*sha1[^"]*"' "$PROJECT_DIR/$lockfile" 2>/dev/null | sed 's/"//g' | sort -u | grep -v "sha512\|sha256")
        ;;
      yarn.lock)
        sha1_packages=$(grep -E "sha1" "$PROJECT_DIR/$lockfile" 2>/dev/null | grep -oE '^[^@]*@[^@]+@|^@[^"]+@' | sed 's/@$//' | grep "sha1" | sort -u | grep -v "sha512\|sha256")
        ;;
      bun.lock)
        sha1_packages=$(strings "$PROJECT_DIR/$lockfile" 2>/dev/null | grep "sha1" | grep -oE '@[a-zA-Z0-9_/-]+sha1[a-zA-Z0-9_-]*|sha1[a-zA-Z0-9_-]+' | sort -u | grep -v "sha512\|sha256")
        ;;
    esac

    if [ -n "$sha1_packages" ]; then
      echo "  📄 Checking packages with 'sha1' in name ($lockfile):"
      while IFS= read -r pkg; do
        [ -z "$pkg" ] && continue
        if is_false_positive "$pkg"; then
          echo -e "    ${YELLOW}ℹ️  $pkg (legitimate package - skipped)${NC}"
          false_positive_count=$((false_positive_count + 1))
        else
          echo -e "    ${RED}🚨 $pkg (SUSPICIOUS)${NC}"
          found_markers=$((found_markers + 1))
          FOUND=$((FOUND + 1))
          FOUND_PACKAGES+=("$pkg (SHA1 in package name - $lockfile)")
        fi
      done <<< "$sha1_packages"
    fi
  done

  if [ $found_markers -eq 0 ]; then
    if [ $false_positive_count -gt 0 ]; then
      echo -e "  ${GREEN}✓ No suspicious SHA1 markers (${false_positive_count} legitimate packages excluded)${NC}"
    else
      echo -e "  ${GREEN}✓ No SHA1-HULUD markers detected${NC}"
    fi
  fi
}

# -------------------------------
# Multi-project handling
# -------------------------------

if [ $# -eq 0 ]; then
  show_help
  exit 1
fi

INPUT_PATH="$1"

if [ ! -d "$INPUT_PATH" ]; then
  echo -e "${RED}❌ Error: Directory '$INPUT_PATH' does not exist${NC}"
  exit 1
fi

# Detect top-level projects (ignore node_modules)
PROJECTS=()
while IFS= read -r proj; do
  case "$proj" in
    */node_modules/*) continue ;;
  esac
  PROJECTS+=("$proj")
done < <(find "$INPUT_PATH" -type f -name package.json -exec dirname {} \; | sort -u)

if [ ${#PROJECTS[@]} -eq 0 ]; then
  echo -e "${RED}❌ No Node.js projects found in $INPUT_PATH${NC}"
  exit 1
fi

# Print projects
echo "📦 Found ${#PROJECTS[@]} project(s):"
for p in "${PROJECTS[@]}"; do
  REAL=$(cd "$p" 2>/dev/null && pwd)
  echo "  • ${REAL:-$p}"
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# -------------------------------
# Scan each project
# -------------------------------

TOTAL_COMPROMISED=0

for proj in "${PROJECTS[@]}"; do
  echo ""
  echo "============================================================"
  echo "🔍 SCANNING PROJECT: $proj"
  echo "============================================================"

  # Reset per-project counters
  FOUND=0
  PROJECT_DIR="$proj"

  scan_package_json
  scan_node_modules
  scan_lockfiles
  scan_sha1_markers

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  if [ $FOUND -eq 0 ]; then
    echo -e "${GREEN}✅ $proj is clean${NC}"
  else
    echo -e "${RED}🚨 $FOUND issue(s) found in $proj${NC}"
    TOTAL_COMPROMISED=$((TOTAL_COMPROMISED + 1))
  fi
done

echo ""
echo "📊 Scan complete"
echo "   • Projects scanned: ${#PROJECTS[@]}"
echo "   • Projects with issues: $TOTAL_COMPROMISED"

if [ $TOTAL_COMPROMISED -gt 0 ]; then
  exit 1
else
  exit 0
fi
