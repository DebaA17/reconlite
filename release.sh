#!/bin/bash

# ReconLite Release Helper
# Usage: ./release.sh 1.0.1 "Bug fix: Socket error handling"

set -e

VERSION=$1
MESSAGE=${2:-"Release $VERSION"}

if [ -z "$VERSION" ]; then
    echo "Usage: ./release.sh VERSION [MESSAGE]"
    echo "Example: ./release.sh 1.0.1 \"Bug fix: Socket error handling\""
    exit 1
fi

TAG="v$VERSION"

echo "📦 Creating release: $TAG"
echo "📝 Message: $MESSAGE"
echo

# Check if tag already exists
if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "❌ Tag $TAG already exists"
    exit 1
fi

# Check for uncommitted changes
if [ -n "$(git status -s)" ]; then
    echo "⚠️  Uncommitted changes detected:"
    git status -s
    read -p "Commit and push these changes? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    
    # Commit changes
    echo "📝 Committing changes..."
    git add -A
    git commit -m "Release: ReconLite $VERSION - $MESSAGE"
    
    # Push to main
    echo "📤 Pushing code to main branch..."
    git push origin main
fi

# Create tag
echo "🏷️  Creating git tag..."
git tag -a "$TAG" -m "ReconLite $VERSION: $MESSAGE"

# Push tag
echo "📤 Pushing tag to GitHub..."
git push origin "$TAG"

echo
echo "✅ Release tag pushed!"
echo
echo "🔗 GitHub Actions will now:"
echo "   1. Run tests"
echo "   2. Generate SHA256 checksums"
echo "   3. Create a GitHub Release"
echo "   4. Upload CHECKSUMS.txt"
echo
echo "Monitor progress at:"
echo "   https://github.com/DebaA17/reconlite/actions"
echo
echo "View release at:"
echo "   https://github.com/DebaA17/reconlite/releases/tag/$TAG"
