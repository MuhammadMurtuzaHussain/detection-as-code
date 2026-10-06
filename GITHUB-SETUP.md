# GitHub Push Instructions

## Step 1: Create a GitHub repository

1. Go to https://github.com/new
2. Repository name: `detection-as-code`
3. Description: "Sigma detection rules in Git, tested in CI against benign and malicious logs, with a results dashboard on GitHub Pages"
4. Choose public (this is a portfolio piece)
5. Do NOT initialise with a README (the repository already has one)

## Step 2: Add the remote and push

```bash
cd ~/Desktop/GItHub\ Projects/detection-as-code

git remote add origin https://github.com/MuhammadMurtuzaHussain/detection-as-code.git
git push -u origin main
```

## Step 3: Turn on GitHub Pages

The workflow publishes the dashboard, but Pages has to be switched to Actions first:

1. Repository Settings, then Pages
2. Under "Build and deployment", set Source to **GitHub Actions**
3. Open the Actions tab and re-run the latest `ci` run if the `pages` job failed the first time

The dashboard URL appears in the `pages` job and will be `https://MuhammadMurtuzaHussain.github.io/detection-as-code/`.

## Step 4: Finish the profile

1. Add the live URL to the repository's About box (Website field)
2. Add topics: `detection-engineering`, `sigma`, `detection-as-code`, `mitre-attack`, `github-actions`, `cybersecurity`
3. Retake `docs/dashboard.png` from the live page so the screenshot uses the page's own typeface (the bundled one was taken without web fonts)

## Check that it works

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
make all
```

*Repository initialised on 2026-10-06 with Claude Sonnet 5.5*
