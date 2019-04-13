# Murphys Maths Backend

![](https://travis-ci.org/ryanbester/murphys-maths-backend.svg?branch=master)

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/a44c0481c07c45f2b1b7289da764a5a3)](https://www.codacy.com/app/ryanbester/murphys-maths-backend?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=ryanbester/murphys-maths-backend&amp;utm_campaign=Badge_Grade)

Backend site for the Murphys Maths website.

This application is powered by node.js and is set up as a reverse proxy from nginx.

## Installing ##

To install the backend application, first clone the repository into a working directory (you will need to set up SSH). Next, `cd` into that directory, and run `npm install` to install all the required packages. To run the application, for production type `pm2 startOrRestart app.js --env production --watch`, or for development type `npm2 startOrRestart app.js --env development --watch`.

```sh
# cd /opt
# git clone git@github.com:ryanbester/murphys-maths-backend.git
Cloning into '.'...
remote: Enumerating objects: 399, done.
remote: Counting objects: 100% (399/399), done.
remote: Compressing objects: 100% (320/320), done.
remote: Total 399 (delta 71), reused 393 (delta 68), pack-reused 0
Receiving objects: 100% (399/399), 545.99 KiB | 1.26 MiB/s, done.
Resolving deltas: 100% (71/71), done.
# cd murphys-maths-backend
# npm install
# pm2 startOrRestart app.js --env production --watch
[PM2] Applying action restartProcessId on app [murphys-maths-prod](ids: 4,5,6,7)
[PM2] [murphys-maths-prod](4) ✓
[PM2] [murphys-maths-prod](5) ✓
[PM2] [murphys-maths-prod](6) ✓
[PM2] [murphys-maths-prod](7) ✓
┌────────────────────┬────┬─────────┬────────┬────┬─────┬───────────┐
│ Name               │ id │ mode    │ status │ ↺  │ cpu │ memory    │
├────────────────────┼────┼─────────┼────────┼────┼─────┼───────────┤
│ murphys-maths-dev  │ 0  │ cluster │ online │ 98 │ 0%  │ 51.3 MB   │
│ murphys-maths-dev  │ 1  │ cluster │ online │ 98 │ 0%  │ 52.0 MB   │
│ murphys-maths-dev  │ 2  │ cluster │ online │ 98 │ 0%  │ 41.6 MB   │
│ murphys-maths-dev  │ 3  │ cluster │ online │ 98 │ 0%  │ 41.9 MB   │
│ murphys-maths-prod │ 4  │ cluster │ online │ 57 │ 0%  │ 48.5 MB   │
│ murphys-maths-prod │ 5  │ cluster │ online │ 57 │ 0%  │ 47.5 MB   │
│ murphys-maths-prod │ 6  │ cluster │ online │ 55 │ 0%  │ 33.0 MB   │
│ murphys-maths-prod │ 7  │ cluster │ online │ 55 │ 0%  │ 29.7 MB   │
└────────────────────┴────┴─────────┴────────┴────┴─────┴───────────┘
```

## Contributing ##

When contributing to this repository, follow the git branching model as shown below:

![Git branching model](https://nvie.com/img/git-model@2x.png)

Always commit on the `develop` branch, create a new branch for features (with prefix `feature-*`), and branch off to a new release branch (with prefix `release-*`), before submitting a pull request for me to merge to `master`.

If there are any important bugs that could affect the security or core functionality of the application, branch off from the `master` branch to a new branch named `hotfix-*`, fix the bug before merging back to `develop` and submitting a pull request to `master`.

Credit: https://nvie.com/posts/a-successful-git-branching-model/
