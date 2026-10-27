module.exports = {
  repositories: ['rtbrick/tools'],
  baseBranches: ['main'],
  // Paket-Manager aktivieren (Go-Module und npm)
  enabledManagers: ['gomod'],
  prConcurrentLimit: 2,
  postUpdateOptions: ['gomodTidy', 'gomodUpdateImportPaths'],
  packageRules: [
    {
      matchPackagePatterns: ['*'],
      matchUpdateTypes: ['minor', "patch", "pin", "digest"],
      groupName: 'all minor and patch dependencies',
      groupSlug: 'all-non-major-deps',
    },
  ],
};
