export default {
  '**/*.js': 'standard',
  '**/*.{js,jsx,json,md,ts,tsx,toml}': 'dprint check',
  '**/*.{js,json}': () => 'tsc --emitDeclarationOnly'
}
