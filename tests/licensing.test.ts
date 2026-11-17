import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (name: string) => readFileSync(new URL(`../${name}`, import.meta.url), 'utf8');

describe('project licence distribution', () => {
  it('declares the selected version policy and copyright holder consistently', () => {
    expect(JSON.parse(read('package.json')).license).toBe('AGPL-3.0-or-later');
    expect(read('README.md')).toContain('AGPL-3.0-or-later');
    expect(read('NOTICE')).toContain('Copyright (C) 2026 Guillermo Moreno');
    expect(read('NOTICE')).toContain('SPDX-License-Identifier: AGPL-3.0-or-later');
    expect(read('LICENSE')).toContain('GNU AFFERO GENERAL PUBLIC LICENSE');
    expect(read('README.md')).toContain('Third-party dependencies and assets');
  });
  it('includes the full licence and application notice in runtime images', () => {
    expect(read('.dockerignore')).toContain('!LICENSE');
    expect(read('.dockerignore')).toContain('!NOTICE');
    expect(read('Dockerfile').split('AS runtime')[1]).toContain('COPY LICENSE NOTICE ./');
  });
});
