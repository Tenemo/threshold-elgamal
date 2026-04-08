import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

type CoverageMetric = {
    covered: number;
    pct: number;
    skipped: number;
    total: number;
};

type CoverageSummary = {
    total: {
        branches: CoverageMetric;
        functions: CoverageMetric;
        lines: CoverageMetric;
        statements: CoverageMetric;
    };
};

type ShieldsBadge = {
    color: string;
    label: string;
    message: string;
    schemaVersion: 1;
};

const repoRoot = process.cwd();
const coverageSummaryPath = path.resolve(
    repoRoot,
    'coverage/coverage-summary.json',
);
const badgeOutputPath = path.resolve(
    repoRoot,
    'docs/public/coverage-badge.json',
);
const summaryOutputPath = path.resolve(
    repoRoot,
    'docs/public/coverage-summary.json',
);

const colorForCoverage = (percent: number): string => {
    if (percent >= 95) {
        return 'brightgreen';
    }
    if (percent >= 90) {
        return 'green';
    }
    if (percent >= 80) {
        return 'yellowgreen';
    }
    if (percent >= 70) {
        return 'yellow';
    }
    if (percent >= 60) {
        return 'orange';
    }
    return 'red';
};

const main = async (): Promise<void> => {
    const summary = JSON.parse(
        await readFile(coverageSummaryPath, 'utf8'),
    ) as CoverageSummary;
    const percent = Number(summary.total.lines.pct.toFixed(1));

    const badge: ShieldsBadge = {
        schemaVersion: 1,
        label: 'coverage',
        message: `${percent}%`,
        color: colorForCoverage(percent),
    };

    await mkdir(path.dirname(badgeOutputPath), { recursive: true });
    await writeFile(badgeOutputPath, `${JSON.stringify(badge, null, 2)}\n`);
    await writeFile(summaryOutputPath, `${JSON.stringify(summary, null, 2)}\n`);

    console.log(
        `Coverage badge written to ${path.relative(repoRoot, badgeOutputPath)}`,
    );
};

void main();
