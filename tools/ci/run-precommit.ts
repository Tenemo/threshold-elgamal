import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const packageManagerEntrypoint = process.env.npm_execpath;

if (packageManagerEntrypoint === undefined) {
    throw new Error('npm_execpath is required to run pre-commit checks');
}

type PrecommitStep = {
    readonly label: string;
    readonly args: readonly string[];
};

const steps: readonly PrecommitStep[] = [
    { label: 'lint', args: ['run', 'lint'] },
    { label: 'typecheck', args: ['run', 'typecheck'] },
    {
        label: 'Math.random guard',
        args: ['run', 'guard:no-math-random'],
    },
    { label: 'generator H verification', args: ['run', 'verify:h-derivation'] },
    { label: 'production build', args: ['run', 'build:skip'] },
    { label: 'node tests', args: ['run', 'test:node:built'] },
    { label: 'browser tests', args: ['run', 'test:browser:built'] },
    { label: 'API docs verification', args: ['run', 'verify:docs'] },
    { label: 'docs site build', args: ['run', 'docs:build:site'] },
    { label: 'vector verification', args: ['run', 'verify:vectors'] },
    { label: 'packed package smoke test', args: ['run', 'smoke:pack'] },
];

const formatDuration = (durationMs: number): string => {
    if (durationMs < 1000) {
        return `${durationMs}ms`;
    }

    return `${(durationMs / 1000).toFixed(1)}s`;
};

const printCapturedOutput = (
    stream: NodeJS.WriteStream,
    output: string,
): void => {
    const trimmedOutput = output.trim();
    if (trimmedOutput.length > 0) {
        stream.write(`${trimmedOutput}\n`);
    }
};

const runStep = (step: PrecommitStep, index: number, total: number): void => {
    const startTime = Date.now();
    const result = spawnSync(
        process.execPath,
        [packageManagerEntrypoint, ...step.args],
        {
            cwd: repoRoot,
            env: process.env,
            encoding: 'utf8',
            maxBuffer: 100 * 1024 * 1024,
        },
    );
    const duration = formatDuration(Date.now() - startTime);

    if (result.error !== undefined) {
        throw new Error(
            `Failed to start ${step.label}: ${result.error.message}`,
        );
    }

    if (result.signal !== null) {
        process.stderr.write(
            `[${index}/${total}] ${step.label} failed after ${duration}\n`,
        );
        printCapturedOutput(process.stdout, result.stdout);
        printCapturedOutput(process.stderr, result.stderr);
        throw new Error(`${step.label} terminated by signal ${result.signal}`);
    }

    if (result.status !== 0) {
        process.stderr.write(
            `[${index}/${total}] ${step.label} failed after ${duration}\n`,
        );
        printCapturedOutput(process.stdout, result.stdout);
        printCapturedOutput(process.stderr, result.stderr);
        process.exit(result.status ?? 1);
    }

    process.stdout.write(
        `[${index}/${total}] ${step.label} passed in ${duration}\n`,
    );
};

const main = (): void => {
    process.stdout.write(`Running ${steps.length} pre-commit checks.\n`);

    steps.forEach((step, index) => {
        runStep(step, index + 1, steps.length);
    });
};

main();
