import { performance } from 'node:perf_hooks';

import { runVotingFlowScenario } from '../../dev-support/voting-flow-harness.js';
import { majorityThreshold, type GroupName } from '../../src/core/index.js';
import { verifyDKGTranscript } from '../../src/dkg/index.js';
import type { KeyAgreementSuite } from '../../src/transport/index.js';

type BenchmarkRow = {
    readonly group: GroupName;
    readonly optionCount: number;
    readonly participantCount: number;
    readonly threshold: number;
    readonly transcriptMessages: number;
    readonly transportSuite: KeyAgreementSuite;
    readonly verifyTranscriptMs: number;
    readonly votingFlowMs: number;
};

const round = (value: number): number => Math.round(value * 1_000) / 1_000;

const formatDurationMs = (value: number): string => {
    const rounded = round(value);

    if (rounded < 1_000) {
        return `${rounded} ms`;
    }

    const totalSeconds = rounded / 1_000;
    if (totalSeconds < 60) {
        return `${round(totalSeconds)} s`;
    }

    const hours = Math.floor(totalSeconds / 3_600);
    const minutes = Math.floor((totalSeconds % 3_600) / 60);
    const seconds = round(totalSeconds % 60);

    const parts = [
        hours > 0 ? `${hours} h` : null,
        minutes > 0 || hours > 0 ? `${minutes} min` : null,
        `${seconds} s`,
    ].filter((part): part is string => part !== null);

    return parts.join(' ');
};

const buildVotes = (participantCount: number): readonly bigint[] =>
    Array.from({ length: participantCount }, (_value, index) =>
        BigInt((index % 10) + 1),
    );

const buildVotesByOption = (
    participantCount: number,
    optionCount: number,
): readonly (readonly bigint[])[] =>
    Array.from({ length: optionCount }, (_value, optionOffset) =>
        Array.from({ length: participantCount }, (_entry, participantOffset) =>
            BigInt(((participantOffset + optionOffset * 3) % 10) + 1),
        ),
    );

const parseArgs = (): {
    readonly group: GroupName;
    readonly optionCount: number;
    readonly participantCounts: readonly number[];
    readonly transportSuite: KeyAgreementSuite;
} => {
    const provided = process.argv
        .slice(2)
        .map((argument) => argument.trim())
        .filter((argument) => argument !== '' && argument !== '--');
    let group: GroupName = 'ffdhe3072';
    let optionCount = 1;
    let transportSuite: KeyAgreementSuite = 'X25519';

    const participantArguments = provided.filter((argument) => {
        if (argument.startsWith('--group=')) {
            group = argument.slice('--group='.length) as GroupName;
            return false;
        }
        if (argument.startsWith('--options=')) {
            optionCount = Number(argument.slice('--options='.length));
            return false;
        }
        if (argument.startsWith('--transport=')) {
            transportSuite = argument.slice(
                '--transport='.length,
            ) as KeyAgreementSuite;
            return false;
        }

        return true;
    });
    const participantCounts =
        participantArguments.length === 0
            ? [3, 11, 21, 31, 41, 50]
            : participantArguments
                  .flatMap((argument) => argument.split(/[,\s]+/u))
                  .map((argument) => argument.trim())
                  .filter((argument) => argument !== '')
                  .map((argument) => {
                      const participantCount = Number(argument);
                      if (
                          !Number.isInteger(participantCount) ||
                          participantCount < 3
                      ) {
                          throw new Error(
                              `Invalid participant count "${argument}". Use integers >= 3.`,
                          );
                      }

                      return participantCount;
                  });

    if (!Number.isInteger(optionCount) || optionCount < 1) {
        throw new Error('Invalid option count. Use an integer >= 1.');
    }

    return {
        group,
        optionCount,
        participantCounts,
        transportSuite,
    };
};

const main = async (): Promise<void> => {
    const { participantCounts, group, optionCount, transportSuite } =
        parseArgs();
    const rows: BenchmarkRow[] = [];
    const benchmarkStart = performance.now();

    for (const [index, participantCount] of participantCounts.entries()) {
        const threshold = majorityThreshold(participantCount);
        const step = index + 1;
        const totalSteps = participantCounts.length;

        console.log(
            `[${step}/${totalSteps}] Starting n=${participantCount}, k=${threshold}, options=${optionCount}, group=${group}, transport=${transportSuite}`,
        );
        console.log(`[${step}/${totalSteps}] Stage 1/2: full voting flow`);

        const votingFlowStart = performance.now();
        const votes = buildVotes(participantCount);
        const votesByOption =
            optionCount === 1
                ? undefined
                : buildVotesByOption(participantCount, optionCount);
        const result = await runVotingFlowScenario({
            participantCount,
            optionList: Array.from(
                { length: optionCount },
                (_value, optionOffset) => `Option ${optionOffset + 1}`,
            ),
            votes,
            votesByOption,
            group,
            transportSuite,
        });
        const votingFlowMs = performance.now() - votingFlowStart;

        console.log(
            `[${step}/${totalSteps}] Stage 1/2 complete in ${formatDurationMs(votingFlowMs)} with ${result.dkgTranscript.length} transcript messages`,
        );

        if (result.finalState.phase !== 'completed') {
            throw new Error(
                `Expected a completed scenario for participant count ${participantCount}`,
            );
        }

        console.log(
            `[${step}/${totalSteps}] Stage 2/2: transcript verification`,
        );
        const verifyStart = performance.now();
        await verifyDKGTranscript({
            protocol: 'gjkr',
            transcript: result.dkgTranscript,
            manifest: result.manifest,
            sessionId: result.sessionId,
        });
        const verifyTranscriptMs = performance.now() - verifyStart;
        const elapsedMs = performance.now() - benchmarkStart;
        const averageMsPerRun = elapsedMs / step;
        const remainingRuns = totalSteps - step;
        const estimatedRemainingMs = averageMsPerRun * remainingRuns;

        console.log(
            `[${step}/${totalSteps}] Stage 2/2 complete in ${formatDurationMs(verifyTranscriptMs)}`,
        );
        console.log(
            `[${step}/${totalSteps}] Finished n=${participantCount} in ${formatDurationMs(votingFlowMs + verifyTranscriptMs)}. Elapsed ${formatDurationMs(elapsedMs)}. Estimated remaining ${formatDurationMs(estimatedRemainingMs)}.`,
        );

        rows.push({
            group,
            optionCount,
            participantCount,
            threshold,
            transcriptMessages: result.dkgTranscript.length,
            transportSuite,
            votingFlowMs: round(votingFlowMs),
            verifyTranscriptMs: round(verifyTranscriptMs),
        });
    }

    console.table(rows);
};

void main();
