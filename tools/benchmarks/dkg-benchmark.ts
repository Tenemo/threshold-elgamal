import { performance } from 'node:perf_hooks';

import { majorityThreshold } from '../../src/core/index.js';
import { verifyDKGTranscript } from '../../src/dkg/index.js';
import { runVotingFlowScenario } from '../../tests/node/integration/voting-flow-harness.js';

type BenchmarkRow = {
    readonly participantCount: number;
    readonly threshold: number;
    readonly transcriptMessages: number;
    readonly verifyTranscriptMs: number;
    readonly votingFlowMs: number;
};

const round = (value: number): number => Math.round(value * 1_000) / 1_000;

const parseParticipantCounts = (): readonly number[] => {
    const provided = process.argv
        .slice(2)
        .flatMap((argument) => argument.split(','))
        .map((argument) => argument.trim())
        .filter((argument) => argument !== '');

    if (provided.length === 0) {
        return [3, 5, 7, 9, 11];
    }

    return provided.map((argument) => {
        const participantCount = Number(argument);
        if (!Number.isInteger(participantCount) || participantCount < 2) {
            throw new Error(
                `Invalid participant count "${argument}". Use integers >= 2.`,
            );
        }

        return participantCount;
    });
};

const buildVotes = (participantCount: number): readonly bigint[] =>
    Array.from({ length: participantCount }, (_value, index) =>
        BigInt((index % 10) + 1),
    );

const main = async (): Promise<void> => {
    const participantCounts = parseParticipantCounts();
    const rows: BenchmarkRow[] = [];

    for (const participantCount of participantCounts) {
        const votingFlowStart = performance.now();
        const result = await runVotingFlowScenario({
            participantCount,
            votes: buildVotes(participantCount),
        });
        const votingFlowMs = performance.now() - votingFlowStart;

        if (result.finalState.phase !== 'completed') {
            throw new Error(
                `Expected a completed scenario for participant count ${participantCount}`,
            );
        }

        const verifyStart = performance.now();
        await verifyDKGTranscript({
            protocol: 'gjkr',
            transcript: result.dkgTranscript,
            manifest: result.manifest,
            sessionId: result.sessionId,
            complaintResolutions: result.complaintResolutionRecords,
        });
        const verifyTranscriptMs = performance.now() - verifyStart;

        rows.push({
            participantCount,
            threshold: majorityThreshold(participantCount),
            transcriptMessages: result.dkgTranscript.length,
            votingFlowMs: round(votingFlowMs),
            verifyTranscriptMs: round(verifyTranscriptMs),
        });
    }

    console.table(rows);
};

void main();
