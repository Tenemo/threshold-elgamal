import { performance } from 'node:perf_hooks';

import { majorityThreshold, type GroupName } from '../../src/core/index.js';
import { verifyDKGTranscript } from '../../src/dkg/index.js';
import type { KeyAgreementSuite } from '../../src/transport/index.js';
import { runVotingFlowScenario } from '../../tests/node/integration/voting-flow-harness.js';

type BenchmarkRow = {
    readonly group: GroupName;
    readonly participantCount: number;
    readonly threshold: number;
    readonly transcriptMessages: number;
    readonly transportSuite: KeyAgreementSuite;
    readonly verifyTranscriptMs: number;
    readonly votingFlowMs: number;
};

const round = (value: number): number => Math.round(value * 1_000) / 1_000;

const buildVotes = (participantCount: number): readonly bigint[] =>
    Array.from({ length: participantCount }, (_value, index) =>
        BigInt((index % 10) + 1),
    );

const parseArgs = (): {
    readonly group: GroupName;
    readonly participantCounts: readonly number[];
    readonly transportSuite: KeyAgreementSuite;
} => {
    const provided = process.argv
        .slice(2)
        .map((argument) => argument.trim())
        .filter((argument) => argument !== '');
    let group: GroupName = 'ffdhe3072';
    let transportSuite: KeyAgreementSuite = 'X25519';

    const participantArguments = provided.filter((argument) => {
        if (argument.startsWith('--group=')) {
            group = argument.slice('--group='.length) as GroupName;
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
            ? [3, 11, 21, 31, 41, 51]
            : participantArguments
                  .flatMap((argument) => argument.split(','))
                  .map((argument) => argument.trim())
                  .filter((argument) => argument !== '')
                  .map((argument) => {
                      const participantCount = Number(argument);
                      if (
                          !Number.isInteger(participantCount) ||
                          participantCount < 2
                      ) {
                          throw new Error(
                              `Invalid participant count "${argument}". Use integers >= 2.`,
                          );
                      }

                      return participantCount;
                  });

    return {
        group,
        participantCounts,
        transportSuite,
    };
};

const main = async (): Promise<void> => {
    const { participantCounts, group, transportSuite } = parseArgs();
    const rows: BenchmarkRow[] = [];

    for (const participantCount of participantCounts) {
        const votingFlowStart = performance.now();
        const result = await runVotingFlowScenario({
            participantCount,
            votes: buildVotes(participantCount),
            group,
            transportSuite,
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
        });
        const verifyTranscriptMs = performance.now() - verifyStart;

        rows.push({
            group,
            participantCount,
            threshold: majorityThreshold(participantCount),
            transcriptMessages: result.dkgTranscript.length,
            transportSuite,
            votingFlowMs: round(votingFlowMs),
            verifyTranscriptMs: round(verifyTranscriptMs),
        });
    }

    console.table(rows);
};

void main();
