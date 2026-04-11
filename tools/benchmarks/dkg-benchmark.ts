import { performance } from 'node:perf_hooks';
import { verifyDKGTranscript } from 'threshold-elgamal';

import { runVotingFlowScenario } from '../../dev-support/voting-flow-harness.js';

type BenchmarkRow = {
    readonly optionCount: number;
    readonly participantCount: number;
    readonly threshold: number;
    readonly transcriptMessages: number;
    readonly verifyTranscriptMs: number;
    readonly votingFlowMs: number;
};
const round = (value: number): number => Math.round(value * 1000) / 1000;
const formatDurationMs = (value: number): string => {
    const rounded = round(value);
    if (rounded < 1000) {
        return `${rounded} ms`;
    }
    const totalSeconds = rounded / 1000;
    if (totalSeconds < 60) {
        return `${round(totalSeconds)} s`;
    }
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = round(totalSeconds % 60);
    const parts = [
        hours > 0 ? `${hours} h` : null,
        minutes > 0 || hours > 0 ? `${minutes} min` : null,
        `${seconds} s`,
    ].filter((part): part is string => part !== null);
    return parts.join(' ');
};
const parseArgs = (): {
    readonly optionCount: number;
    readonly participantCounts: readonly number[];
} => {
    const provided = process.argv
        .slice(2)
        .map((argument) => argument.trim())
        .filter((argument) => argument !== '' && argument !== '--');
    let optionCount = 1;
    const participantArguments = provided.filter((argument) => {
        if (argument.startsWith('--options=')) {
            optionCount = Number(argument.slice('--options='.length));
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
        optionCount,
        participantCounts,
    };
};
const main = async (): Promise<void> => {
    const { participantCounts, optionCount } = parseArgs();
    const rows: BenchmarkRow[] = [];
    const benchmarkStart = performance.now();
    for (const [index, participantCount] of participantCounts.entries()) {
        const step = index + 1;
        const totalSteps = participantCounts.length;
        console.log(
            `[${step}/${totalSteps}] Starting n=${participantCount}, options=${optionCount}, group=ristretto255, transport=X25519`,
        );
        console.log(`[${step}/${totalSteps}] Stage 1/2: full voting flow`);
        const votingFlowStart = performance.now();
        const result = await runVotingFlowScenario({
            closeParticipantIndices: Array.from(
                { length: participantCount },
                (_value, offset) => offset + 1,
            ),
            optionCount,
            optionList: Array.from(
                { length: optionCount },
                (_value, optionOffset) => `Option ${optionOffset + 1}`,
            ),
            participantCount,
            votingParticipantIndices: Array.from(
                { length: participantCount },
                (_value, offset) => offset + 1,
            ),
        });
        const votingFlowMs = performance.now() - votingFlowStart;
        console.log(
            `[${step}/${totalSteps}] Stage 1/2 complete in ${formatDurationMs(votingFlowMs)} with ${result.dkgTranscript.length} transcript messages`,
        );
        console.log(
            `[${step}/${totalSteps}] Stage 2/2: transcript verification`,
        );
        const verifyStart = performance.now();
        await verifyDKGTranscript({
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
            optionCount,
            participantCount,
            threshold: result.threshold,
            transcriptMessages: result.dkgTranscript.length,
            votingFlowMs: round(votingFlowMs),
            verifyTranscriptMs: round(verifyTranscriptMs),
        });
    }
    console.table(rows);
};
void main();
