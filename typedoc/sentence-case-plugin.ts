import {
    MarkdownPageEvent,
    type MarkdownApplication,
} from 'typedoc-plugin-markdown';

const replacements: readonly (readonly [RegExp, string])[] = [
    [/\bType Aliases\b/g, 'Type aliases'],
    [/\bType Alias\b/g, 'Type alias'],
    [/\bType Declarations\b/g, 'Type declarations'],
    [/\bType Declaration\b/g, 'Type declaration'],
    [/\bType Parameters\b/g, 'Type parameters'],
    [/\bType Parameter\b/g, 'Type parameter'],
    [/\bCall Signatures\b/g, 'Call signatures'],
    [/\bCall Signature\b/g, 'Call signature'],
    [/\bIndex Signatures\b/g, 'Index signatures'],
    [/\bIndex Signature\b/g, 'Index signature'],
    [/\bDefault Value\b/g, 'Default value'],
    [/\bDefined In:\b/g, 'Defined in:'],
    [/\bImplementation Of\b/g, 'Implementation of'],
    [/\bImplemented By\b/g, 'Implemented by'],
    [/\bInherited From\b/g, 'Inherited from'],
    [/\bExtended By\b/g, 'Extended by'],
];

const rewriteSentenceCase = (content: string): string => {
    let rewritten = content;

    for (const [pattern, replacement] of replacements) {
        rewritten = rewritten.replace(pattern, replacement);
    }

    return rewritten;
};

export function load(app: MarkdownApplication): void {
    app.renderer.on(MarkdownPageEvent.END, (page): void => {
        if (typeof page.contents !== 'string') {
            return;
        }

        page.contents = rewriteSentenceCase(page.contents);
    });
}
