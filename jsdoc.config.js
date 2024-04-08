BigInt.prototype.toJSON = function () {
    return this.toString() + 'n';
};
module.exports = {
    opts: {
        template: 'node_modules/docdash',
    },
    plugins: ['plugins/markdown'],
    docdash: {
        static: true,
        sort: true,
        search: true,
        collapse: true,
        typedefs: true,
        removeQuotes: 'none',
        scripts: [],
        menu: {
            'Github repo': {
                href: 'https://github.com/Tenemo/threshold-elgamal',
                target: '_blank',
                class: 'menu-item',
                id: 'repository',
            },
        },
    },
    templates: {
        default: {
            useLongnameInNav: true,
        },
    },
};
