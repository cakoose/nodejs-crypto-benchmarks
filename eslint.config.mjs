import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import stylistic from '@stylistic/eslint-plugin';
import globals from 'globals';

export default tseslint.config(
    {
        ignores: ['dist/', '.idea/'],
    },
    eslint.configs.recommended,
    tseslint.configs.recommended,
    {
        plugins: {
            '@stylistic': stylistic,
        },
        languageOptions: {
            globals: {
                ...globals.node,
            },
        },
        rules: {
            'no-loss-of-precision': 'error',
            'no-promise-executor-return': 'error',
            'no-useless-backreference': 'error',
            'require-atomic-updates': 'error',
            'default-param-last': 'error',
            'default-case-last': 'error',
            'eqeqeq': 'error',
            'guard-for-in': 'error',
            'no-caller': 'error',
            'no-implicit-coercion': 'error',
            'no-implied-eval': 'error',
            'no-octal-escape': 'error',
            'no-sequences': 'error',
            'no-unused-expressions': 'error',
            'no-useless-call': 'error',
            'no-useless-return': 'error',
            'no-void': 'error',
            'radix': 'error',
            '@stylistic/dot-location': ['error', 'property'],
            '@stylistic/no-floating-decimal': 'error',
            '@stylistic/no-multi-spaces': 'error',
            '@stylistic/array-bracket-spacing': ['error', 'never'],
            '@stylistic/comma-dangle': ['error', 'only-multiline'],
            '@stylistic/comma-spacing': 'error',
            '@stylistic/eol-last': 'error',
            '@stylistic/semi': 'error',
            '@stylistic/semi-spacing': 'error',
            '@stylistic/semi-style': 'error',
            '@typescript-eslint/no-explicit-any': 'off',
            '@typescript-eslint/no-unused-vars': ['error', {
                argsIgnorePattern: '^_',
                varsIgnorePattern: '^_',
                caughtErrorsIgnorePattern: '^_',
            }],
            'no-restricted-syntax': ['error', {
                selector: ':not(VariableDeclarator, FunctionDeclaration, ArrowFunctionExpression, FunctionExpression, CatchClause, Property[shorthand=false], AssignmentPattern) > Identifier[name=/^_./]',
                message: 'Variables prefixed with "_" are intentionally unused and must not be referenced.',
            }],
        },
    }
);
