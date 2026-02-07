type MonacoLike = {
  editor: {
    defineTheme: (name: string, data: unknown) => void;
  };
};

export const SOTH_MONACO_THEME = "soth-terminal-ops";

export function defineSothMonacoTheme(monaco: MonacoLike): void {
  monaco.editor.defineTheme(SOTH_MONACO_THEME, {
    base: "vs-dark",
    inherit: true,
    rules: [
      { token: "comment", foreground: "9F9F9F" },
      { token: "string", foreground: "D97757" },
      { token: "number", foreground: "D97757" },
      { token: "keyword", foreground: "653626" },
      { token: "operator", foreground: "9F9F9F" },
      { token: "delimiter", foreground: "9F9F9F" },
      { token: "type", foreground: "FFFFFF" },
      { token: "identifier", foreground: "FFFFFF" },
    ],
    colors: {
      "editor.background": "#000000",
      "editor.foreground": "#FFFFFF",
      "editorLineNumber.foreground": "#9F9F9F",
      "editorLineNumber.activeForeground": "#D97757",
      "editor.selectionBackground": "#65362666",
      "editor.selectionHighlightBackground": "#65362633",
      "editorCursor.foreground": "#D97757",
      "editorIndentGuide.background1": "#161616",
      "editorIndentGuide.activeBackground1": "#653626",
      "editorGutter.background": "#000000",
      "editorLineHighlightBackground": "#0E0E0E",
      "editorBracketMatch.background": "#65362622",
      "editorBracketMatch.border": "#653626",
    },
  });
}
