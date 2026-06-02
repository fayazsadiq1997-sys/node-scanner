import { parse } from "@typescript-eslint/parser";
import type { TSESTree } from "@typescript-eslint/types";

/**
 * Parses source text into an AST.
 * Returns null if the file can't be parsed (syntax errors, unsupported syntax).
 */
export function parseAST(content: string, filename: string): TSESTree.Program | null {
  try {
    return parse(content, {
      jsx: /\.[jt]sx$/.test(filename),
      range: false,
      loc: true,
      tokens: false,
      comment: false,
      errorOnUnknownASTType: false,
    });
  } catch {
    return null;
  }
}

/**
 * Walks every node in the AST, calling visitor for each.
 * Visitor returns true to stop traversal early.
 */
export function walk(node: TSESTree.Node | null | undefined, visitor: (node: TSESTree.Node) => boolean | void): void {
  if (!node || typeof node !== "object") return;

  const stop = visitor(node);
  if (stop === true) return;

  for (const key of Object.keys(node) as (keyof typeof node)[]) {
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item === "object" && "type" in item) {
          walk(item as TSESTree.Node, visitor);
        }
      }
    } else if (child && typeof child === "object" && "type" in child) {
      walk(child as TSESTree.Node, visitor);
    }
  }
}

/** Collects all nodes matching a given AST type string. */
export function findAll<T extends TSESTree.Node>(
  root: TSESTree.Node,
  type: string
): T[] {
  const results: T[] = [];
  walk(root, (node) => {
    if (node.type === type) results.push(node as T);
  });
  return results;
}
