import { readFile } from "node:fs/promises";
import path from "node:path";
import index from "@/data/index.json";

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  if (!index.some((item) => item.id === id)) return new Response("Unknown run", { status: 404 });
  const file = path.join(process.cwd(), "data", `${id}.json`);
  const body = await readFile(file, "utf8");
  return new Response(body, { headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
}
