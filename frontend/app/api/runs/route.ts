import index from "@/data/index.json";

export async function GET() {
  return Response.json(index, { headers: { "Cache-Control": "no-store" } });
}
