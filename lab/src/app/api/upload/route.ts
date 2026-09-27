import { NextRequest } from "next/server";
import fs from "fs";
import path from "path";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const UPLOAD_DIR = path.join(process.cwd(), "uploads");

export async function POST(req: NextRequest) {
  const form = await req.formData();
  const file = form.get("file");
  if (!(file instanceof File)) {
    return Response.json({ ok: false, error: "no file" }, { status: 400 });
  }
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  const name = file.name.replace(/[^a-zA-Z0-9._-]/g, "_");
  const data = Buffer.from(await file.arrayBuffer());
  fs.writeFileSync(path.join(UPLOAD_DIR, name), data);
  return Response.json({ ok: true, name, bytes: data.length });
}
