import { NextRequest } from "next/server";
import sharp from "sharp";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const UPLOAD_DIR = process.cwd() + "/uploads";

export async function GET(req: NextRequest) {
  const requested = req.nextUrl.searchParams.get("file") || "sample.avif";
  const name = requested.replace(/[^a-zA-Z0-9._-]/g, "_");
  const result = await sharp(UPLOAD_DIR + "/" + name).png().toBuffer();
  return new Response(result, {
    headers: {
      "Content-Type": "image/png",
      "Content-Length": String(result.length),
      "X-Optimized-By": "sharp/libheif"
    }
  });
}
