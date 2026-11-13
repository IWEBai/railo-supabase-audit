import { createClient } from "npm:@supabase/supabase-js@2";

// Exports all bookings as CSV for the accounting spreadsheet. Admins only.
Deno.serve(async (req) => {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader) return new Response("Unauthorized", { status: 401 });

  // Identify the caller from their own JWT, using the public anon key.
  const asCaller = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, {
    global: { headers: { Authorization: authHeader } },
  });
  const { data: { user } } = await asCaller.auth.getUser();
  if (!user || user.app_metadata?.is_admin !== true) {
    return new Response("Forbidden", { status: 403 });
  }

  // Only now use the service role, server-side.
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
  const { data } = await admin.from("bookings").select("destination, passport_number, total_cents");
  const rows = (data ?? []).map((b) => `${b.destination},${b.passport_number},${b.total_cents}`);
  return new Response(["destination,passport,total_cents", ...rows].join("\n"), {
    headers: { "Content-Type": "text/csv" },
  });
});
