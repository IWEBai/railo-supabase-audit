import { createClient } from "npm:@supabase/supabase-js@2";

// Exports all bookings as CSV for the accounting spreadsheet.
Deno.serve(async () => {
  const admin = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );
  const { data } = await admin.from("bookings").select("destination, passport_number, total_cents");
  const rows = (data ?? []).map((b) => `${b.destination},${b.passport_number},${b.total_cents}`);
  return new Response(["destination,passport,total_cents", ...rows].join("\n"), {
    headers: { "Content-Type": "text/csv" },
  });
});
