import { createClient } from "@supabase/supabase-js";

// Admin client so the dashboard can see every booking.
export const supabaseAdmin = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY,
);
