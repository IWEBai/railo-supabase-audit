import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";

export default function AdminDashboard() {
  const [csv, setCsv] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // The export function checks the caller's JWT and admin flag on the server.
    // Hiding this page is only for convenience; it is not what protects the data.
    supabase.functions.invoke("export-bookings").then(({ data, error }) => {
      if (error) setError("Not authorised.");
      else setCsv(data as string);
    });
  }, []);

  if (error) return <p>{error}</p>;
  return <pre>{csv ?? "Loading..."}</pre>;
}
