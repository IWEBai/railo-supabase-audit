import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { supabaseAdmin } from "@/integrations/supabase/admin";

export default function AdminDashboard() {
  const [bookings, setBookings] = useState<any[]>([]);
  const [isAdmin, setIsAdmin] = useState(false);

  useEffect(() => {
    supabase.auth.getUser().then(({ data }) => {
      // Only admins see this page.
      setIsAdmin(data.user?.user_metadata?.is_admin === true);
    });
    supabaseAdmin.from("bookings").select("*").then(({ data }) => setBookings(data ?? []));
  }, []);

  if (!isAdmin) return <p>Not authorised.</p>;
  return (
    <table>
      <tbody>
        {bookings.map((b) => (
          <tr key={b.id}>
            <td>{b.destination}</td>
            <td>{b.passport_number}</td>
            <td>{(b.total_cents / 100).toFixed(2)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
