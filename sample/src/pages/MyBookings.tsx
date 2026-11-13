import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";

export default function MyBookings({ userId }: { userId: string }) {
  const [bookings, setBookings] = useState<any[]>([]);

  useEffect(() => {
    // Show only this user's bookings.
    supabase
      .from("bookings")
      .select("*")
      .eq("client_id", userId)
      .then(({ data }) => setBookings(data ?? []));
  }, [userId]);

  return (
    <ul>
      {bookings.map((b) => (
        <li key={b.id}>{b.destination}</li>
      ))}
    </ul>
  );
}
