import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405, headers: corsHeaders });

  try {
    const url = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const colleagueUserId = Deno.env.get("BUTDETAL_COLLEAGUE_USER_ID");
    if (!url || !anonKey || !serviceKey || !colleagueUserId) {
      return Response.json({ error: "Server function is not configured." }, { status: 503, headers: corsHeaders });
    }

    const authHeader = req.headers.get("Authorization") ?? "";
    const callerClient = createClient(url, anonKey, {
      global: { headers: { Authorization: authHeader } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: { user }, error: userError } = await callerClient.auth.getUser();
    if (userError || !user) return Response.json({ error: "Unauthorized." }, { status: 401, headers: corsHeaders });

    const { data: profile, error: profileError } = await callerClient
      .from("profiles").select("role").eq("user_id", user.id).single();
    if (profileError || profile?.role !== "admin") {
      return Response.json({ error: "Administrator access required." }, { status: 403, headers: corsHeaders });
    }

    const body = await req.json();
    const password = typeof body.password === "string" ? body.password : "";
    if (password.length < 12 || password.length > 72) {
      return Response.json({ error: "Password must contain 12–72 characters." }, { status: 400, headers: corsHeaders });
    }

    const adminClient = createClient(url, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { error: updateError } = await adminClient.auth.admin.updateUserById(colleagueUserId, { password });
    if (updateError) return Response.json({ error: "Could not update colleague password." }, { status: 400, headers: corsHeaders });

    return Response.json({ ok: true }, { headers: corsHeaders });
  } catch (_error) {
    return Response.json({ error: "Unexpected server error." }, { status: 500, headers: corsHeaders });
  }
});
