const { createClient } = require("@supabase/supabase-js");

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: "Method not allowed" })
    };
  }

  try {
    const token = event.headers.authorization?.replace("Bearer ", "");

    if (!token) {
      throw new Error("Sign in required");
    }

    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY
    );

    const { data: authData, error: authError } =
      await supabase.auth.getUser(token);

    if (authError || !authData.user) {
      throw new Error("Invalid login");
    }

    if (
      authData.user.email.toLowerCase() !==
      process.env.ADMIN_EMAIL.toLowerCase()
    ) {
      throw new Error("Administrator access only");
    }

    const admin = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_ROLE_KEY
    );

    const body = JSON.parse(event.body || "{}");
    let result;

    if (body.action === "list") {
      result = await admin.auth.admin.listUsers();
    } else if (body.action === "create") {
      if (!body.email || !body.password || body.password.length < 8) {
        throw new Error("Enter an email and password of at least 8 characters");
      }

      result = await admin.auth.admin.createUser({
        email: body.email,
        password: body.password,
        email_confirm: true
      });
    } else if (body.action === "suspend") {
      result = await admin.auth.admin.updateUserById(
        body.userId,
        { ban_duration: "876000h" }
      );
    } else if (body.action === "reactivate") {
      result = await admin.auth.admin.updateUserById(
        body.userId,
        { ban_duration: "none" }
      );
    } else if (body.action === "delete") {
      if (body.userId === authData.user.id) {
        throw new Error("You cannot delete your own administrator account");
      }

      result = await admin.auth.admin.deleteUser(body.userId);
    } else {
      throw new Error("Unknown action");
    }

    if (result.error) throw result.error;

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        success: true,
        users: result.data?.users || [],
        user: result.data?.user || null
      })
    };
  } catch (error) {
    return {
      statusCode: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: error.message })
    };
  }
};
