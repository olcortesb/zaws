const std = @import("std");

pub const Credentials = struct {
    access_key_id: [:0]const u8,
    secret_access_key: [:0]const u8,
    session_token: ?[:0]const u8 = null, // only for temporal roles
};

pub fn resolve(environ: std.process.Environ) !Credentials {
    return .{
        .access_key_id = environ.getPosix("AWS_ACCESS_KEY_ID") orelse return error.MissingAccessKey,
        .secret_access_key = environ.getPosix("AWS_SECRET_ACCESS_KEY") orelse return error.MissingSecretKey,
        .session_token = environ.getPosix("AWS_SESSION_TOKEN"), // null si no existe, está bien
    };
}

test "resolve credentials from env" {
    // En el entorno de test no van a existir las vars AWS, así que esperamos error
    const result = resolve(std.testing.environ);
    try std.testing.expectError(error.MissingAccessKey, result);
}
