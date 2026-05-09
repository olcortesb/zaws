const std = @import("std");
pub const credential = @import("credential.zig");
pub const signing = @import("signing.zig");
pub const http = @import("http.zig");

pub fn getEnvVar(environ: std.process.Environ, key: []const u8) ?[:0]const u8 {
    return environ.getPosix(key);
}

test "check path" {
    const path = getEnvVar(std.testing.environ, "PATH");
    try std.testing.expect(path != null);
}

test {
    _ = credential;
    _ = signing;
    _ = http;
}
