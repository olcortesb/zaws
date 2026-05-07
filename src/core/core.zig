pub const credentials = @import("credential.zig");
pub const signing = @import("signing.zig");
const std = @import("std");

pub fn getEnvVar(environ: std.process.Environ, key: []const u8) ?[:0]const u8 {
    return environ.getPosix(key);
}

test "check path" {
    const path = getEnvVar(std.testing.environ, "PATH") orelse "not found";
    std.debug.print("the path: {s}\n", .{path});
}
