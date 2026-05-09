const std = @import("std");
const signing = @import("signing.zig");
const credential = @import("credential.zig");

pub fn sendRequest(allocator: std.mem.Allocator, info: signing.RequestInfo, creds: credential.Credentials, date: []const u8, region: []const u8, service: []const u8) ![]const u8 {
    // 1. Firmar
    var sign_buf: [1024]u8 = undefined;
    const auth_header = try signing.sign(&sign_buf, info, date, region, service, creds.secret_access_key, creds.access_key_id);

    // 2. Construir URL
    const url = try std.fmt.allocPrint(allocator, "https://{s}{s}", .{ info.host, info.path });
    defer allocator.free(url);

    // 3. Setup I/O + Client
    var threaded: std.Io.Threaded = .init(allocator, .{});
    const io = threaded.io();
    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    // 4. Hacer request
    const uri = try std.Uri.parse(url);
    var req = try client.request(.GET, uri, .{
        .extra_headers = &.{
            .{ .name = "Authorization", .value = auth_header },
            .{ .name = "x-amz-date", .value = info.amz_date },
            .{ .name = "host", .value = info.host },
        },
    });
    defer req.deinit();

    try req.sendBodiless();

    var header_buf: [8 * 1024]u8 = undefined;
    var response = try req.receiveHead(&header_buf);

    // 5. Leer body
    var reader = response.reader(&.{});
    const body = try reader.allocRemaining(allocator, .unlimited);
    return body;
}

test "sendRequest compiles" {
    // Solo verifica que los tipos son correctos
    _ = sendRequest;
}

test "real request to s3" {
    const allocator = std.testing.allocator;
    const environ = std.testing.environ;

    const creds = credential.Credentials{
        .access_key_id = environ.getPosix("AWS_ACCESS_KEY_ID") orelse return,
        .secret_access_key = environ.getPosix("AWS_SECRET_ACCESS_KEY") orelse return,
    };

    const info = signing.RequestInfo{
        .method = "GET",
        .path = "/",
        .query = "",
        .host = "s3.us-east-1.amazonaws.com",
        .amz_date = "20250507T160000Z",
        .body = "",
    };

    const response = try sendRequest(allocator, info, creds, "20250507", "us-east-1", "s3");
    defer allocator.free(response);
    std.debug.print("response: {s}\n", .{response});
}
