const std = @import("std");

pub const RequestInfo = struct {
    method: []const u8, // "GET", "POST", etc.
    path: []const u8, // "/my-bucket"
    query: []const u8, // "" si no hay query string
    host: []const u8, // "s3.us-east-1.amazonaws.com"
    amz_date: []const u8, // "20250507T152300Z"
    body: []const u8, // "" para GET
};

pub fn hmac(key: []const u8, message: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&out, message, key);
    return out;
}

pub fn deriveSigningKey(secret: []const u8, date: []const u8, region: []const u8, service: []const u8) [32]u8 {
    var key_buf: [256]u8 = undefined;
    const prefix = "AWS4";
    @memcpy(key_buf[0..prefix.len], prefix);
    @memcpy(key_buf[prefix.len..][0..secret.len], secret);
    const full_key = key_buf[0 .. prefix.len + secret.len];

    const date_key = hmac(full_key, date);
    const region_key = hmac(&date_key, region);
    const service_key = hmac(&region_key, service);
    return hmac(&service_key, "aws4_request");
}

pub fn sha256(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &out, .{});
    return out;
}

pub fn canonicalRequest(buf: []u8, info: RequestInfo) ![]const u8 {
    const body_hash = sha256(info.body);
    return std.fmt.bufPrint(buf, "{s}\n{s}\n{s}\nhost:{s}\nx-amz-date:{s}\n\nhost;x-amz-date\n{x}", .{
        info.method,
        info.path,
        info.query,
        info.host,
        info.amz_date,
        body_hash,
    });
}

pub fn stringToSign(buf: []u8, amz_date: []const u8, date: []const u8, region: []const u8, service: []const u8, canonical_req: []const u8) ![]const u8 {
    const canonical_hash = sha256(canonical_req);
    return std.fmt.bufPrint(buf, "AWS4-HMAC-SHA256\n{s}\n{s}/{s}/{s}/aws4_request\n{x}", .{
        amz_date,
        date,
        region,
        service,
        canonical_hash,
    });
}

pub fn sign(buf: []u8, info: RequestInfo, date: []const u8, region: []const u8, service: []const u8, secret: []const u8, access_key: []const u8) ![]const u8 {
    var canon_buf: [1024]u8 = undefined;
    const canonical = try canonicalRequest(&canon_buf, info);

    var sts_buf: [1024]u8 = undefined;
    const sts = try stringToSign(&sts_buf, info.amz_date, date, region, service, canonical);

    const signing_key = deriveSigningKey(secret, date, region, service);
    const signature = hmac(&signing_key, sts);

    return std.fmt.bufPrint(buf, "AWS4-HMAC-SHA256 Credential={s}/{s}/{s}/{s}/aws4_request, SignedHeaders=host;x-amz-date, Signature={x}", .{
        access_key,
        date,
        region,
        service,
        signature,
    });
}

test "hmac produces 32 bytes" {
    const result = hmac("KEY", "PRAH");
    try std.testing.expect(result.len == 32);
}

test "hmac is deterministic" {
    const a = hmac("KEY", "PRAH");
    const b = hmac("KEY", "PRAH");
    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "derive signing key produces 32 bytes" {
    const key = deriveSigningKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20250507", "us-east-1", "s3");
    try std.testing.expect(key.len == 32);
}

test "canonical request format" {
    var buf: [1024]u8 = undefined;
    const info = RequestInfo{
        .method = "GET",
        .path = "/my-bucket",
        .query = "",
        .host = "s3.us-east-1.amazonaws.com",
        .amz_date = "20250507T152300Z",
        .body = "",
    };

    const result = try canonicalRequest(&buf, info);
    try std.testing.expect(std.mem.startsWith(u8, result, "GET"));
    try std.testing.expect(std.mem.indexOf(u8, result, "host:s3.us-east-1.amazonaws.com") != null);
}

test "string to sign format" {
    var canon_buf: [1024]u8 = undefined;
    const info = RequestInfo{
        .method = "GET",
        .path = "/my-bucket",
        .query = "",
        .host = "s3.us-east-1.amazonaws.com",
        .amz_date = "20250507T152300Z",
        .body = "",
    };
    const canonical = try canonicalRequest(&canon_buf, info);

    var sts_buf: [1024]u8 = undefined;
    const result = try stringToSign(&sts_buf, "20250507T152300Z", "20250507", "us-east-1", "s3", canonical);
    try std.testing.expect(std.mem.startsWith(u8, result, "AWS4-HMAC-SHA256"));
    try std.testing.expect(std.mem.indexOf(u8, result, "20250507/us-east-1/s3/aws4_request") != null);
}

test "sign produces authorization header" {
    var buf: [1024]u8 = undefined;
    const info = RequestInfo{
        .method = "GET",
        .path = "/my-bucket",
        .query = "",
        .host = "s3.us-east-1.amazonaws.com",
        .amz_date = "20250507T152300Z",
        .body = "",
    };

    const auth_header = try sign(&buf, info, "20250507", "us-east-1", "s3", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "AKIAIOSFODNN7EXAMPLE");
    try std.testing.expect(std.mem.startsWith(u8, auth_header, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE"));
    try std.testing.expect(std.mem.indexOf(u8, auth_header, "Signature=") != null);
}
