resource "aws_s3_bucket" "public" {
  bucket = "aegis-fixture-public"
}
resource "aws_s3_bucket_public_access_block" "public" {
  bucket = aws_s3_bucket.public.id
  block_public_acls = false
  block_public_policy = false
}
