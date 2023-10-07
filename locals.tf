locals {
  name = "weather-southkorea"

  region   = "ap-northeast-2"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)
  vpc_cidr = "10.0.0.0/16"

  s3_bucket_data 	     = "weather-southkorea-data"
  s3_bucket_spark            = "weather-southkorea-spark"
  s3_dir_spark_historyserver = "spark-history"
}
