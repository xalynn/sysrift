require "http/client"

def mod_cloud : Nil
  section("Cloud Environment")

  provider = Data.cloud_provider
  context  = Data.cloud_context

  if provider && context
    med("Cloud environment detected: #{context}")
  else
    info("No cloud environment indicators found")
  end

  CLOUD_CLI_TOOLS.each do |tool|
    if path = Process.find_executable(tool[:binary])
      info("#{tool[:provider]} CLI found: #{path}")
    end
  end

  scan_cloud_cred_files

  routes = read_file("/proc/net/route")
  routes.each_line do |row|
    cols = row.split
    # destination field is little-endian hex; A9FEA9FE = 169.254.169.254
    if cols.size >= 2 && cols[1] == "FEA9FEA9"
      info("Metadata route present in routing table (169.254.169.254)")
      break
    end
  end

  if File.exists?("/etc/cloud/cloud.cfg")
    info("cloud-init configuration present")
  end

  if Data.active_mode? && provider
    blank
    tee("#{Y}Active cloud metadata enumeration:#{RS}")
    case provider
    when "aws_ecs"      then enumerate_aws_ecs
    when "aws_ec2"      then enumerate_aws_ec2
    when "aws_lambda"   then enumerate_aws_lambda
    when "aws_codebuild" then enumerate_aws_codebuild
    when "gcp", "gcp_function" then enumerate_gcp
    when "azure"        then enumerate_azure_vm
    when "azure_app"    then enumerate_azure_app
    when "do"           then enumerate_do
    when "ibm"          then enumerate_ibm
    end
  elsif provider
    blank
    info("Cloud metadata endpoints available — run in active mode to enumerate")
  end
end

private def scan_cloud_cred_files : Nil
  Data.passwd.each_line do |entry|
    pw = entry.split(":")
    next unless pw.size >= 6
    homedir = pw[5]
    next if homedir.empty?
    CLOUD_CRED_PATHS.each do |cred|
      path = "#{homedir}#{cred[:path]}"
      if File.exists?(path) && File::Info.readable?(path)
        med("#{cred[:provider]} #{cred[:desc]}: #{path}")
      end
    end
  end
end

private def enumerate_aws_ec2 : Nil
  # v2 requires a PUT-based session token; v1 is unauthenticated GET
  token = imds_put("http://169.254.169.254/latest/api/token",
    headers: HTTP::Headers{"X-aws-ec2-metadata-token-ttl-seconds" => "21600"})

  hdrs = token ? HTTP::Headers{"X-aws-ec2-metadata-token" => token} : nil
  version = token ? "IMDSv2" : "IMDSv1"

  instance_id = imds_get("http://169.254.169.254/latest/meta-data/instance-id", hdrs)
  unless instance_id
    info("IMDS not reachable")
    return
  end
  info("Instance ID: #{instance_id} (#{version})")

  region = imds_get("http://169.254.169.254/latest/meta-data/placement/region", hdrs)
  info("Region: #{region}") if region
  itype = imds_get("http://169.254.169.254/latest/meta-data/instance-type", hdrs)
  info("Instance type: #{itype}") if itype

  role_list = imds_get("http://169.254.169.254/latest/meta-data/iam/security-credentials/", hdrs)
  if role_list && !role_list.empty?
    role = role_list.split("\n").first.strip
    creds = imds_get("http://169.254.169.254/latest/meta-data/iam/security-credentials/#{role}", hdrs)
    if creds && creds.includes?("AccessKeyId")
      hi("IAM role credentials retrieved via #{version}: #{role}")
      tee(indent_preview(creds, 8))
    else
      med("IAM role attached: #{role} (credentials response format unexpected)")
    end
  end

  user_data = imds_get("http://169.254.169.254/latest/user-data", hdrs)
  if user_data && !user_data.empty?
    med("User data available (#{user_data.size} bytes) — may contain bootstrap secrets")
    tee(indent_preview(user_data, 5))
  end
end

private def enumerate_aws_ecs : Nil
  meta_uri = ENV["ECS_CONTAINER_METADATA_URI_v4"]? || ENV["ECS_CONTAINER_METADATA_URI"]?
  if meta_uri
    task_meta = imds_get("#{meta_uri}/task")
    if task_meta
      info("ECS task metadata retrieved")
      tee(indent_preview(task_meta, 5))
    end
  end

  # Task-level creds live on a different link-local (170.2, not 169.254)
  cred_uri = ENV["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"]?
  if cred_uri
    creds = imds_get("http://169.254.170.2#{cred_uri}")
    if creds && creds.includes?("AccessKeyId")
      hi("ECS task IAM credentials retrieved")
      tee(indent_preview(creds, 8))
    end
  end

  # IMDSv2 from inside a container — blocked by default (hop-limit=1 on awsvpc)
  token = imds_put("http://169.254.169.254/latest/api/token",
    headers: HTTP::Headers{"X-aws-ec2-metadata-token-ttl-seconds" => "21600"})
  if token
    med("Host IMDS reachable from container (hop-limit > 1)")
  else
    info("Host IMDS not reachable from container (expected — hop-limit=1 default)")
  end
end

private def enumerate_aws_lambda : Nil
  if api = ENV["AWS_LAMBDA_RUNTIME_API"]?
    info("Lambda runtime API: #{api}")
  end
  ENV.each do |k, v|
    info("  #{k}=#{v}") if k.starts_with?("AWS_LAMBDA_") || k == "AWS_EXECUTION_ENV"
  end
  # Lambda injects short-lived STS creds into the environment
  %w[AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN].each do |k|
    hi("Lambda IAM credentials in environment: #{k}") if ENV[k]?
  end
end

private def enumerate_aws_codebuild : Nil
  env_file = read_file("/codebuild/output/tmp/env.sh")
  return if env_file.empty?
  info("CodeBuild environment file found")
  env_file.each_line do |row|
    next unless row.includes?("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
    if m = row.match(/=(.+)/)
      uri = m[1].strip.tr("\"'", "")
      creds = imds_get("http://169.254.170.2#{uri}")
      if creds && creds.includes?("AccessKeyId")
        hi("CodeBuild task IAM credentials retrieved")
        tee(indent_preview(creds, 8))
      end
    end
  end
end

private def enumerate_gcp : Nil
  hdrs = HTTP::Headers{"Metadata-Flavor" => "Google"}

  project = imds_get("http://metadata.google.internal/computeMetadata/v1/project/project-id", hdrs)
  unless project
    info("GCP metadata server not reachable")
    return
  end
  info("GCP project: #{project}")

  zone = imds_get("http://metadata.google.internal/computeMetadata/v1/instance/zone", hdrs)
  info("Zone: #{zone}") if zone

  sa_list = imds_get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/", hdrs)
  if sa_list
    sa_list.split("\n").each do |entry|
      acct = entry.strip.chomp("/")
      next if acct.empty? || acct == "default"
      tok = imds_get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/#{acct}/token", hdrs)
      hi("GCP service account token retrieved: #{acct}") if tok && tok.includes?("access_token")
      scopes = imds_get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/#{acct}/scopes", hdrs)
      info("  Scopes: #{scopes.split("\n").join(", ")}") if scopes
    end
  end

  ssh_keys = imds_get("http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys", hdrs)
  if ssh_keys && !ssh_keys.empty?
    med("GCP project SSH keys available (#{ssh_keys.split("\n").size} entries)")
  end
end

private def enumerate_azure_vm : Nil
  hdrs = HTTP::Headers{"Metadata" => "true"}

  instance = imds_get("http://169.254.169.254/metadata/instance?api-version=2021-12-13", hdrs)
  unless instance
    info("Azure IMDS not reachable")
    return
  end
  info("Azure instance metadata retrieved")
  tee(indent_preview(instance, 5))

  # Each resource URI maps to a different Azure control plane
  {
    "https://management.azure.com/" => "Azure Management",
    "https://graph.microsoft.com/"  => "Microsoft Graph",
    "https://vault.azure.net/"      => "Azure Key Vault",
    "https://storage.azure.com/"    => "Azure Storage",
  }.each do |resource, label|
    tok = imds_get(
      "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=#{resource}",
      hdrs)
    hi("#{label} token retrieved via managed identity") if tok && tok.includes?("access_token")
  end

  user_data = imds_get("http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-12-13&format=text", hdrs)
  if user_data && !user_data.empty?
    med("Azure user data available (base64, #{user_data.size} bytes)")
  end
end

private def enumerate_azure_app : Nil
  endpoint = ENV["IDENTITY_ENDPOINT"]?
  header   = ENV["IDENTITY_HEADER"]?
  return unless endpoint && header

  hdrs = HTTP::Headers{"X-IDENTITY-HEADER" => header}
  {
    "https://management.azure.com/" => "Azure Management",
    "https://graph.microsoft.com/"  => "Microsoft Graph",
    "https://vault.azure.net/"      => "Azure Key Vault",
  }.each do |resource, label|
    tok = imds_get("#{endpoint}?api-version=2019-08-01&resource=#{resource}", hdrs)
    hi("#{label} token retrieved via App Service managed identity") if tok && tok.includes?("access_token")
  end
end

private def enumerate_do : Nil
  droplet_id = imds_get("http://169.254.169.254/metadata/v1/id")
  unless droplet_id
    info("DO metadata service not reachable")
    return
  end
  info("Droplet ID: #{droplet_id}")

  region = imds_get("http://169.254.169.254/metadata/v1/region")
  info("Region: #{region}") if region

  user_data = imds_get("http://169.254.169.254/metadata/v1/user-data")
  if user_data && !user_data.empty?
    med("DigitalOcean user data available (#{user_data.size} bytes)")
    tee(indent_preview(user_data, 5))
  end

  keys = imds_get("http://169.254.169.254/metadata/v1/public-keys")
  if keys && !keys.empty?
    info("Public SSH keys: #{keys.split("\n").size} entries")
  end
end

private def enumerate_ibm : Nil
  hdrs = HTTP::Headers{"Metadata-Flavor" => "ibm", "Accept" => "application/json"}

  token_resp = imds_put("http://169.254.169.254/instance_identity/v1/token?version=2022-03-01",
    headers: hdrs)
  unless token_resp
    info("IBM metadata service not reachable")
    return
  end

  m = token_resp.match(/"access_token"\s*:\s*"([^"]+)"/)
  unless m
    info("IBM metadata token format unexpected")
    return
  end
  bearer = m[1]
  auth_hdrs = HTTP::Headers{"Authorization" => "Bearer #{bearer}"}

  instance = imds_get("http://169.254.169.254/metadata/v1/instance?version=2022-03-01", auth_hdrs)
  if instance
    info("IBM instance metadata retrieved")
    tee(indent_preview(instance, 5))
  end

  iam_resp = imds_post("http://169.254.169.254/instance_identity/v1/iam_token?version=2022-03-01",
    headers: HTTP::Headers{"Authorization" => "Bearer #{bearer}", "Accept" => "application/json"})
  hi("IBM Cloud IAM token retrieved via instance identity") if iam_resp && iam_resp.includes?("access_token")
end

private def indent_preview(body : String, max_lines : Int32) : String
  "  " + body.split("\n").first(max_lines).join("\n  ")
end

private def imds_get(url : String, headers : HTTP::Headers? = nil) : String?
  imds_request("GET", url, headers)
end

private def imds_put(url : String, headers : HTTP::Headers? = nil) : String?
  imds_request("PUT", url, headers)
end

private def imds_post(url : String, headers : HTTP::Headers? = nil) : String?
  imds_request("POST", url, headers)
end

private def imds_request(method : String, url : String, headers : HTTP::Headers? = nil) : String?
  uri = URI.parse(url)
  host = uri.host.not_nil!
  tls = uri.scheme == "https"
  port = uri.port || (tls ? 443 : 80)
  client = HTTP::Client.new(host, port, tls: tls)
  client.connect_timeout = 2.seconds
  client.read_timeout = 2.seconds
  begin
    resp = client.exec(method, uri.request_target, headers: headers)
    return nil unless resp.status_code == 200
    body = resp.body.strip
    body.empty? ? nil : body
  ensure
    client.close
  end
rescue IO::Error | Socket::Error | IO::TimeoutError | ArgumentError | OpenSSL::SSL::Error
  nil
end
