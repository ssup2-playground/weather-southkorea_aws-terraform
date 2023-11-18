## Provider
provider "aws" {
  profile = "default"
  region = local.region
}

provider "aws" {
  alias  = "ecr"
  profile = "default"
  region = "us-east-1"
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

provider "helm" {
  # to avoid issue : https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }
}

provider "kubectl" {
  apply_retry_count      = 5
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

## Data
data "aws_availability_zones" "available" {}

data "aws_caller_identity" "current" {}

data "aws_ecrpublic_authorization_token" "token" {
  provider = aws.ecr
}

data "aws_iam_policy_document" "spark_history_assume_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [module.eks.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(module.eks.oidc_provider_arn, "/^(.*provider/)/", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "${replace(module.eks.oidc_provider_arn, "/^(.*provider/)/", "")}:sub"
      values   = ["system:serviceaccount:spark:spark-history"]
    }
  }
}

## VPC
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = format("%s-vpc", local.name)

  cidr             = local.vpc_cidr
  azs              = local.azs
  public_subnets   = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k)]
  private_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 10)]

  enable_nat_gateway   = true
  enable_dns_hostnames = true
  enable_dns_support   = true

  manage_default_network_acl    = true
  manage_default_route_table    = true
  manage_default_security_group = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1 # for AWS Load Balancer Controller
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1                            # for AWS Load Balancer Controller
    "karpenter.sh/discovery"          = format("%s-eks", local.name) # for Karpenter
  }
}

## EFS
module "efs" {
  source = "terraform-aws-modules/efs/aws"

  name = format("%s-efs", local.name)

  mount_targets = { for k, v in zipmap(local.azs, module.vpc.private_subnets) : k => { subnet_id = v } }

  attach_policy         = false
  security_group_vpc_id = module.vpc.vpc_id
  security_group_rules  = {
    vpc = {
      cidr_blocks = module.vpc.private_subnets_cidr_blocks
    }
  }
}

## EKS
module "eks" {
  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-eks", local.name)
  cluster_version = "1.26"

  vpc_id                          = module.vpc.vpc_id
  subnet_ids                      = module.vpc.private_subnets
  cluster_endpoint_public_access  = true

  eks_managed_node_groups = {
    control = {
      min_size     = 3
      max_size     = 3
      desired_size = 3

      instance_types = ["m5.large"]
      iam_role_additional_policies = {
        AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      }

      labels = {
        type = "control"
      }

      taints = {
        dedicated = {
          key    = "type"
          value  = "control"
          effect = "NO_SCHEDULE"
        }
      }
    }
  }

  ## Node Security Group
  node_security_group_tags = {
    "karpenter.sh/discovery" = format("%s-eks", local.name) # for Karpenter
  }
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }

    # for spark-operator, yunikorn
    ingress_control_to_node_all = {
      description                   = "Control plane to node all ports/protocols"
      protocol                      = "-1"
      from_port                     = 0
      to_port                       = 0
      type                          = "ingress"
      source_cluster_security_group = true
    }
  }

  manage_aws_auth_configmap = true
  aws_auth_roles = [
    {
      ## for Karpenter
      rolearn  = module.karpenter.role_arn
      username = "system:node:{{EC2PrivateDNSName}}"
      groups = [
        "system:bootstrappers",
        "system:nodes",
      ]
    }
  ]
}

## EKS / Addons
module "eks_blueprints_addons" {
  source  = "aws-ia/eks-blueprints-addons/aws"

  cluster_name      = module.eks.cluster_name
  cluster_endpoint  = module.eks.cluster_endpoint
  cluster_version   = module.eks.cluster_version
  oidc_provider_arn = module.eks.oidc_provider_arn

  eks_addons = {
    coredns = {
      most_recent = true
      configuration_values = jsonencode({
        nodeSelector: {
          type: "control"
        }
        tolerations: [
          {
            key: "type",
            value: "control",
            operator: "Equal",
            effect: "NoSchedule"
          }
        ]
      })
    }
    vpc-cni = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
  }
}

## EKS / Karpenter
module "karpenter" {
  source = "terraform-aws-modules/eks/aws//modules/karpenter"

  cluster_name = module.eks.cluster_name

  irsa_oidc_provider_arn       = module.eks.oidc_provider_arn
  iam_role_additional_policies = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
}

resource "helm_release" "karpenter" {
  namespace        = "karpenter"
  create_namespace = true

  name       = "karpenter"
  chart      = "karpenter"
  repository = "oci://public.ecr.aws/karpenter"
  version    = "v0.24.0"

  set {
    name  = "settings.aws.clusterName"
    value = module.eks.cluster_name
  }
  set {
    name  = "settings.aws.clusterEndpoint"
    value = module.eks.cluster_endpoint
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.karpenter.irsa_arn
  }
  set {
    name  = "settings.aws.defaultInstanceProfile"
    value = module.karpenter.instance_profile_name
  }
  set {
    name  = "settings.aws.interruptionQueueName"
    value = module.karpenter.queue_name
  }
  set {
    name  = "nodeSelector.type"
    value = "control"
  }
  set {
    name  = "tolerations[0].key"
    value = "type"
  }
  set {
    name  = "tolerations[0].value"
    value = "control"
  }
  set {
    name  = "tolerations[0].operator"
    value = "Equal"
  }
  set {
    name  = "tolerations[0].effect"
    value = "NoSchedule"
  }
}

resource "kubectl_manifest" "karpenter_provisioner" {
  yaml_body = <<-YAML
    apiVersion: karpenter.sh/v1alpha5
    kind: Provisioner
    metadata:
      name: default
    spec:
      consolidation:
        enabled: true
      requirements:
        - key: karpenter.sh/capacity-type
          operator: In
          values: ["on-demand"]
        - key: karpenter.k8s.aws/instance-family
          operator: In
          values: ["m5"]
        - key: karpenter.k8s.aws/instance-size
          operator: In
          values: ["large"]
      labels:
        type: service
      limits:
        resources:
          cpu: 1000
          memory: 1000Gi
      providerRef:
        name: default
  YAML

  depends_on = [
    helm_release.karpenter
  ]
}

resource "kubectl_manifest" "karpenter_node_template" {
  yaml_body = <<-YAML
    apiVersion: karpenter.k8s.aws/v1alpha1
    kind: AWSNodeTemplate
    metadata:
      name: default
    spec:
      subnetSelector:
        karpenter.sh/discovery: ${module.eks.cluster_name}
      securityGroupSelector:
        karpenter.sh/discovery: ${module.eks.cluster_name}
      tags:
        karpenter.sh/discovery: ${module.eks.cluster_name}
  YAML

  depends_on = [
    helm_release.karpenter
  ]
}

## EKS / Spark
resource "aws_iam_role" "spark_history" {
  name = format("%s-eks-emr-spark-history", local.name)

  assume_role_policy = data.aws_iam_policy_document.spark_history_assume_policy.json
  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"]
}

resource "aws_s3_bucket" "spark" {
  bucket = local.s3_bucket_spark
}

resource "aws_s3_object" "spark_history" {
  bucket = "${aws_s3_bucket.spark.id}"
  acl    = "private"
  key    = format("%s/", local.s3_dir_spark_historyserver)
  source = "/dev/null"
}

resource "helm_release" "spark_operator" {
  namespace  = "spark"
  create_namespace = true

  name       = "spark-operator"
  chart      = "spark-operator"
  repository = "https://googlecloudplatform.github.io/spark-on-k8s-operator"

  set {
    name  = "nodeSelector.type"
    value = "control"
  }
  set {
    name  = "tolerations[0].key"
    value = "type"
  }
  set {
    name  = "tolerations[0].value"
    value = "control"
  }
  set {
    name  = "tolerations[0].operator"
    value = "Equal"
  }
  set {
    name  = "tolerations[0].effect"
    value = "NoSchedule"
  }
  set {
    name = "serviceAccounts.spark.name"
    value = "spark"
  }
  set {
    name = "webhook.enable"
    value = "true"  
  }
  set {
    name = "webhook.port"
    value = "8080"
  }
  set {
    name = "uiService.enable"
    value = "true"
  }
}

resource "helm_release" "spark_history_server" {
  namespace  = "spark"
  create_namespace = true

  name       = "spark-history-server"
  chart      = "spark-history-server"
  repository = "https://hyper-mesh.github.io/spark-history-server"

  set {
    name  = "serviceAccount.create"
    value = "true"
  }
  set {
    name  = "serviceAccount.name"
    value = "spark-history"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = aws_iam_role.spark_history.arn
  }
  set {
    name  = "sparkHistoryOpts"
    value = "-Dspark.history.fs.logDirectory=s3a://${local.s3_bucket_spark}/${local.s3_dir_spark_historyserver}"
  }
  set {
    name  = "nodeSelector.type"
    value = "control"
  }
  set {
    name  = "tolerations[0].key"
    value = "type"
  }
  set {
    name  = "tolerations[0].value"
    value = "control"
  }
  set {
    name  = "tolerations[0].operator"
    value = "Equal"
  }
  set {
    name  = "tolerations[0].effect"
    value = "NoSchedule"
  }
}

## EKS / Load Balancer Controller
module "eks_load_balancer_controller_irsa_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s-eks-aws-load-balancer-controller", local.name)
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "helm_release" "aws_load_balancer_controller" {
  namespace  = "kube-system"
  name       = "aws-load-balancer-controller"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
 
  set {
    name  = "clusterName"
    value = module.eks.cluster_name
  }
  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.eks_load_balancer_controller_irsa_role.iam_role_arn
  }
  set {
    name  = "nodeSelector.type"
    value = "control"
  }
  set {
    name  = "tolerations[0].key"
    value = "type"
  }
  set {
    name  = "tolerations[0].value"
    value = "control"
  }
  set {
    name  = "tolerations[0].operator"
    value = "Equal"
  }
  set {
    name  = "tolerations[0].effect"
    value = "NoSchedule"
  }
}

## EKS / EBS CSI
module "eks_ebs_csi_irsa_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = format("%s-eks-ebs-csi", local.name)
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa"]
    }
  }
}

resource "helm_release" "aws_ebs_csi_driver" {
  namespace  = "kube-system"
  name       = "aws-ebs-csi-driver"
  chart      = "aws-ebs-csi-driver"
  repository = "https://kubernetes-sigs.github.io/aws-ebs-csi-driver/"
 
  set {
    name  = "controller.serviceAccount.name"
    value = "ebs-csi-controller-sa"
  }
  set {
    name  = "controller.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.eks_ebs_csi_irsa_role.iam_role_arn
  }
  set {
    name  = "controller.nodeSelector.type"
    value = "control"
  }
  set {
    name  = "controller.tolerations[0].key"
    value = "type"
  }
  set {
    name  = "controller.tolerations[0].value"
    value = "control"
  }
  set {
    name  = "controller.tolerations[0].operator"
    value = "Equal"
  }
  set {
    name  = "controller.tolerations[0].effect"
    value = "NoSchedule"
  }
}

resource "kubectl_manifest" "ebs_sc" {
  yaml_body = <<-YAML
    apiVersion: storage.k8s.io/v1
    kind: StorageClass
    metadata:
      name: ebs-sc
    provisioner: ebs.csi.aws.com
  YAML

  depends_on = [
    helm_release.aws_ebs_csi_driver
  ]
}

## EKS / EFS CSI
module "eks_efs_csi_irsa_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = format("%s-eks-efs-csi", local.name)
  attach_efs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:efs-csi-controller-sa"]
    }
  }
}

resource "helm_release" "aws_efs_csi_driver" {
  namespace  = "kube-system"
  name       = "aws-efs-csi-driver"
  chart      = "aws-efs-csi-driver"
  repository = "https://kubernetes-sigs.github.io/aws-efs-csi-driver/"
 
  set {
    name  = "controller.serviceAccount.name"
    value = "efs-csi-controller-sa"
  }
  set {
    name  = "controller.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.eks_efs_csi_irsa_role.iam_role_arn
  }
  set {
    name  = "controller.nodeSelector.type"
    value = "control"
  }
  set {
    name  = "controller.tolerations[0].key"
    value = "type"
  }
  set {
    name  = "controller.tolerations[0].value"
    value = "control"
  }
  set {
    name  = "controller.tolerations[0].operator"
    value = "Equal"
  }
  set {
    name  = "controller.tolerations[0].effect"
    value = "NoSchedule"
  }
}

resource "kubectl_manifest" "efs_pv" {
  yaml_body = <<-YAML
    apiVersion: v1
    kind: PersistentVolume
    metadata:
      name: efs-pv
    spec:
      capacity:
        storage: 5Gi
      volumeMode: Filesystem
      accessModes:
        - ReadWriteMany
      persistentVolumeReclaimPolicy: Retain
      storageClassName: efs-sc
      csi:
        driver: efs.csi.aws.com
        volumeHandle: ${module.efs.id}
  YAML

  depends_on = [
    helm_release.aws_efs_csi_driver
  ]
}

resource "kubectl_manifest" "efs_pvc" {
  yaml_body = <<-YAML
    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: efs-pvc
    spec:
      accessModes:
        - ReadWriteMany
      storageClassName: efs-sc
      resources:
        requests:
          storage: 5Gi
  YAML

  depends_on = [
    helm_release.aws_efs_csi_driver
  ]
}

resource "kubectl_manifest" "efs_sc" {
  yaml_body = <<-YAML
    apiVersion: storage.k8s.io/v1
    kind: StorageClass
    metadata:
      name: efs-sc
    provisioner: efs.csi.aws.com
  YAML

  depends_on = [
    helm_release.aws_efs_csi_driver
  ]
}

## EKS / Airflow 
resource "helm_release" "airflow" {
  namespace  = "airflow"
  create_namespace = true

  name       = "airflow"
  chart      = "airflow"
  repository = "https://airflow.apache.org"
  timeout    = "600"

  set {
    name  = "createUserJob.useHelmHooks"
    value = "false"
  }
  set {
    name  = "createUserJob.applyCustomEnv"
    value = "false"
  }
  set {
    name  = "migrateDatabaseJob.useHelmHooks"
    value = "false"
  }
  set {
    name  = "migrateDatabaseJob.applyCustomEnv"
    value = "false"
  }
  set {
    name  = "executor"
    value = "KubernetesExecutor"
  }
  set {
    name  = "dags.gitSync.enabled"
    value = "true"
  }
  set {
    name  = "dags.gitSync.repo"
    value = "https://github.com/ssup2-playground/weather-southkorea_airflow-dag.git"
  }
  set {
    name  = "dags.gitSync.subPath"
    value = "dags"
  }
  set {
    name  = "dags.gitSync.branch"
    value = "master"
  }
  set {
    name = "webserver.service.type"
    value = "LoadBalancer" 
  }
  set {
    name  = "webserver.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-type"
    value = "external"
  }
  set {
    name  = "webserver.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-scheme"
    value = "internet-facing"
  }
}

## Workload
resource "aws_s3_bucket" "data" {
  bucket = local.s3_bucket_data
}

resource "aws_s3_object" "data_synoptic" {
  bucket = "${aws_s3_bucket.data.id}"
  acl    = "private"
  key    = format("%s/", local.s3_dir_data_synoptic)
  source = "/dev/null"
}
