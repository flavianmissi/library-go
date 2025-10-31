package kms

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
)

func TestContainer(t *testing.T) {
	tests := []struct {
		name            string
		kmsConfig       *configv1.KMSConfig
		containerConfig *ContainerConfig
		wantErr         bool
		validateFunc    func(*testing.T, *corev1.Container)
	}{
		{
			name: "valid AWS KMS with hostNetwork",
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.AWSKMSProvider,
				AWS: &configv1.AWSKMSConfig{
					KeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
					Region: "us-east-1",
				},
			},
			containerConfig: &ContainerConfig{
				Image:          "test-image:latest",
				UseHostNetwork: true,
			},
			wantErr: false,
			validateFunc: func(t *testing.T, c *corev1.Container) {
				if c.Name != KMSContainerName {
					t.Errorf("expected container name %s, got %s", KMSContainerName, c.Name)
				}
				if c.Image != "test-image:latest" {
					t.Errorf("expected image test-image:latest, got %s", c.Image)
				}
				if len(c.Args) != 3 {
					t.Errorf("expected 3 args, got %d", len(c.Args))
				}
				// Should NOT have credentials mount when using hostNetwork
				foundCredsMount := false
				for _, vm := range c.VolumeMounts {
					if vm.Name == KMSCredentialsVolumeName {
						foundCredsMount = true
					}
				}
				if foundCredsMount {
					t.Error("should not have credentials mount when UseHostNetwork is true")
				}
			},
		},
		{
			name: "valid AWS KMS with credentials secret",
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.AWSKMSProvider,
				AWS: &configv1.AWSKMSConfig{
					KeyARN: "arn:aws:kms:us-west-2:987654321098:key/abcdef12-3456-7890-abcd-ef1234567890",
					Region: "us-west-2",
				},
			},
			containerConfig: &ContainerConfig{
				Image:                 "test-image:v2",
				UseHostNetwork:        false,
				CredentialsSecretName: "kms-creds",
			},
			wantErr: false,
			validateFunc: func(t *testing.T, c *corev1.Container) {
				// Should have credentials mount
				foundCredsMount := false
				for _, vm := range c.VolumeMounts {
					if vm.Name == KMSCredentialsVolumeName {
						foundCredsMount = true
						if vm.MountPath != "/var/run/secrets/aws" {
							t.Errorf("expected mount path /var/run/secrets/aws, got %s", vm.MountPath)
						}
					}
				}
				if !foundCredsMount {
					t.Error("should have credentials mount when UseHostNetwork is false")
				}
				// Should have AWS_SHARED_CREDENTIALS_FILE env var
				foundEnv := false
				for _, env := range c.Env {
					if env.Name == "AWS_SHARED_CREDENTIALS_FILE" {
						foundEnv = true
					}
				}
				if !foundEnv {
					t.Error("should have AWS_SHARED_CREDENTIALS_FILE env var when using credentials secret")
				}
			},
		},
		{
			name:      "nil kmsConfig",
			kmsConfig: nil,
			containerConfig: &ContainerConfig{
				Image:          "test-image:latest",
				UseHostNetwork: true,
			},
			wantErr: true,
		},
		{
			name: "nil containerConfig",
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.AWSKMSProvider,
				AWS: &configv1.AWSKMSConfig{
					KeyARN: "arn:aws:kms:us-east-1:123456789012:key/test",
					Region: "us-east-1",
				},
			},
			containerConfig: nil,
			wantErr:         true,
		},
		{
			name: "missing image",
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.AWSKMSProvider,
				AWS: &configv1.AWSKMSConfig{
					KeyARN: "arn:aws:kms:us-east-1:123456789012:key/test",
					Region: "us-east-1",
				},
			},
			containerConfig: &ContainerConfig{
				Image:          "",
				UseHostNetwork: true,
			},
			wantErr: true,
		},
		{
			name: "missing credentials secret when not using hostNetwork",
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.AWSKMSProvider,
				AWS: &configv1.AWSKMSConfig{
					KeyARN: "arn:aws:kms:us-east-1:123456789012:key/test",
					Region: "us-east-1",
				},
			},
			containerConfig: &ContainerConfig{
				Image:                 "test-image:latest",
				UseHostNetwork:        false,
				CredentialsSecretName: "",
			},
			wantErr: true,
		},
		{
			name: "missing AWS config",
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.AWSKMSProvider,
				AWS:  nil,
			},
			containerConfig: &ContainerConfig{
				Image:          "test-image:latest",
				UseHostNetwork: true,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildPluginContainer(tt.kmsConfig, tt.containerConfig)
			if (err != nil) != tt.wantErr {
				t.Errorf("container() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.validateFunc != nil {
				tt.validateFunc(t, got)
			}
		})
	}
}

func TestVolumes(t *testing.T) {
	tests := []struct {
		name                  string
		useHostNetwork        bool
		credentialsSecretName string
		hostPath              bool
		expectedVolumeCount   int
		validateFunc          func(*testing.T, []corev1.Volume)
	}{
		{
			name:                  "hostNetwork with emptyDir socket",
			useHostNetwork:        true,
			credentialsSecretName: "",
			hostPath:              false,
			expectedVolumeCount:   1,
			validateFunc: func(t *testing.T, volumes []corev1.Volume) {
				if volumes[0].Name != KMSSocketVolumeName {
					t.Errorf("expected socket volume name %s, got %s", KMSSocketVolumeName, volumes[0].Name)
				}
				if volumes[0].VolumeSource.EmptyDir == nil {
					t.Error("expected EmptyDir volume source for socket")
				}
			},
		},
		{
			name:                  "hostNetwork with hostPath socket",
			useHostNetwork:        true,
			credentialsSecretName: "",
			hostPath:              true,
			expectedVolumeCount:   1,
			validateFunc: func(t *testing.T, volumes []corev1.Volume) {
				if volumes[0].VolumeSource.HostPath == nil {
					t.Error("expected HostPath volume source for socket")
				}
				if volumes[0].VolumeSource.HostPath.Path != "/var/run/kmsplugin" {
					t.Errorf("expected hostPath /var/run/kmsplugin, got %s", volumes[0].VolumeSource.HostPath.Path)
				}
			},
		},
		{
			name:                  "credentials secret",
			useHostNetwork:        false,
			credentialsSecretName: "my-kms-creds",
			hostPath:              false,
			expectedVolumeCount:   2,
			validateFunc: func(t *testing.T, volumes []corev1.Volume) {
				foundCredsVolume := false
				for _, v := range volumes {
					if v.Name == KMSCredentialsVolumeName {
						foundCredsVolume = true
						if v.VolumeSource.Secret == nil {
							t.Error("expected Secret volume source for credentials")
						}
						if v.VolumeSource.Secret.SecretName != "my-kms-creds" {
							t.Errorf("expected secret name my-kms-creds, got %s", v.VolumeSource.Secret.SecretName)
						}
					}
				}
				if !foundCredsVolume {
					t.Error("expected to find credentials volume")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildPluginVolumes(tt.useHostNetwork, tt.credentialsSecretName, tt.hostPath)
			if len(got) != tt.expectedVolumeCount {
				t.Errorf("expected %d volumes, got %d", tt.expectedVolumeCount, len(got))
			}
			if tt.validateFunc != nil {
				tt.validateFunc(t, got)
			}
		})
	}
}

func TestAddKMSPluginToPodSpec(t *testing.T) {
	tests := []struct {
		name                 string
		podSpec              *corev1.PodSpec
		kmsConfig            *configv1.KMSConfig
		containerConfig      *ContainerConfig
		useHostPathForSocket bool
		wantErr              bool
		validateFunc         func(*testing.T, *corev1.PodSpec)
	}{
		{
			name: "add to kube-apiserver pod",
			podSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "kube-apiserver",
						Image: "kube-apiserver:latest",
					},
				},
			},
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.AWSKMSProvider,
				AWS: &configv1.AWSKMSConfig{
					KeyARN: "arn:aws:kms:us-east-1:123456789012:key/test",
					Region: "us-east-1",
				},
			},
			containerConfig: &ContainerConfig{
				Image:          "kms-plugin:latest",
				UseHostNetwork: true,
			},
			useHostPathForSocket: true,
			wantErr:              false,
			validateFunc: func(t *testing.T, ps *corev1.PodSpec) {
				if len(ps.Containers) != 2 {
					t.Errorf("expected 2 containers, got %d", len(ps.Containers))
				}
				// Check that kube-apiserver has socket mount
				foundSocketMount := false
				for _, c := range ps.Containers {
					if c.Name == "kube-apiserver" {
						for _, vm := range c.VolumeMounts {
							if vm.Name == KMSSocketVolumeName {
								foundSocketMount = true
								if vm.MountPath != "/var/run/kmsplugin" {
									t.Errorf("expected socket mount path /var/run/kmsplugin, got %s", vm.MountPath)
								}
								if !vm.ReadOnly {
									t.Error("expected socket mount to be read-only")
								}
							}
						}
					}
				}
				if !foundSocketMount {
					t.Error("kube-apiserver should have socket volume mount")
				}
			},
		},
		{
			name:    "nil podSpec",
			podSpec: nil,
			kmsConfig: &configv1.KMSConfig{
				Type: configv1.AWSKMSProvider,
				AWS: &configv1.AWSKMSConfig{
					KeyARN: "arn:aws:kms:us-east-1:123456789012:key/test",
					Region: "us-east-1",
				},
			},
			containerConfig: &ContainerConfig{
				Image:          "kms-plugin:latest",
				UseHostNetwork: true,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AddKMSPluginToPodSpec(tt.podSpec, tt.kmsConfig, tt.containerConfig, tt.useHostPathForSocket)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddKMSPluginToPodSpec() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.validateFunc != nil {
				tt.validateFunc(t, tt.podSpec)
			}
		})
	}
}
