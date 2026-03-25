/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// SAAuditorSpec defines the desired state of SAAuditor
type SAAuditorSpec struct {
	// TargetNamespace is the namespace to monitor ServiceAccounts in.
	TargetNamespace string `json:"targetNamespace"`

	// ScoringInterval is how often to recalculate the Least Privilege Score.
	ScoringInterval string `json:"scoringInterval,omitempty"`

	// AlertThreshold sets the minimum score (0-100) before triggering an alert.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	AlertThreshold int32 `json:"alertThreshold,omitempty"`
}

type SAAuditorStatus struct {
	// CurrentScore represents the Least Privilege Score (0-100%).
	// 100% means perfect least privilege (all granted permissions are used).
	// +optional
	CurrentScore *int32 `json:"currentScore,omitempty"`

	// UsedPermissions lists the API rules actually utilized by the ServiceAccount.
	// +optional
	UsedPermissions []string `json:"usedPermissions,omitempty"`

	// UnusedPermissions lists the API rules granted but never utilized.
	// +optional
	UnusedPermissions []string `json:"unusedPermissions,omitempty"`

	// Anomalies detects external IP bindings or unprecedented actions.
	// +optional
	Anomalies []string `json:"anomalies,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// SAAuditor is the Schema for the saauditors API
type SAAuditor struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of SAAuditor
	// +required
	Spec SAAuditorSpec `json:"spec"`

	// status defines the observed state of SAAuditor
	// +optional
	Status SAAuditorStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SAAuditorList contains a list of SAAuditor
type SAAuditorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SAAuditor `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SAAuditor{}, &SAAuditorList{})
}
