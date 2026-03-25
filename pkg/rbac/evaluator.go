package rbac

import (
	"context"
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Evaluator is responsible for calculating the total granted permissions
// for a specific Kubernetes ServiceAccount by inspecting RoleBindings and ClusterRoleBindings.
type Evaluator struct {
	Client client.Client
}

func NewEvaluator(c client.Client) *Evaluator {
	return &Evaluator{Client: c}
}

// GetGrantedPermissions returns a flattened list of permissions possessed by the given ServiceAccount.
// For simplicity in this operator, it returns them as formatted strings e.g. "get,list /core/pods"
func (e *Evaluator) GetGrantedPermissions(ctx context.Context, namespace, saName string) ([]string, error) {
	var granted []string

	// 1. Check Namespace RoleBindings
	var roleBindings rbacv1.RoleBindingList
	if err := e.Client.List(ctx, &roleBindings, client.InNamespace(namespace)); err != nil {
		return nil, err
	}

	for _, rb := range roleBindings.Items {
		if e.matchesSubject(rb.Subjects, namespace, saName) {
			switch rb.RoleRef.Kind {
			case "Role":
				var role rbacv1.Role
				if err := e.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: rb.RoleRef.Name}, &role); err == nil {
					granted = append(granted, e.formatRules(role.Rules)...)
				}
			case "ClusterRole":
				var crole rbacv1.ClusterRole
				if err := e.Client.Get(ctx, client.ObjectKey{Name: rb.RoleRef.Name}, &crole); err == nil {
					granted = append(granted, e.formatRules(crole.Rules)...)
				}
			}
		}
	}

	// 2. Check Cluster-wide ClusterRoleBindings
	var clusterRoleBindings rbacv1.ClusterRoleBindingList
	if err := e.Client.List(ctx, &clusterRoleBindings); err != nil {
		return nil, err
	}

	for _, crb := range clusterRoleBindings.Items {
		if e.matchesSubject(crb.Subjects, namespace, saName) {
			if crb.RoleRef.Kind == "ClusterRole" {
				var crole rbacv1.ClusterRole
				if err := e.Client.Get(ctx, client.ObjectKey{Name: crb.RoleRef.Name}, &crole); err == nil {
					granted = append(granted, e.formatRules(crole.Rules)...)
				}
			}
		}
	}

	return granted, nil
}

func (e *Evaluator) matchesSubject(subjects []rbacv1.Subject, namespace, saName string) bool {
	for _, subj := range subjects {
		// Handling K8s RBAC quirk: Some service accounts lack the namespace field if they are local to the binding.
		if subj.Kind == "ServiceAccount" && subj.Name == saName && (subj.Namespace == namespace || subj.Namespace == "") {
			return true
		}
	}
	return false
}

func (e *Evaluator) formatRules(rules []rbacv1.PolicyRule) []string {
	formatted := make([]string, 0, len(rules))
	for _, r := range rules {
		verbs := strings.Join(r.Verbs, ",")

		apiGroups := strings.Join(r.APIGroups, ",")
		if apiGroups == "" {
			apiGroups = "core"
		}

		resources := strings.Join(r.Resources, ",")

		formatted = append(formatted, fmt.Sprintf("%s /%s/%s", verbs, apiGroups, resources))
	}
	return formatted
}
