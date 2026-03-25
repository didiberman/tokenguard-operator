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

package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	securityv1 "github.com/yadid/token-guard/api/v1"
	"github.com/yadid/token-guard/pkg/audit"
	"github.com/yadid/token-guard/pkg/rbac"
)

// SAAuditorReconciler reconciles a SAAuditor object
type SAAuditorReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	AuditReceiver *audit.Receiver
	RBACEval      *rbac.Evaluator
}

// +kubebuilder:rbac:groups=security.tokenguard.io,resources=saauditors,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.tokenguard.io,resources=saauditors/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.tokenguard.io,resources=saauditors/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings;clusterrolebindings,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;clusterroles,verbs=get;list;watch

func (r *SAAuditorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)

	var aud securityv1.SAAuditor
	if err := r.Get(ctx, req.NamespacedName, &aud); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	targetNs := aud.Spec.TargetNamespace
	if targetNs == "" {
		targetNs = aud.Namespace
	}

	var saList corev1.ServiceAccountList
	if err := r.List(ctx, &saList, client.InNamespace(targetNs)); err != nil {
		logger.Error(err, "unable to list ServiceAccounts")
		return ctrl.Result{}, err
	}

	var totalGranted, totalUsed int
	var allUsed, allUnused, anomalies []string

	for _, sa := range saList.Items {
		saUsername := fmt.Sprintf("system:serviceaccount:%s:%s", sa.Namespace, sa.Name)

		granted, _ := r.RBACEval.GetGrantedPermissions(ctx, sa.Namespace, sa.Name)

		usage := r.AuditReceiver.GetUsage(saUsername)
		var used []string
		if usage != nil {
			used = usage.UsedPermissions
			for ip := range usage.SourceIpMap {
				// Naive check: if it's not a private IP, it's external (Anomalous Token Usage - Supply Chain Mitigation)
				if !strings.HasPrefix(ip, "10.") && !strings.HasPrefix(ip, "192.168.") && ip != "127.0.0.1" && ip != "::1" && !strings.HasPrefix(ip, "fd") {
					anomalies = append(anomalies, fmt.Sprintf("CRITICAL: External IP %s used SA %s token", ip, sa.Name))
				}
			}
		}

		totalGranted += len(granted)
		totalUsed += len(used)

		for _, u := range used {
			allUsed = append(allUsed, fmt.Sprintf("%s: %s", sa.Name, u))
		}
		for _, g := range granted {
			if !contains(used, g) {
				allUnused = append(allUnused, fmt.Sprintf("%s: %s", sa.Name, g))
			}
		}
	}

	var score int32 = 100
	if totalGranted > 0 {
		score = int32((float64(totalUsed) / float64(totalGranted)) * 100)
	}

	aud.Status.CurrentScore = &score
	aud.Status.UsedPermissions = allUsed
	aud.Status.UnusedPermissions = allUnused
	aud.Status.Anomalies = anomalies

	if err := r.Status().Update(ctx, &aud); err != nil {
		logger.Error(err, "failed to update status")
		return ctrl.Result{}, err
	}

	logger.Info("Reconciled SAAuditor", "namespace", targetNs, "score", score, "anomalies", len(anomalies))
	return ctrl.Result{RequeueAfter: 2 * time.Minute}, nil
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// SetupWithManager sets up the controller with the Manager.
func (r *SAAuditorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1.SAAuditor{}).
		Named("saauditor").
		Complete(r)
}
