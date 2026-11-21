# sandprobe-recipe: v1
# provider: Kubernetes, a cluster you run, through kubectl
# docs: https://kubernetes.io/docs/reference/kubectl/
# terms: Kubernetes is Apache-2.0 software and the cluster is yours. Whoever hosts it (EKS, GKE, AKS) has terms this recipe can't know, so the checks that contact a provider's own endpoints stay off.
# exclusions: SEC-4 EGR-3 AMP-6 AMP-7
# addressed-by: name
# env: SANDPROBE_KUBE_CONTEXT SANDPROBE_KUBE_NAMESPACE SANDPROBE_KUBE_IMAGE SANDPROBE_KUBE_OVERRIDES
#
# PRV-16. One throwaway pod in the context and namespace you name; the current context is never used. Its ID is the
# UID its create returned. It's deleted only through a UID precondition, so no other pod can ever be deleted, and it
# stops on its own after an hour (activeDeadlineSeconds) if the cleanup never comes.
#
#   SANDPROBE_KUBE_CONTEXT    required: the kubeconfig context to create the pod in
#   SANDPROBE_KUBE_NAMESPACE  default "default"
#   SANDPROBE_KUBE_IMAGE      default: the debian image pinned by digest in test/probe.sh
#   SANDPROBE_KUBE_OVERRIDES  a JSON merge patch over the generated pod, read by kubectl --patch-file: your agent's
#                             securityContext, serviceAccountName, runtimeClassName, nodeSelector and so on. A
#                             containers list replaces the generated one, so give it the image and a long command

sp_image='debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2'

sp_ns() { printf '%s' "${SANDPROBE_KUBE_NAMESPACE:-default}"; }

# sp_say is the recipe's own message, on fd 3: the only output of a recipe Sandprobe shows. Its stderr, where kubectl
# and an exec plugin write and which can carry a credential, is never shown (AGENTS rule 3). Every child command runs
# with fd 3 closed (sp_kc, sp_kube, sp_sha12 and the exec in sp_shell), so no tool can write a message as the recipe.
sp_say() { { echo "$*" >&3; } 2>/dev/null; }

sp_kc() { kubectl "$@"; } 3>&-

sp_sha12() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256
	else
		openssl dgst -sha256 -r
	fi | cut -c1-12
} 3>&-

sp_kube() { kubectl --context "$SANDPROBE_KUBE_CONTEXT" --namespace "$(sp_ns)" "$@"; } 3>&-

# sp_target names where pods are made: the context, its API server, the namespace, and a SHA-256 of the context's
# cluster and context entries (CA, proxy, TLS server name, skip-verify, cluster and user names), so a change to any of
# them, not only the server, stops every later call. It reads only the kubeconfig, and prints none of those entries.
# An API server URL with a user, query or fragment part could carry a credential, so it's refused, never printed; of
# the rest only the origin (scheme, host, port) is shown, since a proxy's path can carry one too. The hash covers the
# whole URL, path included.
sp_target() {
	sp_server=$(sp_kc config view --minify --context "$SANDPROBE_KUBE_CONTEXT" -o 'jsonpath={.clusters[0].cluster.server}' 2>/dev/null) || return 1
	[ -n "$sp_server" ] || return 1
	case $sp_server in *@* | *'?'* | *'#'* | ://* | *://*://*)
		sp_say "the context's API server URL has a user, query or fragment part; Sandprobe won't print it or use it"
		return 1
		;;
	*://?*) ;;
	*)
		sp_say "the context's API server isn't a URL Sandprobe can use"
		return 1
		;;
	esac
	sp_rest=${sp_server#*://}
	sp_origin="${sp_server%%://*}://${sp_rest%%/*}"
	sp_raw=$(sp_kc config view --minify --flatten --raw --context "$SANDPROBE_KUBE_CONTEXT" \
		-o 'jsonpath={.clusters[0].cluster} {.contexts[0].context}' 2>/dev/null) || return 1
	[ -n "$sp_raw" ] || return 1
	sp_conf=$(printf '%s' "$sp_raw" | sp_sha12) || return 1
	sp_raw=
	[ ${#sp_conf} -eq 12 ] || return 1
	printf 'context %s, API server %s, namespace %s, cluster settings %s\n' "$SANDPROBE_KUBE_CONTEXT" "$sp_origin" "$(sp_ns)" "$sp_conf"
}

# sp_bound: every call after sp_ready refuses unless the target is still the one the plan named (RCP-1).
sp_bound() {
	if [ -z "$SANDPROBE_TARGET" ] || [ "$(sp_target)" != "$SANDPROBE_TARGET" ]; then
		sp_say "the context no longer points where the plan said"
		return 1
	fi
}

sp_ready() {
	command -v kubectl >/dev/null 2>&1 || { sp_say "kubectl isn't on PATH"; return 1; }
	[ -n "$SANDPROBE_KUBE_CONTEXT" ] || {
		sp_say "set SANDPROBE_KUBE_CONTEXT to the context to create the pod in; the current context is never used"
		return 1
	}
	sp_n=$(sp_ns)
	# The characters spelled out: a range such as a-z follows the locale's collation, and can match capitals.
	case $sp_n in '' | -* | *- | *[!abcdefghijklmnopqrstuvwxyz0123456789-]*)
		sp_say "SANDPROBE_KUBE_NAMESPACE isn't a namespace name"
		return 1
		;;
	esac
	[ ${#sp_n} -le 63 ] || { sp_say "SANDPROBE_KUBE_NAMESPACE is too long"; return 1; }
	if [ -n "$SANDPROBE_KUBE_OVERRIDES" ] && ! { [ -f "$SANDPROBE_KUBE_OVERRIDES" ] && [ -r "$SANDPROBE_KUBE_OVERRIDES" ]; }; then
		sp_say "can't read SANDPROBE_KUBE_OVERRIDES"
		return 1
	fi
	sp_target >/dev/null || { sp_say "the context $SANDPROBE_KUBE_CONTEXT has no API server Sandprobe can use in your kubeconfig"; return 1; }
	for sp_can in 'create pods' 'get pods' 'delete pods' 'create pods --subresource=exec'; do
		# shellcheck disable=SC2086 # the verb and resource are two words
		[ "$(sp_kube auth can-i $sp_can 2>/dev/null)" = yes ] || {
			sp_say "this context can't $sp_can in namespace $sp_n"
			return 1
		}
	done
	sp_target
}

# sp_create prints only the UID of the pod it created. Your overrides apply first, read by kubectl from the file so
# they never sit on a command line; the name, namespace, label and deadline are set over them. The create is a
# create, never an apply, so it can't take over a pod that already exists.
sp_create() {
	sp_bound || return 1
	sp_n=$(sp_ns)
	sp_ours=$(printf '{"metadata":{"name":"%s","namespace":"%s","labels":{"app.kubernetes.io/managed-by":"sandprobe"}},"spec":{"activeDeadlineSeconds":3600}}' "$SANDPROBE_NAME" "$sp_n")
	sp_obj=$(sp_kube run "$SANDPROBE_NAME" --restart=Never --image="${SANDPROBE_KUBE_IMAGE:-$sp_image}" \
		--dry-run=client -o json --command -- sleep 3600) || { sp_say "kubectl run's dry run failed"; return 1; }
	if [ -n "$SANDPROBE_KUBE_OVERRIDES" ]; then
		sp_obj=$(printf '%s' "$sp_obj" | sp_kc patch --context "$SANDPROBE_KUBE_CONTEXT" --local -f - --type merge \
			--patch-file "$SANDPROBE_KUBE_OVERRIDES" -o json) || { sp_say "the overrides didn't apply as a JSON merge patch"; return 1; }
	fi
	sp_obj=$(printf '%s' "$sp_obj" | sp_kc patch --context "$SANDPROBE_KUBE_CONTEXT" --local -f - --type merge \
		-p "$sp_ours" -o json) || return 1
	# Nothing is created unless it's this one pod, in this namespace: overrides that change the kind or the namespace
	# would make something sp_whois, sp_delete and sp_gone can't see.
	sp_is=$(printf '%s' "$sp_obj" | sp_kube create --dry-run=client -f - -o 'jsonpath={.apiVersion}/{.kind}/{.metadata.namespace}/{.metadata.name}') || return 1
	[ "$sp_is" = "v1/Pod/$sp_n/$SANDPROBE_NAME" ] || {
		sp_say "the overrides make $sp_is, not the pod $sp_n/$SANDPROBE_NAME"
		return 1
	}
	sp_made=$(printf '%s' "$sp_obj" | sp_kube create -f - -o 'jsonpath={.kind}/{.metadata.name}/{.metadata.uid}') || {
		sp_say "kubectl create failed; its own message isn't shown, since it can carry a credential"
		return 1
	}
	case $sp_made in
	"Pod/$SANDPROBE_NAME/"?*) ;;
	*) sp_say "the create returned $sp_made, not the pod $SANDPROBE_NAME"; return 1 ;;
	esac
	echo "${sp_made#"Pod/$SANDPROBE_NAME/"}"
	sp_kube wait --for=condition=Ready "pod/$SANDPROBE_NAME" --timeout=180s >/dev/null || {
		sp_say "the pod didn't become ready"
		return 1
	}
}

# sp_whois prints the UID now holding the name, or nothing.
sp_whois() {
	sp_bound || return 1
	sp_kube get pod "$SANDPROBE_NAME" --ignore-not-found -o 'jsonpath={.metadata.uid}'
}

sp_shell() {
	sp_bound || return 1
	exec kubectl --context "$SANDPROBE_KUBE_CONTEXT" --namespace "$(sp_ns)" exec -i "$SANDPROBE_NAME" -- sh 3>&-
}

# sp_delete deletes the pod only while it carries the UID the create returned: the API refuses any other.
sp_delete() {
	sp_bound || return 1
	printf '{"kind":"DeleteOptions","apiVersion":"v1","gracePeriodSeconds":1,"preconditions":{"uid":"%s"}}' "$SANDPROBE_BOX" |
		sp_kc --context "$SANDPROBE_KUBE_CONTEXT" delete --raw "/api/v1/namespaces/$(sp_ns)/pods/$SANDPROBE_NAME" -f - >/dev/null
}

# sp_gone: 0 when the name is absent or held by another UID (so ours is gone), 1 while ours holds it, 2 when kubectl
# can't say.
sp_gone() {
	sp_bound || return 2
	sp_now=$(sp_kube get pod "$SANDPROBE_NAME" --ignore-not-found -o 'jsonpath={.metadata.uid}') || return 2
	[ "$sp_now" = "$SANDPROBE_BOX" ] && return 1
	return 0
}
